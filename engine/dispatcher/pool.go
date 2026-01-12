// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package dispatcher

import (
	"fmt"
	"log/slog"
	"sync"
	"time"

	et "github.com/owasp-amass/amass/v5/engine/types"
	oam "github.com/owasp-amass/open-asset-model"
	"golang.org/x/net/publicsuffix"
)

type pipelinePool struct {
	sync.RWMutex
	log     *slog.Logger
	dis     *dynamicDispatcher
	reg     et.Registry
	eventTy oam.AssetType
	// dynamic bounds
	minInstances int
	maxInstances int
	// baseline policy bounds
	baseMin         int
	baseMax         int
	hardMax         int // absolute safety cap
	nextInstanceSeq uint64
	instances       map[string]*pipelineInstance // instanceID -> instance
	ring            *hashRing                    // shardKey -> instanceID
	// session fan-out and load tracking
	sessionFanout   map[string]int   // sessionID -> fanout factor (1 = no fanout)
	sessionQueued   map[string]int64 // sessionID -> queued count across all instances
	pendingSessions map[string]et.Session
	wake            chan struct{}
}

func newPipelinePool(dis *dynamicDispatcher, atype oam.AssetType, pmin, pmax int) *pipelinePool {
	pmin = max(pmin, 1)
	pmax = max(pmax, pmin)
	hard := pmax * 2

	p := &pipelinePool{
		log:             dis.log,
		dis:             dis,
		reg:             dis.reg,
		eventTy:         atype,
		minInstances:    pmin,
		maxInstances:    pmax,
		baseMin:         pmin,
		baseMax:         pmax,
		hardMax:         hard,
		instances:       make(map[string]*pipelineInstance),
		ring:            newHashRing(50),
		sessionFanout:   make(map[string]int),
		sessionQueued:   make(map[string]int64),
		pendingSessions: make(map[string]et.Session),
		wake:            make(chan struct{}, 1),
	}

	p.ensureMinInstances()
	go p.runPump()
	return p
}

// Dispatch wakes up the pump for admission.
func (p *pipelinePool) Dispatch(e *et.Event) error {
	// mark that this session/atype has backlog
	p.notePending(e)

	// decide whether to fill work queues
	inst := p.pickInstance(p.workShardKey(e))
	if inst != nil && inst.queueLen() <= instanceLowWater {
		p.notifyCapacity()
	}

	return nil
}

func (p *pipelinePool) ensureMinInstances() {
	p.Lock()
	defer p.Unlock()

	p.ensureMinInstancesLocked()
}

func (p *pipelinePool) ensureMinInstancesLocked() {
	for len(p.instances) < p.minInstances {
		if p.createInstanceLocked() == nil {
			break
		}
	}
}

// workShardKey decides which logical shard this event belongs to.
// - Normal case (fanout=1): shardKey = sessionID
// - Fan-out case (fanout>1): shardKey = sessionID/bucket, bucket chosen by assetKey.
func (p *pipelinePool) workShardKey(e *et.Event) string {
	sid := sessionIDOf(e)
	if sid == "" {
		// Fallback sharding when we don't have a session
		return fallbackShardKey(e)
	}

	p.RLock()
	fanout := p.sessionFanout[sid]
	p.RUnlock()

	if fanout <= 1 {
		return sid
	}

	assetKey := assetBucket(e)
	if assetKey == "" {
		assetKey = sid
	}

	bucket := hashKey(sid+"/"+assetKey) % uint32(fanout)
	return fmt.Sprintf("%s/%d", sid, bucket)
}

// pickInstance enforces "one pipeline per (assetType, shardKey) at a time".
func (p *pipelinePool) pickInstance(shardKey string) *pipelineInstance {
	p.RLock()
	defer p.RUnlock()

	if len(p.instances) == 0 {
		return nil
	}

	if shardKey == "" {
		// fallback: pick emptiest
		var best *pipelineInstance
		for _, inst := range p.instances {
			if best == nil || inst.queueLen() < best.queueLen() {
				best = inst
			}
		}
		return best
	}

	id, ok := p.ring.Lookup(shardKey)
	if !ok {
		return nil
	}

	inst, ok := p.instances[id]
	if !ok {
		return nil
	}
	return inst
}

func (p *pipelinePool) runPump() {
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()

	for {
		select {
		case <-p.dis.done:
			return
		case <-p.wake:
			p.pumpOnce()
		case <-tick.C:
			p.pumpOnce()
		}
	}
}

func (p *pipelinePool) pumpOnce() {
	// Snapshot pending sessions (avoid holding lock during DB calls)
	sessions := p.snapshotPendingSessions()
	if len(sessions) == 0 {
		return
	}

	// Round-robin / bounded burst per session
	const perSessionBurst = 10

	// check that at least one instance has enough capacity
	if !p.hasCapacity(perSessionBurst) {
		return
	}

	for _, sess := range sessions {
		entities, err := sess.Backlog().ClaimNext(p.eventTy, perSessionBurst)
		if err != nil || len(entities) == 0 {
			p.clearPending(sess.ID().String())
			continue
		}

		for _, ent := range entities {
			event := &et.Event{
				Name:       ent.Asset.Key(),
				Entity:     ent,
				Dispatcher: p.dis,
				Session:    sess,
			}

			inst := p.pickInstance(p.workShardKey(event))
			if inst == nil {
				_ = sess.Backlog().Release(ent, p.eventTy, false)
				continue
			}

			if err := inst.enqueue(event); err != nil {
				_ = sess.Backlog().Release(ent, p.eventTy, false)
			}
		}

		if queued, _, _, err := sess.Backlog().Counts(p.eventTy); err == nil && queued == 0 {
			p.clearPending(sess.ID().String())
		}
	}
}

func (p *pipelinePool) hasCapacity(num int64) bool {
	p.RLock()
	defer p.RUnlock()

	for _, inst := range p.instances {
		if inst.queueLen()+num <= instanceMaxQueued {
			return true
		}
	}
	return false
}

// snapshotPendingSessions returns a point-in-time list of session IDs that the pool
// believes have pending work in the durable queue (or were previously blocked by
// backpressure). The returned slice is safe to iterate without holding p.mu.
func (p *pipelinePool) snapshotPendingSessions() []et.Session {
	p.RLock()
	defer p.RUnlock()

	if len(p.pendingSessions) == 0 {
		return nil
	}

	sessions := make([]et.Session, 0, len(p.pendingSessions))
	for _, sess := range p.pendingSessions {
		sessions = append(sessions, sess)
	}

	return sessions
}

// clearPendingIfEmpty removes sid from pendingSessions.
func (p *pipelinePool) clearPending(sid string) {
	if sid == "" {
		return
	}

	p.Lock()
	delete(p.pendingSessions, sid)
	p.Unlock()
}

func (p *pipelinePool) notePending(e *et.Event) {
	sid := sessionIDOf(e)
	if sid == "" {
		return
	}

	p.Lock()
	p.pendingSessions[sid] = e.Session
	p.Unlock()
}

func (p *pipelinePool) notifyCapacity() {
	select {
	case p.wake <- struct{}{}:
	default:
	}
}

// ----------------------------------------------------------------
// ---------------- Helpers for session keys ----------------------
// ----------------------------------------------------------------

// sessionIDOf extracts a stable session identifier from an event.
func sessionIDOf(e *et.Event) string {
	if e == nil || e.Session == nil {
		return ""
	}
	return e.Session.ID().String()
}

// fallbackShardKey is used when we don't have a session.
func fallbackShardKey(e *et.Event) string {
	if e == nil || e.Entity == nil {
		return ""
	}
	return e.Entity.ID
}

// assetKeyOf returns a stable per-asset key used to choose a bucket
// within a session. This should be consistent with the AssetType.
func assetBucket(e *et.Event) string {
	if e == nil || e.Entity == nil {
		return ""
	}

	switch e.Entity.Asset.AssetType() {
	case oam.FQDN:
		if name := e.Entity.Asset.Key(); name != "" {
			if dom, err := publicsuffix.EffectiveTLDPlusOne(name); err == nil {
				return dom
			}
		}
	}

	return e.Entity.Asset.Key()
}
