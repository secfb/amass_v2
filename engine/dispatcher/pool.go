// Copyright © by Jeff Foley 2017-2025. All rights reserved.
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
)

type pipelinePool struct {
	mu      sync.RWMutex
	log     *slog.Logger
	dis     *dynamicDispatcher
	reg     et.Registry
	eventTy oam.AssetType
	// dynamic bounds
	minInstances int
	maxInstances int
	// baseline policy bounds
	baseMin   int
	baseMax   int
	hardMax   int                          // absolute safety cap
	instances map[string]*pipelineInstance // instanceID -> instance
	ring      *hashRing                    // shardKey -> instanceID
	// session fan-out and load tracking
	sessionFanout   map[string]int   // sessionID -> fanout factor (1 = no fanout)
	sessionQueued   map[string]int64 // sessionID -> queued count across all instances
	lastScale       time.Time
	pendingSessions map[string]et.Session
	wake            chan struct{}
	lastBounds      time.Time
}

func newPipelinePool(dis *dynamicDispatcher, atype oam.AssetType, min, max int) *pipelinePool {
	if min <= 0 {
		min = 1
	}
	if max < min {
		max = min
	}

	// hardMax: you can tune per asset type; keep it conservative
	hard := max
	switch atype {
	case oam.FQDN, oam.IPAddress:
		if hard < 256 {
			hard = 256
		} // example: allow growth beyond baseMax if needed
	default:
		if hard < 64 {
			hard = 64
		}
	}

	p := &pipelinePool{
		log:             dis.log,
		dis:             dis,
		reg:             dis.reg,
		eventTy:         atype,
		minInstances:    min,
		maxInstances:    max,
		baseMin:         min,
		baseMax:         max,
		hardMax:         hard,
		instances:       make(map[string]*pipelineInstance),
		ring:            newHashRing(50),
		sessionFanout:   make(map[string]int),
		sessionQueued:   make(map[string]int64),
		lastScale:       time.Now(),
		pendingSessions: make(map[string]et.Session),
		wake:            make(chan struct{}, 1),
		lastBounds:      time.Now(),
	}

	go p.runPump()
	return p
}

// Dispatch wakes up the pump for admission.
func (p *pipelinePool) Dispatch(e *et.Event) error {
	// mark that this session/atype has backlog
	p.notePending(e)
	p.maybeScale()
	p.maybeAdjustFanout(e)
	return nil
}

func (p *pipelinePool) runPump() {
	tick := time.NewTicker(250 * time.Millisecond)
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
			if inst == nil || !inst.canAccept() {
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

// snapshotPendingSessions returns a point-in-time list of session IDs that the pool
// believes have pending work in the durable queue (or were previously blocked by
// backpressure). The returned slice is safe to iterate without holding p.mu.
func (p *pipelinePool) snapshotPendingSessions() []et.Session {
	p.mu.RLock()
	defer p.mu.RUnlock()

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

	p.mu.Lock()
	defer p.mu.Unlock()

	delete(p.pendingSessions, sid)
}

func (p *pipelinePool) notePending(e *et.Event) {
	sid := sessionIDOf(e)
	if sid == "" {
		return
	}
	p.mu.Lock()
	p.pendingSessions[sid] = e.Session
	p.mu.Unlock()
	p.notifyCapacity()
}

func (p *pipelinePool) notifyCapacity() {
	select {
	case p.wake <- struct{}{}:
	default:
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

	p.mu.RLock()
	fanout := p.sessionFanout[sid]
	p.mu.RUnlock()

	if fanout <= 1 {
		return sid
	}

	assetKey := assetKeyOf(e)
	if assetKey == "" {
		assetKey = sid
	}

	bucket := hashKey(sid+"/"+assetKey) % uint32(fanout)
	return fmt.Sprintf("%s/%d", sid, bucket)
}

// pickInstance enforces "one pipeline per (assetType, shardKey) at a time".
func (p *pipelinePool) pickInstance(shardKey string) *pipelineInstance {
	p.mu.Lock()
	defer p.mu.Unlock()

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

func (p *pipelinePool) createInstanceLocked() *pipelineInstance {
	if len(p.instances) >= p.maxInstances {
		return nil
	}

	ap, err := p.reg.BuildAssetPipeline(string(p.eventTy))
	if err != nil {
		p.log.Error("BuildAssetPipeline failed", "atype", p.eventTy, "err", err)
		return nil
	}

	id := fmt.Sprintf("%s-%d", p.eventTy, len(p.instances)+1)
	inst := &pipelineInstance{
		parent:    p,
		id:        id,
		atype:     p.eventTy,
		ap:        ap,
		maxQueued: 200,
		lowWater:  100,
	}
	p.instances[id] = inst
	p.ring.Add(id)

	p.log.Info("created pipeline instance",
		"atype", p.eventTy,
		"id", id,
	)
	return inst
}

// incSessionQueued tracks total queued items for a session across instances.
func (p *pipelinePool) incSessionQueued(sid string, delta int64) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.sessionQueued[sid] += delta
	if p.sessionQueued[sid] <= 0 {
		delete(p.sessionQueued, sid)
	}
}

// maybeAdjustFanout bumps fan-out for very heavy sessions.
func (p *pipelinePool) maybeAdjustFanout(e *et.Event) {
	sid := sessionIDOf(e)
	if sid == "" {
		return
	}

	const (
		sessionGrowThreshold = int64(500)
	)

	p.mu.Lock()
	defer p.mu.Unlock()

	queued := p.sessionQueued[sid]
	if queued <= sessionGrowThreshold {
		p.sessionFanout[sid] = 1
		return
	}

	var scount int
	for _, sess := range p.sessionQueued {
		if sess > 0 {
			scount++
		}
	}
	if scount == 0 {
		return
	}

	n := len(p.instances)
	if n < scount {
		// not enough instances to bother with fan-out
		p.sessionFanout[sid] = 1
		return
	}
	maxFanout := n / scount

	fanout := p.sessionFanout[sid]
	if fanout == 0 {
		fanout = 1
	}

	newFanout := fanout * 2
	newFanout = min(newFanout, maxFanout)
	p.sessionFanout[sid] = newFanout

	p.log.Info("adjusting session fan-out",
		"atype", p.eventTy,
		"session", sid,
		"from", fanout,
		"to", newFanout,
		"queued", queued,
	)
}

// maybeScale still does global instance scaling based on overall queue sizes.
func (p *pipelinePool) maybeScale() {
	const (
		scaleInterval   = 5 * time.Second
		growThreshold   = 100
		shrinkThreshold = 10
	)

	now := time.Now()
	if now.Sub(p.lastScale) < scaleInterval {
		return
	}
	p.lastScale = now

	p.mu.Lock()
	defer p.mu.Unlock()

	// compute load
	var total int64
	for _, inst := range p.instances {
		total += inst.queueLen()
	}

	n := len(p.instances)
	var avg int64
	if n > 0 {
		avg = total / int64(n)
	}

	// NEW: adjust min/max based on current workload + active sessions
	p.recomputeBoundsLocked(total, avg)

	// NEW: enforce dynamic min immediately
	for len(p.instances) < p.minInstances {
		if p.createInstanceLocked() == nil {
			break
		}
	}

	n = len(p.instances)
	if n == 0 {
		return
	}
	avg = total / int64(n)

	// Scale up (within dynamic max)
	if avg > growThreshold && n < p.maxInstances {
		p.log.Info("scaling up pipeline pool",
			"atype", p.eventTy,
			"from", n,
			"to", n+1,
			"queuedTotal", total,
			"queuedAvg", avg,
			"min", p.minInstances,
			"max", p.maxInstances,
		)
		p.createInstanceLocked()
		return
	}

	// Scale down (respect dynamic min)
	if avg < shrinkThreshold && n > p.minInstances {
		// your existing drain/choose-emptiest logic, but compare to p.minInstances
		var count int
		var best *pipelineInstance

		for _, inst := range p.instances {
			if inst.draining.Load() {
				continue
			}
			count++
			if best == nil || inst.queueLen() < best.queueLen() {
				best = inst
			}
		}
		if best == nil || count <= p.minInstances {
			return
		}

		best.ap.Queue.Drain()
		p.ring.Remove(best.id)
		best.draining.Store(true)
		if best.queueLen() == 0 {
			delete(p.instances, best.id)
			p.log.Info("removed idle pipeline instance",
				"atype", p.eventTy,
				"id", best.id,
			)
		}
	}
}

func (p *pipelinePool) activeSessionCountLocked() int {
	if len(p.pendingSessions) == 0 && len(p.sessionQueued) == 0 {
		return 0
	}
	set := make(map[string]struct{}, len(p.pendingSessions)+len(p.sessionQueued))
	for sid := range p.pendingSessions {
		set[sid] = struct{}{}
	}
	for sid, q := range p.sessionQueued {
		if q > 0 {
			set[sid] = struct{}{}
		}
	}
	return len(set)
}

func (p *pipelinePool) recomputeBoundsLocked(totalQueued int64, avgQueued int64) {
	const boundsInterval = 2 * time.Second

	now := time.Now()
	if now.Sub(p.lastBounds) < boundsInterval {
		return
	}
	p.lastBounds = now

	active := p.activeSessionCountLocked()

	// If nothing is active, drift back toward baseline.
	if active == 0 && totalQueued == 0 {
		p.minInstances = p.baseMin
		p.maxInstances = p.baseMax
		return
	}

	// Dynamic max: baseline plus ability to grow with activity/pressure.
	targetMax := p.baseMax
	if active > targetMax {
		targetMax = active
	}

	// If we are seeing pressure, allow growth beyond baseline.
	// (You already have growThreshold=100 in maybeScale; reuse it conceptually.)
	if avgQueued > 100 {
		// add headroom when congested
		targetMax = maxInt(targetMax, len(p.instances)+1)
		targetMax = maxInt(targetMax, active+(active/2)) // 1.5x sessions under pressure
	}

	targetMax = clampInt(targetMax, p.baseMin, p.hardMax)

	// Dynamic min: keep some warm capacity as sessions grow (but not 1:1).
	warm := p.baseMin + (active+3)/4 // 1 extra instance per 4 active sessions
	targetMin := clampInt(warm, p.baseMin, targetMax)

	p.minInstances = targetMin
	p.maxInstances = targetMax
}

func clampInt(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
