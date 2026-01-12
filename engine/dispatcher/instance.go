// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package dispatcher

import (
	"fmt"
	"sync/atomic"

	et "github.com/owasp-amass/amass/v5/engine/types"
	oam "github.com/owasp-amass/open-asset-model"
)

const (
	instanceLowWater  = int64(100)
	instanceHighWater = int64(175)
	instanceMaxQueued = int64(200)
)

var ErrBackpressure = fmt.Errorf("backpressure")

type pipelineInstance struct {
	parent    *pipelinePool
	id        string
	atype     oam.AssetType
	ap        *et.AssetPipeline
	draining  atomic.Bool
	queued    atomic.Int64
	maxQueued int64 // e.g., 200 or 500; tune per asset type
	lowWater  int64 // e.g., maxQueued/2; used for wakeups
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

	id := p.nextInstanceID()
	inst := &pipelineInstance{
		parent:    p,
		id:        id,
		atype:     p.eventTy,
		ap:        ap,
		maxQueued: instanceMaxQueued,
		lowWater:  instanceLowWater,
	}
	p.instances[id] = inst
	p.ring.Add(id)

	p.log.Info("created pipeline instance", "atype", p.eventTy, "id", id)
	return inst
}

// nextInstanceID allocates a unique ID independent of map length.
func (p *pipelinePool) nextInstanceID() string {
	var id string

	for {
		p.nextInstanceSeq++
		id = fmt.Sprintf("%s-%d", p.eventTy, p.nextInstanceSeq)
		if _, exists := p.instances[id]; !exists {
			break
		}
		p.log.Error("pipeline instance id collision", "atype", p.eventTy, "id", id)
	}

	return id
}

func (pi *pipelineInstance) canAccept() bool {
	if pi.draining.Load() {
		return false
	}
	return pi.queued.Load() < pi.maxQueued
}

func (pi *pipelineInstance) enqueue(e *et.Event) error {
	if !pi.canAccept() {
		return ErrBackpressure
	}
	// Only increment AFTER admission decision
	pi.queued.Add(1)

	sid := sessionIDOf(e)
	if sid != "" {
		pi.parent.incSessionQueued(sid, 1)
	}

	e.Dispatcher = pi.parent.dis
	data := et.NewEventDataElement(e)
	data.Exit = pi.parent.dis.cchan
	data.Ref = pi // keep a ref to the instance
	return pi.ap.Queue.Append(data)
}

func (pi *pipelineInstance) onDequeue(e *et.Event) {
	pi.queued.Add(-1)

	sid := sessionIDOf(e)
	if sid != "" {
		pi.parent.incSessionQueued(sid, -1)
	}

	qlen := pi.queueLen()
	// Wake the pool pump when we are below lowWater
	if qlen <= pi.lowWater {
		pi.parent.notifyCapacity()
	}

	if pi.draining.Load() && qlen == 0 {
		pi.parent.Lock()
		defer pi.parent.Unlock()

		delete(pi.parent.instances, pi.id)
		pi.parent.log.Info("removed idle pipeline instance",
			"atype", pi.parent.eventTy,
			"id", pi.id,
		)
	}
}

func (pi *pipelineInstance) queueLen() int64 {
	return pi.queued.Load()
}

// incSessionQueued tracks total queued items for a session across instances.
func (p *pipelinePool) incSessionQueued(sid string, delta int64) {
	p.Lock()
	defer p.Unlock()

	p.sessionQueued[sid] += delta
	if p.sessionQueued[sid] <= 0 {
		delete(p.sessionQueued, sid)
	}
}
