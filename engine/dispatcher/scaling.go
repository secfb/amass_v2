// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package dispatcher

import (
	"time"
)

const (
	sessionMaxQueued     = int64(200)
	sessionGrowThreshold = int64(100)
)

func (p *pipelinePool) activeSessionCountLocked() int {
	if len(p.pendingSessions) == 0 && len(p.sessionQueued) == 0 {
		return 0
	}

	set := make(map[string]struct{},
		len(p.pendingSessions)+len(p.sessionQueued))

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
	targetMax := max(active, p.baseMax)
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

// maybeAdjustFanout bumps fan-out for very heavy sessions.
func (p *pipelinePool) maybeAdjustFanout(sid string) {
	const fanoutInterval = 2 * time.Second

	now := time.Now()
	if now.Sub(p.lastFanout) < fanoutInterval {
		return
	}
	p.lastFanout = now

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
	fanout = max(fanout, 1)

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

	// adjust min/max based on current workload + active sessions
	p.recomputeBoundsLocked(total, avg)

	// enforce dynamic min immediately
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
		_ = p.createInstanceLocked()
		return
	}

	// Scale down (respect dynamic min)
	if avg < shrinkThreshold && n > p.minInstances {
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
