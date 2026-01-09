// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package dispatcher

import (
	"fmt"
	"sync/atomic"

	et "github.com/owasp-amass/amass/v5/engine/types"
	oam "github.com/owasp-amass/open-asset-model"
	"golang.org/x/net/publicsuffix"
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
	// Wake the pool pump when we cross below lowWater
	if qlen == pi.lowWater {
		pi.parent.notifyCapacity()
	}

	if pi.draining.Load() && qlen == 0 {
		pi.parent.mu.Lock()
		defer pi.parent.mu.Unlock()

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

// fallbackShardKey is used when we don't have a session; you can
// make this smarter if needed.
func fallbackShardKey(e *et.Event) string {
	if e == nil || e.Entity == nil {
		return ""
	}
	return e.Entity.ID
}

// assetKeyOf returns a stable per-asset key used to choose a bucket
// within a session. This should be consistent with the AssetType.
func assetKeyOf(e *et.Event) string {
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
