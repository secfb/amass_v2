// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package dispatcher

import (
	"fmt"
	"log/slog"
	"sync"

	"github.com/caffix/queue"
	et "github.com/owasp-amass/amass/v5/engine/types"
	oam "github.com/owasp-amass/open-asset-model"
)

type dynamicDispatcher struct {
	log    *slog.Logger
	reg    et.Registry
	mgr    et.SessionManager
	done   chan struct{}
	cchan  chan *et.EventDataElement
	cqueue queue.Queue

	mu    sync.RWMutex
	pools map[oam.AssetType]*pipelinePool
}

func NewDispatcher(l *slog.Logger, r et.Registry, mgr et.SessionManager) et.Dispatcher {
	d := &dynamicDispatcher{
		log:    l,
		reg:    r,
		mgr:    mgr,
		done:   make(chan struct{}),
		cchan:  make(chan *et.EventDataElement, 1000),
		cqueue: queue.NewQueue(),
		pools:  make(map[oam.AssetType]*pipelinePool),
	}

	go d.runEvents()
	return d
}

func (d *dynamicDispatcher) Shutdown() {
	// Optional: add pool-level shutdown if you want explicit draining.
	select {
	case <-d.done:
		return
	default:
	}
	close(d.done)
}

func (d *dynamicDispatcher) runEvents() {
	for {
		select {
		case <-d.done:
			return
		default:
		}

		select {
		case e := <-d.cchan:
			d.cqueue.Append(e)
		case <-d.cqueue.Signal():
			d.cqueue.Process(func(data interface{}) {
				if ede, valid := data.(*et.EventDataElement); valid {
					d.completedCallback(ede)
				}
			})
		}
	}
}

func (d *dynamicDispatcher) completedCallback(data interface{}) {
	ede, ok := data.(*et.EventDataElement)
	if !ok {
		return
	}

	_ = ede.Event.Session.Queue().Processed(ede.Event.Entity)

	if inst, ok := ede.Ref.(*pipelineInstance); ok {
		inst.onDequeue(ede.Event)
	}

	if err := ede.Error; err != nil {
		ede.Event.Session.Log().WithGroup("event").With("name", ede.Event.Name).Error(err.Error())
	}
	// increment the number of events processed in the session
	if stats := ede.Event.Session.Stats(); stats != nil {
		stats.Lock()
		stats.WorkItemsCompleted++
		stats.Unlock()
	}
}

func (d *dynamicDispatcher) DispatchEvent(e *et.Event) error {
	if e == nil || e.Entity == nil {
		return nil
	}

	// do not schedule the same asset more than once
	if e.Session.Queue().Has(e.Entity) {
		return nil
	}

	err := e.Session.Queue().Append(e.Entity, false)
	if err != nil {
		return err
	}

	// increment the number of events processed in the session
	if stats := e.Session.Stats(); stats != nil {
		stats.Lock()
		stats.WorkItemsTotal++
		stats.Unlock()
	}

	atype := e.Entity.Asset.AssetType()
	if pool := d.getOrCreatePool(atype); pool != nil {
		return pool.Dispatch(e)
	}

	return fmt.Errorf("no pipeline pool available for asset type %s", string(atype))
}

func (d *dynamicDispatcher) getOrCreatePool(atype oam.AssetType) *pipelinePool {
	d.mu.RLock()
	pool := d.pools[atype]
	d.mu.RUnlock()
	if pool != nil {
		return pool
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	if pool = d.pools[atype]; pool != nil {
		return pool
	}

	// TODO: make these configurable per AssetType
	minInstances := 2
	maxInstances := 16
	pool = newPipelinePool(d, atype, minInstances, maxInstances)
	d.pools[atype] = pool
	return pool
}
