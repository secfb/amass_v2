// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/owasp-amass/amass/v5/config"
	"github.com/owasp-amass/amass/v5/engine/pubsub"
	"github.com/owasp-amass/amass/v5/engine/sessions/scope"
	"github.com/owasp-amass/asset-db/repository"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/yl2chen/cidranger"
)

type Session interface {
	ID() uuid.UUID
	Log() *slog.Logger
	PubSub() *pubsub.Logger
	Config() *config.Config
	Scope() *scope.Scope
	StartTime() time.Time
	DB() repository.Repository
	Backlog() Backlog
	CIDRanger() cidranger.Ranger
	TmpDir() string
	Stats() *SessionStats
	Done() bool
	Kill()
}

// Backlog is the durable, per-session work backlog with claim/lease semantics.
// Items are:
//   - Enqueued (queued)
//   - Claimed (leased/in-flight)
//   - Acked (done) or Released (returned to queued)
type Backlog interface {
	Has(e *dbt.Entity) bool

	Enqueue(e *dbt.Entity) error
	EnqueueDone(e *dbt.Entity) error

	// ClaimNext leases up to num entities of this asset type.
	// Claimed items will not be returned again until Ack/Release or lease expiry.
	ClaimNext(atype oam.AssetType, num int) ([]*dbt.Entity, error)

	// Ack marks completion (done). Call on actual completion (e.g. pipeline finished).
	Ack(e *dbt.Entity, enforceOwner bool) error

	// Release returns a leased item back to queued (e.g. backpressure/admission failure).
	Release(e *dbt.Entity, atype oam.AssetType, enforceOwner bool) error

	Counts(atype oam.AssetType) (queued, leased, done int64, err error)

	Delete(e *dbt.Entity) error
	Close() error

	// Optional knobs:
	SetOwner(owner string)
	SetLeaseTTL(ttl time.Duration)
}

type SessionStats struct {
	sync.RWMutex
	WorkItemsCompleted int `json:"workItemsCompleted"`
	WorkItemsTotal     int `json:"workItemsTotal"`
}

type SessionManager interface {
	NewSession(cfg *config.Config) (Session, error)
	AddSession(s Session) error
	CancelSession(id uuid.UUID)
	GetSession(id uuid.UUID) Session
	GetSessions() []Session
	Shutdown()
}

type AmassRangerEntry interface {
	Network() net.IPNet
	AutonomousSystem() int
	Source() *Source
}
