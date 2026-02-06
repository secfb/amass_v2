// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package org

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/general"
	oamorg "github.com/owasp-amass/open-asset-model/org"
)

var createOrgLock sync.Mutex

func CreateOrgAsset(session et.Session, obj *dbt.Entity, rel oam.Relation, o *oamorg.Organization, src *et.Source) (*dbt.Entity, error) {
	createOrgLock.Lock()
	defer createOrgLock.Unlock()

	if o == nil || o.Name == "" {
		return nil, errors.New("missing the organization name")
	} else if src == nil {
		return nil, errors.New("missing the source")
	}

	var orgent *dbt.Entity
	if obj != nil {
		orgent = dedupChecks(session, obj, o)
	}

	if orgent == nil {
		name := strings.ToLower(o.Name)
		id := &general.Identifier{
			UniqueID: fmt.Sprintf("%s:%s", general.OrganizationName, name),
			ID:       name,
			Type:     general.OrganizationName,
		}

		idctx, idcancel := context.WithTimeout(session.Ctx(), 10*time.Second)
		defer idcancel()

		if ident, err := session.DB().CreateAsset(idctx, id); err == nil && ident != nil {
			_, _ = session.DB().CreateEntityProperty(idctx, ident, &general.SourceProperty{
				Source:     src.Name,
				Confidence: src.Confidence,
			})

			o.ID = genStableOrgID()
			octx, ocancel := context.WithTimeout(session.Ctx(), 20*time.Second)
			defer ocancel()

			orgent, err = session.DB().CreateAsset(octx, o)
			if err != nil || orgent == nil {
				return nil, errors.New("failed to create the OAM Organization asset")
			}

			_, _ = session.DB().CreateEntityProperty(octx, orgent, &general.SourceProperty{
				Source:     src.Name,
				Confidence: src.Confidence,
			})

			ctx, cancel := context.WithTimeout(session.Ctx(), 10*time.Second)
			defer cancel()

			if err := createRelation(ctx, session, orgent, &general.SimpleRelation{Name: "id"}, ident, src); err != nil {
				return nil, err
			}
		}
	}

	if obj != nil && rel != nil && orgent != nil && obj.ID != orgent.ID {
		ctx, cancel := context.WithTimeout(session.Ctx(), 10*time.Second)
		defer cancel()

		if err := createRelation(ctx, session, obj, rel, orgent, src); err != nil {
			return nil, err
		}
	}

	return orgent, nil
}

func genStableOrgID() string {
	return uuid.New().String()
}

func createRelation(ctx context.Context, sess et.Session, obj *dbt.Entity, rel oam.Relation, subject *dbt.Entity, src *et.Source) error {
	edge, err := sess.DB().CreateEdge(ctx, &dbt.Edge{
		Relation:   rel,
		FromEntity: obj,
		ToEntity:   subject,
	})
	if err != nil {
		return err
	} else if edge == nil {
		return errors.New("failed to create the edge")
	}

	_, err = sess.DB().CreateEdgeProperty(ctx, edge, &general.SourceProperty{
		Source:     src.Name,
		Confidence: src.Confidence,
	})
	return err
}
