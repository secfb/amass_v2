// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package scope

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/adrg/strutil"
	"github.com/adrg/strutil/metrics"
	"github.com/caffix/stringset"
	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamcert "github.com/owasp-amass/open-asset-model/certificate"
	oamcon "github.com/owasp-amass/open-asset-model/contact"
	oamorg "github.com/owasp-amass/open-asset-model/org"
	oamreg "github.com/owasp-amass/open-asset-model/registration"
	"golang.org/x/net/publicsuffix"
)

func (s *Scope) IsAssociated(req *et.Association) ([]*et.Association, error) {
	if req == nil || req.Submission == nil || req.Submission.Asset == nil || req.Confidence < 0 || req.Confidence > 100 {
		return nil, errors.New("invalid request")
	}
	if atype := req.Submission.Asset.AssetType(); atype != oam.FQDN &&
		atype != oam.Identifier && atype != oam.Organization && atype != oam.Location {
		return nil, errors.New("the request included a submission with an unsupported asset type")
	}

	// related assets that provide association matching value
	assocs := s.AssetsWithAssociation(req.Submission)
	// are any of these assets in the current session scope?
	results := s.checkRelatedAssetsforAssoc(req, assocs)

	if req.ScopeChange {
		// add all assets related to the asset found to be associated
		for _, result := range results {
			var impacted []*dbt.Entity

			for _, im := range append(result.ImpactedAssets, result.Match) {
				if s.Add(im.Asset) {
					impacted = append(impacted, im)
				}
			}
			// review all previously seen assets that provide association for scope changes
			for size := len(impacted); size > 0; {
				added := s.reviewAndUpdate(req)

				size = len(added)
				impacted = append(impacted, added...)
			}

			result.ImpactedAssets = impacted
			if len(result.ImpactedAssets) > 0 {
				result.ScopeChange = true
				s.addScopeChangesToRationale(result)
			}
		}
	}

	if len(results) == 0 {
		return nil, errors.New("the submission is not associated with assets in the session scope")
	}
	return results, nil
}

func (s *Scope) addScopeChangesToRationale(result *et.Association) {
	var changes []string

	for _, im := range result.ImpactedAssets {
		changes = append(changes, fmt.Sprintf("[%s: %s]", im.Asset.AssetType(), im.Asset.Key()))
	}

	result.Rationale += ". The following assets were added to the session scope: " + strings.Join(changes, ", ")
}

func (s *Scope) reviewAndUpdate(req *et.Association) []*dbt.Entity {
	var assocs []*dbt.Entity

	ctx, cancel := context.WithTimeout(s.Session.Ctx(), 10*time.Second)
	defer cancel()

	since := s.ttlStartTime(oam.DomainRecord, oam.DomainRecord)
	if drs, err := s.Session.DB().FindEntitiesByType(ctx, oam.DomainRecord, since, 0); err == nil && len(drs) > 0 {
		assocs = append(assocs, drs...)
	}

	since = s.ttlStartTime(oam.IPNetRecord, oam.IPNetRecord)
	if iprecs, err := s.Session.DB().FindEntitiesByType(ctx, oam.IPNetRecord, since, 0); err == nil && len(iprecs) > 0 {
		assocs = append(assocs, iprecs...)
	}

	since = s.ttlStartTime(oam.AutnumRecord, oam.AutnumRecord)
	if autnums, err := s.Session.DB().FindEntitiesByType(ctx, oam.AutnumRecord, since, 0); err == nil && len(autnums) > 0 {
		assocs = append(assocs, autnums...)
	}

	since = s.ttlStartTime(oam.TLSCertificate, oam.TLSCertificate)
	if certs, err := s.Session.DB().FindEntitiesByType(ctx, oam.TLSCertificate, since, 0); err == nil && len(certs) > 0 {
		assocs = append(assocs, certs...)
	}

	var impacted []*dbt.Entity
	for _, assoc := range s.checkRelatedAssetsforAssoc(req, assocs) {
		for _, a := range append(assoc.ImpactedAssets, assoc.Match) {
			if s.Add(a.Asset) {
				impacted = append(impacted, a)
			}
		}
	}
	return impacted
}

func (s *Scope) checkRelatedAssetsforAssoc(req *et.Association, assocs []*dbt.Entity) []*et.Association {
	var results []*et.Association

	for _, assoc := range assocs {
		var best int
		var msg string

		var impacted []*dbt.Entity
		for _, asset := range append(s.assetsRelatedToAssetWithAssoc(assoc), assoc) {
			if req.ScopeChange {
				impacted = append(impacted, asset)
			}
			if match, conf := s.IsAssetInScope(asset.Asset, req.Confidence); conf > 0 {
				if conf > best {
					best = conf

					aa := assoc.Asset
					sa := req.Submission.Asset
					msg = fmt.Sprintf("[%s: %s] is related to an asset with associative value [%s: %s], ", sa.AssetType(), sa.Key(), aa.AssetType(), aa.Key())
					msg += fmt.Sprintf("which has a related asset [%s: %s] that was determined associated with [%s: %s] at a confidence of %d out of 100",
						asset.Asset.AssetType(), asset.Asset.Key(), match.AssetType(), match.Key(), conf)
				}
			}
		}

		if best > 0 {
			results = append(results, &et.Association{
				Submission:     req.Submission,
				Match:          assoc,
				Rationale:      msg,
				Confidence:     best,
				ImpactedAssets: impacted,
			})
		}
	}
	return results
}

func (s *Scope) assetsRelatedToAssetWithAssoc(assoc *dbt.Entity) []*dbt.Entity {
	set := stringset.New(assoc.ID)
	defer set.Close()

	var results []*dbt.Entity
	for findings := []*dbt.Entity{assoc}; len(findings) > 0; {
		assets := findings
		findings = []*dbt.Entity{}

		for _, a := range assets {
			var found bool

			switch v := a.Asset.(type) {
			/*case *oamdns.FQDN:
			ctx, cancel := context.WithTimeout(s.Session.Ctx(), 3*time.Second)
			defer cancel()

			since := s.ttlStartTime(oam.FQDN, oam.FQDN)
			if ents, err := s.Session.DB().IncomingEdges(ctx, a, since, "node"); err != nil || len(ents) == 0 {
				found = true
				results = append(results, a)
			}*/
			case *oamorg.Organization:
				found = true
				if cert, ok := assoc.Asset.(*oamcert.TLSCertificate); !ok || s.orgNameSimilarToCommon(v, cert) {
					results = append(results, a)
				}
			case *oamcon.Location:
				found = true
				results = append(results, a)
			}

			if !found {
				if f, err := s.awayFromAssetsWithAssociation(a); err == nil && len(f) > 0 {
					for _, finding := range f {
						if !set.Has(finding.ID) {
							set.Insert(finding.ID)
							findings = append(findings, finding)
						}
					}
				}
			}
		}
	}
	return results
}

func (s *Scope) AssetsWithAssociation(asset *dbt.Entity) []*dbt.Entity {
	set := stringset.New(asset.ID)
	defer set.Close()

	var results []*dbt.Entity
	since := s.ttlStartTime(oam.TLSCertificate, oam.Service)
	for findings := []*dbt.Entity{asset}; len(findings) > 0; {
		assets := findings
		findings = []*dbt.Entity{}

		for _, a := range assets {
			var found bool

			switch a.Asset.(type) {
			case *oamreg.DomainRecord:
				found = true
				results = append(results, a)
			case *oamreg.IPNetRecord:
				found = true
				results = append(results, a)
			case *oamreg.AutnumRecord:
				found = true
				results = append(results, a)
			case *oamcert.TLSCertificate:
				found = true
				ctx, cancel := context.WithTimeout(s.Session.Ctx(), 10*time.Second)
				defer cancel()

				// only certificates directly used by the services are considered
				if _, err := s.Session.DB().IncomingEdges(ctx, a, since, "certificate"); err == nil {
					results = append(results, a)
				}
			}

			if !found {
				if f, err := s.towardsAssetsWithAssociation(a); err == nil && len(f) > 0 {
					for _, finding := range f {
						if !set.Has(finding.ID) {
							set.Insert(finding.ID)
							findings = append(findings, finding)
						}
					}
				}
			}
		}
	}
	return results
}

func (s *Scope) awayFromAssetsWithAssociation(assoc *dbt.Entity) ([]*dbt.Entity, error) {
	var results []*dbt.Entity
	// Determine relationship directions to follow on the graph
	var out, in bool
	var outRels, inRels []string
	var outSince, inSince time.Time
	switch assoc.Asset.AssetType() {
	/*case oam.FQDN:
	in = true
	inRels = append(inRels, "node")
	inSince = s.ttlStartTime(oam.FQDN, oam.FQDN)*/
	case oam.DomainRecord:
		out = true
		outRels = append(outRels, "registrant_contact")
		outSince = s.ttlStartTime(oam.DomainRecord, oam.ContactRecord)
	case oam.IPNetRecord:
		out = true
		outRels = append(outRels, "registrant")
		outSince = s.ttlStartTime(oam.IPNetRecord, oam.ContactRecord)
	case oam.AutnumRecord:
		out = true
		outRels = append(outRels, "registrant")
		outSince = s.ttlStartTime(oam.AutnumRecord, oam.ContactRecord)
	case oam.TLSCertificate:
		out = true
		outRels = append(outRels, "subject_contact")
		outSince = s.ttlStartTime(oam.TLSCertificate, oam.ContactRecord)
	case oam.ContactRecord:
		out = true
		outRels = append(outRels, "organization", "location")
		since1 := s.ttlStartTime(oam.ContactRecord, oam.Organization)
		outSince = s.ttlStartTime(oam.ContactRecord, oam.Location)
		if !since1.IsZero() && since1.Before(outSince) {
			outSince = since1
		}

	}
	if out {
		ctx, cancel := context.WithTimeout(s.Session.Ctx(), 10*time.Second)
		defer cancel()

		if edges, err := s.Session.DB().OutgoingEdges(ctx, assoc, outSince, outRels...); err == nil && len(edges) > 0 {
			for _, edge := range edges {
				if entity, err := s.Session.DB().FindEntityById(ctx, edge.ToEntity.ID); err == nil && entity != nil {
					results = append(results, entity)
				}
			}
		}
	}
	if in {
		ctx, cancel := context.WithTimeout(s.Session.Ctx(), 10*time.Second)
		defer cancel()

		if edges, err := s.Session.DB().IncomingEdges(ctx, assoc, inSince, inRels...); err == nil && len(edges) > 0 {
			for _, edge := range edges {
				if entity, err := s.Session.DB().FindEntityById(ctx, edge.FromEntity.ID); err == nil && entity != nil {
					results = append(results, entity)
				}
			}
		}
	}
	if len(results) == 0 {
		return nil, errors.New("zero assets were found in-scope one hop away from the provided asset")
	}
	return results, nil
}

func (s *Scope) towardsAssetsWithAssociation(asset *dbt.Entity) ([]*dbt.Entity, error) {
	var results []*dbt.Entity
	// Determine relationship directions to follow on the graph
	var out, in bool
	var outRels, inRels []string
	var outSince, inSince time.Time
	switch asset.Asset.AssetType() {
	case oam.FQDN:
		out = true
		outRels = append(outRels, "registration")
		outSince = s.ttlStartTime(oam.FQDN, oam.DomainRecord)
		in = true
		inRels = append(inRels, "node")
		inSince = s.ttlStartTime(oam.FQDN, oam.FQDN)
	case oam.IPAddress:
		in = true
		inRels = append(inRels, "contains")
		inSince = s.ttlStartTime(oam.IPAddress, oam.Netblock)
	case oam.Netblock:
		out = true
		outRels = append(outRels, "registration")
		outSince = s.ttlStartTime(oam.Netblock, oam.IPNetRecord)
	case oam.AutonomousSystem:
		out = true
		outRels = append(outRels, "registration")
		outSince = s.ttlStartTime(oam.AutonomousSystem, oam.AutnumRecord)
	case oam.Organization:
		in = true
		inRels = append(inRels, "organization")
		inSince = s.ttlStartTime(oam.Organization, oam.ContactRecord)
	case oam.Location:
		in = true
		inRels = append(inRels, "location")
		inSince = s.ttlStartTime(oam.Location, oam.ContactRecord)
	case oam.ContactRecord:
		in = true
		inRels = append(inRels, "registrant", "registrant_contact", "subject_contact")
		since1 := s.ttlStartTime(oam.ContactRecord, oam.DomainRecord)
		since2 := s.ttlStartTime(oam.ContactRecord, oam.IPNetRecord)
		since3 := s.ttlStartTime(oam.ContactRecord, oam.AutnumRecord)
		inSince = s.ttlStartTime(oam.ContactRecord, oam.TLSCertificate)
		if !since1.IsZero() && since1.Before(inSince) {
			inSince = since1
		}
		if !since2.IsZero() && since2.Before(inSince) {
			inSince = since2
		}
		if !since3.IsZero() && since3.Before(inSince) {
			inSince = since3
		}
	case oam.Service:
		out = true
		outRels = append(outRels, "certificate")
		outSince = s.ttlStartTime(oam.Service, oam.TLSCertificate)
	}
	if out {
		ctx, cancel := context.WithTimeout(s.Session.Ctx(), 10*time.Second)
		defer cancel()

		if edges, err := s.Session.DB().OutgoingEdges(ctx, asset, outSince, outRels...); err == nil && len(edges) > 0 {
			for _, edge := range edges {
				if entity, err := s.Session.DB().FindEntityById(ctx, edge.ToEntity.ID); err == nil && entity != nil {
					results = append(results, entity)
				}
			}
		}
	}
	if in {
		ctx, cancel := context.WithTimeout(s.Session.Ctx(), 10*time.Second)
		defer cancel()

		if edges, err := s.Session.DB().IncomingEdges(ctx, asset, inSince, inRels...); err == nil && len(edges) > 0 {
			for _, edge := range edges {
				if entity, err := s.Session.DB().FindEntityById(ctx, edge.FromEntity.ID); err == nil && entity != nil {
					results = append(results, entity)
				}
			}
		}
	}
	if len(results) == 0 {
		return nil, errors.New("zero assets were found in-scope one hop toward the provided asset")
	}
	return results, nil
}

func (s *Scope) ttlStartTime(from, to oam.AssetType) time.Time {
	if matches, err := s.Session.Config().CheckTransformations(string(from), string(to)); err == nil && matches != nil {
		if ttl := matches.TTL(string(to)); ttl >= 0 {
			return time.Now().Add(time.Duration(-ttl) * time.Minute)
		}
	}
	return time.Time{}
}

func (s *Scope) orgNameSimilarToCommon(o *oamorg.Organization, cert *oamcert.TLSCertificate) bool {
	swg := metrics.NewSmithWatermanGotoh()
	swg.CaseSensitive = false
	swg.GapPenalty = -0.1
	swg.Substitution = metrics.MatchMismatch{
		Match:    1,
		Mismatch: -0.5,
	}

	dom, err := publicsuffix.EffectiveTLDPlusOne(cert.SubjectCommonName)
	if err != nil {
		return false
	}

	labels := strings.Split(dom, ".")
	if len(labels) < 2 {
		return false
	}

	common := labels[0]
	if sim := strutil.Similarity(o.Name, common, swg); sim >= 0.5 {
		return true
	}
	return false
}
