// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package horizontals

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/miekg/dns"
	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamcert "github.com/owasp-amass/open-asset-model/certificate"
	oamcon "github.com/owasp-amass/open-asset-model/contact"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oamgen "github.com/owasp-amass/open-asset-model/general"
	oamnet "github.com/owasp-amass/open-asset-model/network"
	oamorg "github.com/owasp-amass/open-asset-model/org"
	oamreg "github.com/owasp-amass/open-asset-model/registration"
	oamurl "github.com/owasp-amass/open-asset-model/url"
	"github.com/owasp-amass/resolve/utils"
	"golang.org/x/net/publicsuffix"
)

type horizPlugin struct {
	name       string
	log        *slog.Logger
	horfqdn    *horfqdn
	horaddr    *horaddr
	horContact *horContact
	source     *et.Source
}

func NewHorizontals() et.Plugin {
	return &horizPlugin{
		name: "Horizontals",
		source: &et.Source{
			Name:       "Horizontals",
			Confidence: 50,
		},
	}
}

func (h *horizPlugin) Name() string {
	return h.name
}

func (h *horizPlugin) Start(r et.Registry) error {
	h.log = r.Log().WithGroup("plugin").With("name", h.name)

	h.horfqdn = &horfqdn{
		name:   h.name + "-FQDN-Handler",
		plugin: h,
	}
	if err := r.RegisterHandler(&et.Handler{
		Plugin:       h,
		Name:         h.horfqdn.name,
		Position:     10,
		MaxInstances: support.MaxHandlerInstances,
		Transforms:   []string{string(oam.FQDN)},
		EventType:    oam.FQDN,
		Callback:     h.horfqdn.check,
	}); err != nil {
		return err
	}

	h.horaddr = &horaddr{
		name:   h.name + "-IPAddress-Handler",
		plugin: h,
	}
	if err := r.RegisterHandler(&et.Handler{
		Plugin:       h,
		Name:         h.horaddr.name,
		Position:     10,
		MaxInstances: support.MaxHandlerInstances,
		Transforms:   []string{string(oam.IPAddress)},
		EventType:    oam.IPAddress,
		Callback:     h.horaddr.check,
	}); err != nil {
		return err
	}

	h.horContact = &horContact{
		name:   h.name + "-ContactRecord-Handler",
		plugin: h,
	}
	if err := r.RegisterHandler(&et.Handler{
		Plugin:       h,
		Name:         h.horContact.name,
		Position:     10,
		MaxInstances: support.MaxHandlerInstances,
		Transforms: []string{
			string(oam.Organization),
			string(oam.Location),
			string(oam.Identifier),
		},
		EventType: oam.ContactRecord,
		Callback:  h.horContact.check,
	}); err != nil {
		return err
	}

	h.log.Info("Plugin started")
	return nil
}

func (h *horizPlugin) Stop() {
	h.log.Info("Plugin stopped")
}

func assetToContentFilters(a oam.Asset) dbt.ContentFilters {
	filters := dbt.ContentFilters{}

	switch v := a.(type) {
	case *oamdns.FQDN:
		filters["name"] = v.Name
	case *oamnet.IPAddress:
		filters["address"] = v.Address.String()
	case *oamnet.Netblock:
		filters["cidr"] = v.CIDR.String()
	case *oamnet.AutonomousSystem:
		filters["number"] = v.Number
	case *oamreg.DomainRecord:
		filters["domain"] = v.Domain
	case *oamreg.IPNetRecord:
		filters["handle"] = v.Handle
	case *oamreg.AutnumRecord:
		filters["handle"] = v.Handle
	case *oamgen.Identifier:
		filters["unique_id"] = v.UniqueID
	case *oamcert.TLSCertificate:
		filters["serial_number"] = v.SerialNumber
	case *oamurl.URL:
		filters["url"] = v.Raw
	case *oamorg.Organization:
		filters["unique_id"] = v.ID
	case *oamcon.Location:
		filters["address"] = v.Address
	}
	return filters
}

func (h *horizPlugin) process(e *et.Event, since time.Time, assets []*dbt.Entity) {
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), time.Minute)
	defer cancel()

	for _, asset := range assets {
		// check for new networks added to the scope
		switch v := asset.Asset.(type) {
		case *oamnet.Netblock:
			h.ipPTRTargetsInScope(ctx, e, asset, since)
			h.sweepAroundIPs(ctx, e, asset, since)
			//h.sweepNetblock(e, v, src)
		case *oamreg.IPNetRecord:
			if ents, err := e.Session.DB().FindEntitiesByContent(ctx, oam.Netblock, since, 1, dbt.ContentFilters{
				"cidr": v.CIDR.String(),
			}); err == nil {
				a := ents[0]

				if _, ok := a.Asset.(*oamnet.Netblock); ok {
					h.ipPTRTargetsInScope(ctx, e, a, since)
					h.sweepAroundIPs(ctx, e, a, since)
					//h.sweepNetblock(e, nb, src)
				}
			}
		}

		_, _ = e.Session.DB().CreateEntityProperty(ctx, asset, &oamgen.SourceProperty{
			Source:     h.source.Name,
			Confidence: h.source.Confidence,
		})

		_ = e.Dispatcher.DispatchEvent(&et.Event{
			Name:    asset.Asset.Key(),
			Entity:  asset,
			Session: e.Session,
		})
	}
}

func (h *horizPlugin) ipPTRTargetsInScope(ctx context.Context, e *et.Event, nb *dbt.Entity, since time.Time) {
	if edges, err := e.Session.DB().OutgoingEdges(ctx, nb, since, "contains"); err == nil && len(edges) > 0 {
		for _, edge := range edges {
			to, err := e.Session.DB().FindEntityById(ctx, edge.ToEntity.ID)
			if err != nil {
				continue
			}

			reverse, err := dns.ReverseAddr(to.Asset.Key())
			if err != nil {
				continue
			}

			if ents, err := e.Session.DB().FindEntitiesByContent(ctx, oam.FQDN, since, 1, dbt.ContentFilters{
				"name": utils.RemoveLastDot(reverse),
			}); err == nil {
				if edges, err := e.Session.DB().OutgoingEdges(ctx, ents[0], since, "dns_record"); err == nil && len(edges) > 0 {
					for _, edge := range edges {
						if rel, ok := edge.Relation.(*oamdns.BasicDNSRelation); !ok || rel.Header.RRType != 12 {
							continue
						}
						to, err := e.Session.DB().FindEntityById(ctx, edge.ToEntity.ID)
						if err != nil {
							continue
						}
						if dom, err := publicsuffix.EffectiveTLDPlusOne(to.Asset.Key()); err == nil {
							if e.Session.Scope().AddDomain(dom) {
								h.submitFQDN(e, dom)
								e.Session.Log().Info(fmt.Sprintf("[%s: %s] was added to the session scope", "FQDN", dom))
							}
						}
					}
				}
			}
		}
	}
}

func (h *horizPlugin) sweepAroundIPs(ctx context.Context, e *et.Event, nb *dbt.Entity, since time.Time) {
	if edges, err := e.Session.DB().OutgoingEdges(ctx, nb, since, "contains"); err == nil && len(edges) > 0 {
		for _, edge := range edges {
			size := 100
			if e.Session.Config().Active {
				size = 250
			}

			to, err := e.Session.DB().FindEntityById(ctx, edge.ToEntity.ID)
			if err != nil {
				continue
			}
			if ip, ok := to.Asset.(*oamnet.IPAddress); ok {
				support.IPAddressSweep(e, ip, h.source, size, h.submitIPAddress)
			}
		}
	}
}

/*
	func (h *horizPlugin) sweepNetblock(e *et.Event, nb *oamnet.Netblock, src *et.Source) {
		for _, ip := range h.inScopeNetblockIPs(nb) {
			h.submitIPAddresses(e, ip, src)
		}
	}

	func (h *horizPlugin) inScopeNetblockIPs(nb *oamnet.Netblock) []*oamnet.IPAddress {
		_, cidr, err := net.ParseCIDR(nb.CIDR.String())
		if err != nil {
			return []*oamnet.IPAddress{}
		}

		var ips []net.IP
		if nb.CIDR.Masked().Bits() > 20 {
			ips = amassnet.AllHosts(cidr)
		} else {
			ips = h.distAcrossNetblock(cidr, 2048)
		}

		var results []*oamnet.IPAddress
		for _, ip := range ips {
			addr := &oamnet.IPAddress{Address: netip.MustParseAddr(ip.String()), Type: "IPv4"}
			if addr.Address.Is6() {
				addr.Type = "IPv6"
			}
			results = append(results, addr)
		}
		return results
	}

	func (h *horizPlugin) distAcrossNetblock(cidr *net.IPNet, num int) []net.IP {
		r := rand.New(rand.NewSource(time.Now().UnixNano()))

		_, bits := cidr.Mask.Size()
		if bits == 0 {
			return []net.IP{}
		}

		total := 1 << bits
		inc := total / num
		var results []net.IP
		for ip := cidr.IP.Mask(cidr.Mask); cidr.Contains(ip); {
			sel := r.Intn(inc)

			for i := 0; i < inc; i++ {
				if i == sel {
					results = append(results, net.ParseIP(ip.String()))
				}
				amassnet.IPInc(ip)
			}
		}
		return results
	}
*/

func (h *horizPlugin) submitIPAddress(e *et.Event, asset *oamnet.IPAddress, src *et.Source) {
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 10*time.Second)
	defer cancel()

	// ensure we do not work on an IP address that was processed previously
	_, err := e.Session.DB().FindEntitiesByContent(ctx, oam.IPAddress, e.Session.StartTime(), 1, dbt.ContentFilters{
		"address": asset.Address.String(),
	})
	if err == nil {
		return
	}

	addr, err := e.Session.DB().CreateAsset(ctx, asset)
	if err == nil && addr != nil {
		_, _ = e.Session.DB().CreateEntityProperty(ctx, addr, &oamgen.SourceProperty{
			Source:     src.Name,
			Confidence: src.Confidence,
		})
		_ = e.Dispatcher.DispatchEvent(&et.Event{
			Name:    addr.Asset.Key(),
			Entity:  addr,
			Session: e.Session,
		})
	}
}

func (h *horizPlugin) submitFQDN(e *et.Event, dom string) {
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 3*time.Second)
	defer cancel()

	fqdn, err := e.Session.DB().CreateAsset(ctx, &oamdns.FQDN{Name: dom})
	if err == nil && fqdn != nil {
		_, _ = e.Session.DB().CreateEntityProperty(ctx, fqdn, &oamgen.SourceProperty{
			Source:     h.source.Name,
			Confidence: h.source.Confidence,
		})
		_ = e.Dispatcher.DispatchEvent(&et.Event{
			Name:    fqdn.Asset.Key(),
			Entity:  fqdn,
			Session: e.Session,
		})
	}
}
