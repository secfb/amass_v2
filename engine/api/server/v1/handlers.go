// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/owasp-amass/amass/v5/config"
	oam "github.com/owasp-amass/open-asset-model"
)

const maxBulkItems = 5000

type HealthCheckResponse struct {
	Result string `json:"result"`
}

type CreateSessionResponse struct {
	SessionToken string `json:"sessionToken"`
}

type ListSessionsResponse struct {
	SessionTokens []string `json:"sessionTokens"`
}

type SessionStatsResponse struct {
	WorkItemsCompleted int `json:"workItemsCompleted"`
	WorkItemsTotal     int `json:"workItemsTotal"`
}

type ScopeResponse struct {
	Data []json.RawMessage `json:"data"`
}

type AddAssetResponse struct {
	EntityID string `json:"entityID"`
}

// Bulk typed add: {"items":[ <OAM obj>, <OAM obj>, ... ]}
// where each item is arbitrary JSON object without "type".
type BulkAddAssetsRequest struct {
	Items []json.RawMessage `json:"items"`
}

type BulkAddAssetsResponse struct {
	Ingested int64 `json:"ingested"`
	Stored   int64 `json:"stored"`
	Failed   int64 `json:"failed"`
}

var (
	ErrNotFound   = errors.New("not found")
	ErrBadRequest = errors.New("bad request")
)

func (s *Server) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		s.log.Info("request completed", "method", r.Method, "path", r.URL.Path, "duration", time.Since(start))
	})
}

// healthCheck godoc
//
// @Summary      Health check
// @Description  Returns a simple health indicator that the Amass Engine API is running.
// @Tags         system
// @Produce      json
// @Success      200  {object}  HealthCheckResponse
// @Router       /v1/health [get]
func (s *Server) healthCheck(w http.ResponseWriter, r *http.Request) {
	resp := HealthCheckResponse{Result: "Amass Engine OK"}

	writeJSON(w, http.StatusOK, resp)
}

// createSessionHandler godoc
//
// @Summary      Create a new engine session
// @Description  Creates a new Amass engine session using the provided configuration JSON.
// @Tags         sessions
// @Accept       json
// @Produce      json
// @Param        config  body      config.Config  true  "Engine configuration"
// @Success      201     {object}  CreateSessionResponse
// @Failure      400     {object}  ErrorResponse  "Invalid JSON or invalid configuration"
// @Failure      500     {object}  ErrorResponse  "Failed to create session"
// @Router       /v1/sessions [post]
func (s *Server) createSessionHandler(w http.ResponseWriter, r *http.Request) {
	raw, err := readRawJSON(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON", err)
		return
	}
	// minimal validation: ensure it’s valid JSON object
	if !looksLikeJSONObject(raw) {
		writeError(w, http.StatusBadRequest, "invalid JSON object", nil)
		return
	}

	var config config.Config
	if err := json.Unmarshal(raw, &config); err != nil {
		writeError(w, http.StatusBadRequest, "invalid configuration", err)
		return
	}
	// Populate FROM/TO in transformations
	for k, t := range config.Transformations {
		_ = t.Split(k)
	}

	sess, err := s.mgr.NewSession(&config)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create session", err)
		return
	}

	writeJSON(w, http.StatusCreated, CreateSessionResponse{
		SessionToken: sess.ID().String(),
	})
}

// listSessionsHandler godoc
//
// @Summary      List active sessions
// @Description  Returns the session tokens for all currently active sessions.
// @Tags         sessions
// @Produce      json
// @Success      200  {object}  ListSessionsResponse
// @Failure      404  {object}  ErrorResponse  "Zero sessions found"
// @Router       /v1/sessions/list [get]
func (s *Server) listSessionsHandler(w http.ResponseWriter, r *http.Request) {
	sessions := s.mgr.GetSessions()
	if len(sessions) == 0 {
		writeError(w, http.StatusNotFound, "zero sessions found", ErrNotFound)
		return
	}

	var resp ListSessionsResponse
	for _, sess := range sessions {
		resp.SessionTokens = append(resp.SessionTokens, sess.ID().String())
	}

	writeJSON(w, http.StatusOK, resp)
}

// terminateSessionHandler godoc
//
// @Summary      Terminate a session
// @Description  Cancels an active session. Returns no content on success.
// @Tags         sessions
// @Param        session_token  path  string  true  "Session token (UUID)"
// @Success      204
// @Failure      400  {object}  ErrorResponse  "Invalid session token"
// @Failure      404  {object}  ErrorResponse  "Session not found"
// @Router       /v1/sessions/{session_token} [delete]
func (s *Server) terminateSessionHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	sid := vars["session_token"]

	// Check if the session token is valid
	token, err := uuid.Parse(sid)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid session token", err)
		return
	}
	// Check if the session exists
	// and if the session is not already terminated
	sess := s.mgr.GetSession(token)
	if sess == nil {
		writeError(w, http.StatusNotFound, "session not found", ErrNotFound)
		return
	}

	go s.mgr.CancelSession(token)
	w.WriteHeader(http.StatusNoContent)
}

// getStatsHandler godoc
//
// @Summary      Get session statistics
// @Description  Returns the current runtime statistics for a session.
// @Tags         sessions
// @Produce      json
// @Param        session_token  path  string  true  "Session token (UUID)"
// @Success      200  {object}  SessionStatsResponse
// @Failure      400  {object}  ErrorResponse  "Invalid session token"
// @Failure      404  {object}  ErrorResponse  "Session not found"
// @Router       /v1/sessions/{session_token}/stats [get]
func (s *Server) getStatsHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	sid := vars["session_token"]

	// Check if the session token is valid
	token, err := uuid.Parse(sid)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid session token", err)
		return
	}
	// Check if the session exists
	// and if the session is not already terminated
	sess := s.mgr.GetSession(token)
	if sess == nil {
		writeError(w, http.StatusNotFound, "session not found", ErrNotFound)
		return
	}
	stats := sess.Stats()

	stats.RLock()
	writeJSON(w, http.StatusOK, stats)
	stats.RUnlock()
}

// getScopeHandler godoc
//
// @Summary      Get session scope for an asset type
// @Description  Returns the scoped assets for the given session and asset type as an array of raw OAM JSON objects.
// @Tags         scope
// @Produce      json
// @Param        session_token  path  string  true  "Session token (UUID)"
// @Param        asset_type     path  string  true  "Asset type (e.g., autonomoussystem, fqdn, ipaddress, netblock, location, organization)"
// @Success      200  {object}  ScopeResponse  "Response contains a 'data' array of raw OAM JSON"
// @Failure      400  {object}  ErrorResponse  "Invalid session token"
// @Failure      404  {object}  ErrorResponse  "Session not found or scope not found for asset type"
// @Router       /v1/sessions/{session_token}/scope/{asset_type} [get]
func (s *Server) getScopeHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	sid := vars["session_token"]
	assetType := strings.ToLower(strings.TrimSpace(vars["asset_type"]))

	// Check if the session token is valid
	token, err := uuid.Parse(sid)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid session token", err)
		return
	}
	// Check if the session exists
	// and if the session is not already terminated
	sess := s.mgr.GetSession(token)
	if sess == nil {
		writeError(w, http.StatusNotFound, "session not found", ErrNotFound)
		return
	}

	var assets []oam.Asset
	switch assetType {
	case strings.ToLower(string(oam.AutonomousSystem)):
		for _, a := range sess.Scope().AutonomousSystems() {
			assets = append(assets, a)
		}
	case strings.ToLower(string(oam.FQDN)):
		for _, a := range sess.Scope().FQDNs() {
			assets = append(assets, a)
		}
	case strings.ToLower(string(oam.IPAddress)):
		for _, a := range sess.Scope().IPAddresses() {
			assets = append(assets, a)
		}
	case strings.ToLower(string(oam.Netblock)):
		for _, a := range sess.Scope().Netblocks() {
			assets = append(assets, a)
		}
	case strings.ToLower(string(oam.Location)):
		for _, a := range sess.Scope().Locations() {
			assets = append(assets, a)
		}
	case strings.ToLower(string(oam.Organization)):
		for _, a := range sess.Scope().Organizations() {
			assets = append(assets, a)
		}
	}

	if len(assets) == 0 {
		writeError(w, http.StatusNotFound,
			"session scope not found for the selected asset type", ErrNotFound)
		return
	}

	jsonArray := make([]json.RawMessage, len(assets))
	for i, a := range assets {
		if raw, err := a.JSON(); err == nil {
			jsonArray[i] = json.RawMessage(raw)
		}
	}

	response := struct {
		Data []json.RawMessage `json:"data"`
	}{
		Data: jsonArray,
	}
	writeJSON(w, http.StatusOK, response)
}

// addAssetTypedHandler godoc
//
// @Summary      Add a single asset (typed by path)
// @Description  Submits a single OAM asset to the session. The asset type is provided in the URL path; the request body is a raw OAM JSON object without a 'type' field.
// @Tags         assets
// @Accept       json
// @Produce      json
// @Param        session_token  path  string          true  "Session token (UUID)"
// @Param        asset_type     path  string          true  "Asset type (e.g., autonomous_system, fqdn, ipaddress, netblock, location, organization)"
// @Param        asset          body  json.RawMessage true  "Raw OAM JSON object (without 'type')"
// @Success      200            {object}  AddAssetResponse
// @Failure      400            {object}  ErrorResponse  "Invalid session token, invalid JSON, or invalid asset object"
// @Failure      404            {object}  ErrorResponse  "Session not found"
// @Failure      500            {object}  ErrorResponse  "Failed to submit the asset"
// @Router       /v1/sessions/{session_token}/assets/{asset_type} [post]
func (s *Server) addAssetTypedHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	sid := vars["session_token"]
	assetType := strings.ToLower(strings.TrimSpace(vars["asset_type"]))

	// Check if the session token is valid
	token, err := uuid.Parse(sid)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid session token", err)
		return
	}
	// Check if the session exists
	// and if the session is not already terminated
	sess := s.mgr.GetSession(token)
	if sess == nil {
		writeError(w, http.StatusNotFound, "session not found", ErrNotFound)
		return
	}

	raw, err := readRawJSON(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON", err)
		return
	}
	// minimal validation: ensure it’s valid JSON object
	if !looksLikeJSONObject(raw) {
		writeError(w, http.StatusBadRequest, "invalid JSON object", nil)
		return
	}

	asset, err := parseAsset(assetType, raw)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid asset object", err)
		return
	}

	eid, err := s.PutAsset(s.ctx, sess, asset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to submit the asset", err)
		return
	}

	writeJSON(w, http.StatusOK, AddAssetResponse{
		EntityID: eid,
	})
}

// addAssetsBulkHandler godoc
//
// @Summary      Add assets in bulk (typed by path)
// @Description  Submits multiple OAM assets to the session in one request. The asset type is provided in the URL path. Each item in 'items' is a raw OAM JSON object without a 'type' field.
// @Tags         assets
// @Accept       json
// @Produce      json
// @Param        session_token  path  string               true  "Session token (UUID)"
// @Param        asset_type     path  string               true  "Asset type (e.g., autonomous_system, fqdn, ipaddress, netblock, location, organization)"
// @Param        request        body  BulkAddAssetsRequest true  "Bulk add request payload"
// @Success      200            {object}  BulkAddAssetsResponse
// @Failure      400            {object}  ErrorResponse  "Invalid session token, invalid JSON, empty items, or no valid items"
// @Failure      404            {object}  ErrorResponse  "Session not found"
// @Failure      413            {object}  ErrorResponse  "Too many items in bulk request"
// @Failure      500            {object}  BulkAddAssetsResponse  "Server failure (response includes ingested/stored/failed)"
// @Router       /v1/sessions/{session_token}/assets/{asset_type}:bulk [post]
func (s *Server) addAssetsBulkHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	sid := vars["session_token"]
	assetType := strings.ToLower(strings.TrimSpace(vars["asset_type"]))

	// Check if the session token is valid
	token, err := uuid.Parse(sid)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid session token", err)
		return
	}
	// Check if the session exists
	// and if the session is not already terminated
	sess := s.mgr.GetSession(token)
	if sess == nil {
		writeError(w, http.StatusNotFound, "session not found", ErrNotFound)
		return
	}

	var req BulkAddAssetsRequest
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON", err)
		return
	}
	if len(req.Items) == 0 {
		writeError(w, http.StatusBadRequest, "items must be non-empty", nil)
		return
	}
	if len(req.Items) > maxBulkItems {
		writeError(w, http.StatusRequestEntityTooLarge,
			"too many items in bulk request", errors.New("max items exceeded"))
		return
	}

	assets := make([]oam.Asset, 0, len(req.Items))
	for _, raw := range req.Items {
		if a, err := parseAsset(assetType, raw); err == nil {
			assets = append(assets, a)
		}
	}

	ingested := int64(len(assets))
	if ingested == 0 {
		writeError(w, http.StatusBadRequest, "no valid JSON objects in items", nil)
		return
	}

	stored, err := s.PutAssets(s.ctx, sess, assets)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, BulkAddAssetsResponse{
			Ingested: ingested,
			Stored:   0,
			Failed:   ingested,
		})
		return
	}

	failed := ingested - stored
	writeJSON(w, http.StatusOK, BulkAddAssetsResponse{
		Ingested: ingested,
		Stored:   stored,
		Failed:   failed,
	})
}
