//go:build !cgo

// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package libpostal

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"time"

	"github.com/owasp-amass/amass/v5/internal/net/http"
)

type parsed struct {
	Parts []ParsedComponent `json:"parts"`
}

type parseRequest struct {
	Address  string `json:"addr"`
	Language string `json:"lang"`
	Country  string `json:"country"`
}

var postalHost, postalPort string

func init() {
	postalHost = os.Getenv("POSTAL_SERVER_HOST")
	postalPort = os.Getenv("POSTAL_SERVER_PORT")
}

func ParseAddress(address string) ([]ParsedComponent, error) {
	if postalHost == "" || postalPort == "" {
		return nil, errors.New(ErrPostalLibNotAvailable)
	}

	reqJSON, err := json.Marshal(parseRequest{Address: address})
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	resp, err := http.RequestWebPage(ctx, &http.Request{
		Method: "POST",
		URL:    "http://" + postalHost + ":" + postalPort + "/parse",
		Body:   string(reqJSON),
	})
	if err != nil {
		return nil, err
	}

	var p parsed
	if err := json.Unmarshal([]byte("{\"parts\":"+resp.Body+"}"), &p); err != nil {
		return nil, err
	}
	return p.Parts, nil
}
