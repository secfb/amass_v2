// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/gorilla/mux"
	"github.com/owasp-amass/amass/v5/internal/libpostal"
)

type Request struct {
	Address  string `json:"addr"`
	Language string `json:"lang"`
	Country  string `json:"country"`
}

func main() {
	host := os.Getenv("POSTAL_SERVER_HOST")
	if host == "" {
		host = "0.0.0.0"
	}
	port := os.Getenv("POSTAL_SERVER_PORT")
	if port == "" {
		port = "4001"
	}

	router := mux.NewRouter()
	router.HandleFunc("/health", HealthHandler).Methods("GET")
	router.HandleFunc("/parse", ParserHandler).Methods("POST")

	listenSpec := fmt.Sprintf("%s:%s", host, port)
	s := &http.Server{Addr: listenSpec, Handler: router}
	go func() { s.ListenAndServe() }()

	stop := make(chan os.Signal)
	// reacting to Interrupt or KILL signals to gracefully terminate the process
	signal.Notify(stop, os.Interrupt, os.Kill)

	<-stop
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	s.Shutdown(ctx)
}

func HealthHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func ParserHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	data, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read the request", http.StatusBadRequest)
		return
	}

	var req Request
	if err := json.Unmarshal(data, &req); err != nil {
		http.Error(w, "Failed to extract the request", http.StatusBadRequest)
		return
	}

	if req.Address == "" {
		http.Error(w, "An address must exist in the request", http.StatusBadRequest)
		return
	}

	var parsed []libpostal.ParsedComponent
	if req.Language != "" || req.Country != "" {
		opts := libpostal.ParserOptions{
			Language: req.Language,
			Country:  req.Country,
		}

		parsed, err = libpostal.ParseAddressOptions(req.Address, opts)
	} else {
		parsed, err = libpostal.ParseAddress(req.Address)
	}

	parsedJSON, err := json.Marshal(parsed)
	if err != nil {
		http.Error(w, "Failed to encode the response", http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(parsedJSON)
}
