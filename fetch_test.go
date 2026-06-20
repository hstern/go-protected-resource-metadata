// Copyright 2026 The go-protected-resource-metadata Authors
// SPDX-License-Identifier: Apache-2.0

package prm

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFetch(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != WellKnownPathSegment {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		// resource echoes the host the client used, so it matches the request.
		_, _ = fmt.Fprintf(w, `{"resource":"https://%s","scopes_supported":["read","write"]}`, r.Host)
	}))
	defer ts.Close()

	m, err := Fetch(context.Background(), ts.Client(), ts.URL)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if m.Resource != ts.URL {
		t.Errorf("Resource = %q, want %q", m.Resource, ts.URL)
	}
	if len(m.ScopesSupported) != 2 {
		t.Errorf("ScopesSupported = %v", m.ScopesSupported)
	}
}

func TestFetchResourceMismatch(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"resource":"https://attacker.example.com"}`)
	}))
	defer ts.Close()

	_, err := Fetch(context.Background(), ts.Client(), ts.URL)
	if !errors.Is(err, ErrResourceMismatch) {
		t.Fatalf("Fetch error = %v, want ErrResourceMismatch", err)
	}
}

func TestFetchNon200(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer ts.Close()

	_, err := Fetch(context.Background(), ts.Client(), ts.URL)
	if !errors.Is(err, ErrUnexpectedStatus) {
		t.Fatalf("Fetch error = %v, want ErrUnexpectedStatus", err)
	}
	var he *HTTPError
	if !errors.As(err, &he) || he.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("want *HTTPError{503}, got %v", err)
	}
}

func TestFetchInvalidBody(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{not valid json`)
	}))
	defer ts.Close()

	_, err := Fetch(context.Background(), ts.Client(), ts.URL)
	if !errors.Is(err, ErrInvalidResponse) {
		t.Fatalf("Fetch error = %v, want ErrInvalidResponse", err)
	}
}

func TestFetchMetadataURL(t *testing.T) {
	const rs = "https://rs.example.com"
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprintf(w, `{"resource":%q}`, rs)
	}))
	defer ts.Close()

	// The challenge-redirect case: the document is fetched from an out-of-band
	// metadata URL and must match the resource the client actually called.
	m, err := FetchMetadataURL(context.Background(), ts.Client(), ts.URL+"/md", rs)
	if err != nil {
		t.Fatalf("FetchMetadataURL: %v", err)
	}
	if m.Resource != rs {
		t.Errorf("Resource = %q, want %q", m.Resource, rs)
	}

	// A document whose resource is not the expected one is rejected.
	_, err = FetchMetadataURL(context.Background(), ts.Client(), ts.URL+"/md", "https://other.example.com")
	if !errors.Is(err, ErrResourceMismatch) {
		t.Errorf("FetchMetadataURL mismatch error = %v, want ErrResourceMismatch", err)
	}

	// An empty expected resource is a usage error, not a free pass (§3.4 guard).
	if _, err := FetchMetadataURL(context.Background(), ts.Client(), ts.URL+"/md", ""); !errors.Is(err, ErrValidation) {
		t.Errorf("FetchMetadataURL(empty expected) error = %v, want ErrValidation", err)
	}
}
