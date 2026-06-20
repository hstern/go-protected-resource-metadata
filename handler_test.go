// Copyright 2026 The go-protected-resource-metadata Authors
// SPDX-License-Identifier: Apache-2.0

package prm

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func validDoc() *Metadata {
	return &Metadata{
		Resource:               "https://resource.example.com",
		AuthorizationServers:   []string{"https://as.example.com"},
		ScopesSupported:        []string{"read", "write"},
		BearerMethodsSupported: []string{BearerMethodHeader},
	}
}

func TestServeMetadata(t *testing.T) {
	rec := httptest.NewRecorder()
	if err := ServeMetadata(rec, validDoc()); err != nil {
		t.Fatalf("ServeMetadata: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q", ct)
	}
	var got Metadata
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode served body: %v", err)
	}
	if got.Resource != "https://resource.example.com" {
		t.Errorf("served Resource = %q", got.Resource)
	}

	// An invalid document is not served.
	rec2 := httptest.NewRecorder()
	if err := ServeMetadata(rec2, &Metadata{}); !errors.Is(err, ErrValidation) {
		t.Errorf("ServeMetadata(invalid) err = %v, want ErrValidation", err)
	}
}

func TestHandlerGETAndHEAD(t *testing.T) {
	h := validDoc().Handler()

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, WellKnownPathSegment, nil))
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("GET: code=%d ct=%q", rec.Code, rec.Header().Get("Content-Type"))
	}
	if rec.Body.Len() == 0 {
		t.Error("GET: empty body")
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodHead, WellKnownPathSegment, nil))
	if rec.Code != http.StatusOK {
		t.Errorf("HEAD: code = %d", rec.Code)
	}
	if rec.Body.Len() != 0 {
		t.Errorf("HEAD: body should be empty, got %d bytes", rec.Body.Len())
	}
	if rec.Header().Get("Content-Length") == "" {
		t.Error("HEAD: missing Content-Length")
	}
}

func TestHandlerMethodNotAllowed(t *testing.T) {
	rec := httptest.NewRecorder()
	validDoc().Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, WellKnownPathSegment, nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("code = %d, want 405", rec.Code)
	}
	if allow := rec.Header().Get("Allow"); allow != "GET, HEAD" {
		t.Errorf("Allow = %q, want \"GET, HEAD\"", allow)
	}
}

func TestHandlerInvalidDocument(t *testing.T) {
	rec := httptest.NewRecorder()
	(&Metadata{}).Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, WellKnownPathSegment, nil))
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("code = %d, want 500", rec.Code)
	}
}

func TestHandlerCacheAndETag(t *testing.T) {
	h := validDoc().Handler(WithMaxAge(time.Hour), WithETag("v1"))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, WellKnownPathSegment, nil))
	if cc := rec.Header().Get("Cache-Control"); cc != "max-age=3600" {
		t.Errorf("Cache-Control = %q, want max-age=3600", cc)
	}
	if et := rec.Header().Get("ETag"); et != `"v1"` {
		t.Errorf("ETag = %q, want \"v1\"", et)
	}

	// A matching If-None-Match yields 304 with no body.
	req := httptest.NewRequest(http.MethodGet, WellKnownPathSegment, nil)
	req.Header.Set("If-None-Match", `"v1"`)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotModified {
		t.Errorf("If-None-Match: code = %d, want 304", rec.Code)
	}
	if rec.Body.Len() != 0 {
		t.Error("304 should have no body")
	}
}

func TestWellKnownRequestPath(t *testing.T) {
	cases := map[string]string{
		"https://resource.example.com":            "/.well-known/oauth-protected-resource",
		"https://resource.example.com/":           "/.well-known/oauth-protected-resource",
		"https://resource.example.com/resource1":  "/.well-known/oauth-protected-resource/resource1",
		"https://resource.example.com/p?tenant=b": "/.well-known/oauth-protected-resource/p",
	}
	for resource, want := range cases {
		got, err := WellKnownRequestPath(resource)
		if err != nil {
			t.Errorf("WellKnownRequestPath(%q): %v", resource, err)
			continue
		}
		if got != want {
			t.Errorf("WellKnownRequestPath(%q) = %q, want %q", resource, got, want)
		}
	}

	if _, err := WellKnownRequestPath("http://insecure.example.com"); !errors.Is(err, ErrValidation) {
		t.Errorf("WellKnownRequestPath(non-https) err = %v, want ErrValidation", err)
	}

	// Round-trip: the mount path equals the path of the client-facing URL.
	const res = "https://resource.example.com/resource1"
	full, err := WellKnownPath(res)
	if err != nil {
		t.Fatalf("WellKnownPath: %v", err)
	}
	u, err := url.Parse(full)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	reqPath, _ := WellKnownRequestPath(res)
	if u.Path != reqPath {
		t.Errorf("mount path %q != client URL path %q", reqPath, u.Path)
	}
}

// TestPublishFetchRoundTrip exercises the server publish side and the client
// fetch side together: a resource mounts its document at the well-known path,
// and Fetch retrieves and resource-matches it.
func TestPublishFetchRoundTrip(t *testing.T) {
	// Mount paths are host-independent, so they can be registered before the
	// server's address is known. The handlers fill in the live host per request.
	rootPath, _ := WellKnownRequestPath("https://placeholder")
	nestedPath, _ := WellKnownRequestPath("https://placeholder/tenant1")

	mux := http.NewServeMux()
	mux.HandleFunc(rootPath, func(w http.ResponseWriter, r *http.Request) {
		_ = ServeMetadata(w, &Metadata{Resource: "https://" + r.Host, ScopesSupported: []string{"read"}})
	})
	mux.HandleFunc(nestedPath, func(w http.ResponseWriter, r *http.Request) {
		_ = ServeMetadata(w, &Metadata{Resource: "https://" + r.Host + "/tenant1"})
	})
	ts := httptest.NewTLSServer(mux)
	defer ts.Close()

	for _, resource := range []string{ts.URL, ts.URL + "/tenant1"} {
		got, err := Fetch(context.Background(), ts.Client(), resource)
		if err != nil {
			t.Fatalf("Fetch(%q): %v", resource, err)
		}
		if got.Resource != resource {
			t.Errorf("Resource = %q, want %q", got.Resource, resource)
		}
	}
}
