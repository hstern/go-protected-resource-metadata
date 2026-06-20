// Copyright 2026 The go-protected-resource-metadata Authors
// SPDX-License-Identifier: Apache-2.0

package prm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hstern/go-protected-resource-metadata/internal/specfixtures"
)

func TestConformanceWellKnownCases(t *testing.T) {
	for _, tc := range specfixtures.WellKnownCases {
		t.Run(tc.Name, func(t *testing.T) {
			gotURL, err := WellKnownPath(tc.Resource)
			if err != nil {
				t.Fatalf("WellKnownPath: %v", err)
			}
			if gotURL != tc.URL {
				t.Errorf("WellKnownPath = %q, want %q", gotURL, tc.URL)
			}
			gotPath, err := WellKnownRequestPath(tc.Resource)
			if err != nil {
				t.Fatalf("WellKnownRequestPath: %v", err)
			}
			if gotPath != tc.RequestPath {
				t.Errorf("WellKnownRequestPath = %q, want %q", gotPath, tc.RequestPath)
			}
		})
	}
}

func TestConformanceValidDocument(t *testing.T) {
	var m Metadata
	if err := json.Unmarshal([]byte(specfixtures.ValidDocument), &m); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}
	if err := m.Validate(); err != nil {
		t.Fatalf("the valid fixture failed Validate: %v", err)
	}
	// byte-stable round trip
	first, _ := json.Marshal(m)
	var m2 Metadata
	if err := json.Unmarshal(first, &m2); err != nil {
		t.Fatalf("re-unmarshal: %v", err)
	}
	second, _ := json.Marshal(m2)
	if !bytes.Equal(first, second) {
		t.Errorf("valid fixture not byte-stable:\n %s\n %s", first, second)
	}
}

func TestConformanceInvalidDocuments(t *testing.T) {
	for _, inv := range specfixtures.InvalidDocuments {
		t.Run(inv.Name, func(t *testing.T) {
			var m Metadata
			if err := json.Unmarshal([]byte(inv.JSON), &m); err != nil {
				t.Fatalf("fixture is not valid JSON: %v", err)
			}
			if err := m.Validate(); !errors.Is(err, ErrValidation) {
				t.Errorf("Validate() = %v, want ErrValidation (%s)", err, inv.Why)
			}
		})
	}
}

// TestConformanceBothRoles drives the server publish side and the client fetch
// side through the §2 example document: the resource serves it (resource patched
// to the live host) and the client fetches, resource-matches, and decodes it.
func TestConformanceBothRoles(t *testing.T) {
	var base Metadata
	if err := json.Unmarshal([]byte(specfixtures.ValidDocument), &base); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc(WellKnownPathSegment, func(w http.ResponseWriter, r *http.Request) {
		doc := base
		doc.Resource = "https://" + r.Host
		_ = ServeMetadata(w, &doc)
	})
	ts := httptest.NewTLSServer(mux)
	defer ts.Close()

	got, err := Fetch(context.Background(), ts.Client(), ts.URL)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if got.Resource != ts.URL {
		t.Errorf("Resource = %q, want %q", got.Resource, ts.URL)
	}
	// Fixture content survives the publish/fetch round trip.
	if len(got.ScopesSupported) != 2 || len(got.AuthorizationServers) != 2 {
		t.Errorf("fixture content not preserved: scopes=%v as=%v", got.ScopesSupported, got.AuthorizationServers)
	}
	if got.JWKSURI != "https://resource.example.com/jwks" {
		t.Errorf("JWKSURI = %q", got.JWKSURI)
	}
	// The open-Extra passthrough survives both roles (§2 extension members, §2.1).
	var feature string
	if present, err := got.GetExtra("x_example_org_feature", &feature); err != nil || !present || feature != "enabled" {
		t.Errorf("extension member not preserved: present=%v feature=%q err=%v", present, feature, err)
	}
	if v, ok := got.Localized("resource_name", "fr"); !ok || v != "Ressource protégée" {
		t.Errorf("i18n variant not preserved: Localized(resource_name, fr) = %q, %v", v, ok)
	}
}

func TestConformanceResourceMismatch(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, specfixtures.MismatchDocument)
	}))
	defer ts.Close()

	if _, err := Fetch(context.Background(), ts.Client(), ts.URL); !errors.Is(err, ErrResourceMismatch) {
		t.Errorf("Fetch = %v, want ErrResourceMismatch", err)
	}
}

func TestConformanceChallengeHeader(t *testing.T) {
	name, value := ChallengeParam(specfixtures.ChallengeMetadataURL)
	// The caller's challenge serializer wraps the value in a quoted-string; this
	// mirrors that to confirm the pair renders to the §5.1 example header.
	header := "Bearer " + name + `="` + value + `"`
	if header != specfixtures.ChallengeHeader {
		t.Errorf("rendered header = %q, want %q", header, specfixtures.ChallengeHeader)
	}
}

func TestConformanceNestedSignedMetadataRejected(t *testing.T) {
	token := makeJWT(
		map[string]any{"alg": "none"},
		map[string]any{
			"resource":        "https://resource.example.com",
			"iss":             "https://issuer.example.com",
			"signed_metadata": "nested.jwt.here",
		},
		"sig",
	)
	if _, err := ParseSignedMetadata(token); !errors.Is(err, ErrInvalidSignedMetadata) {
		t.Errorf("ParseSignedMetadata(nested) = %v, want ErrInvalidSignedMetadata", err)
	}
}
