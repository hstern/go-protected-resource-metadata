// Copyright 2026 The go-protected-resource-metadata Authors
// SPDX-License-Identifier: Apache-2.0

package prm

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
)

func b64(v any) string {
	b, _ := json.Marshal(v)
	return base64.RawURLEncoding.EncodeToString(b)
}

// makeJWT builds a JWS Compact Serialization from header/payload objects and a
// raw (already-decoded) signature. The signature is not a real cryptographic
// signature — these tests exercise parsing, not verification.
func makeJWT(header, payload map[string]any, sig string) string {
	return b64(header) + "." + b64(payload) + "." + base64.RawURLEncoding.EncodeToString([]byte(sig))
}

func TestParseSignedMetadata(t *testing.T) {
	header := map[string]any{"alg": "RS256", "typ": "JWT"}
	payload := map[string]any{
		"resource":         "https://resource.example.com",
		"iss":              "https://issuer.example.com",
		"scopes_supported": []string{"read"},
	}
	token := makeJWT(header, payload, "signature-bytes")

	sm, err := ParseSignedMetadata(token)
	if err != nil {
		t.Fatalf("ParseSignedMetadata: %v", err)
	}
	if sm.Issuer != "https://issuer.example.com" {
		t.Errorf("Issuer = %q", sm.Issuer)
	}
	if sm.Metadata.Resource != "https://resource.example.com" {
		t.Errorf("Metadata.Resource = %q", sm.Metadata.Resource)
	}
	var alg string
	if err := json.Unmarshal(sm.Header["alg"], &alg); err != nil || alg != "RS256" {
		t.Errorf("Header alg = %q (%v)", alg, err)
	}
	// SigningInput is exactly header.payload (no signature segment).
	wantInput := b64(header) + "." + b64(payload)
	if string(sm.SigningInput) != wantInput {
		t.Errorf("SigningInput = %q, want %q", sm.SigningInput, wantInput)
	}
	if string(sm.Signature) != "signature-bytes" {
		t.Errorf("Signature = %q", sm.Signature)
	}
}

func TestParseSignedMetadataErrors(t *testing.T) {
	good := map[string]any{"resource": "https://r.example.com", "iss": "https://i.example.com"}

	cases := map[string]string{
		"not three parts":        "header.payload",
		"empty segment":          b64(map[string]any{"alg": "none"}) + ".." + "sig",
		"header not base64url":   "@@@." + b64(good) + "." + base64.RawURLEncoding.EncodeToString([]byte("s")),
		"missing iss":            makeJWT(map[string]any{"alg": "none"}, map[string]any{"resource": "https://r.example.com"}, "s"),
		"nested signed_metadata": makeJWT(map[string]any{"alg": "none"}, map[string]any{"resource": "https://r.example.com", "iss": "https://i.example.com", "signed_metadata": "x.y.z"}, "s"),
	}
	for name, token := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseSignedMetadata(token); !errors.Is(err, ErrInvalidSignedMetadata) {
				t.Errorf("err = %v, want ErrInvalidSignedMetadata", err)
			}
		})
	}
}

func TestMetadataParseSignedMetadata(t *testing.T) {
	// No signed_metadata present: (nil, nil).
	sm, err := (&Metadata{Resource: "https://r.example.com"}).ParseSignedMetadata()
	if sm != nil || err != nil {
		t.Errorf("empty: got (%v, %v), want (nil, nil)", sm, err)
	}

	// Present: delegates to ParseSignedMetadata.
	token := makeJWT(
		map[string]any{"alg": "none"},
		map[string]any{"resource": "https://r.example.com", "iss": "https://i.example.com"},
		"s",
	)
	m := &Metadata{Resource: "https://r.example.com", SignedMetadata: token}
	sm, err = m.ParseSignedMetadata()
	if err != nil || sm == nil || sm.Issuer != "https://i.example.com" {
		t.Errorf("present: sm=%v err=%v", sm, err)
	}
}

func TestSignedMetadataApply(t *testing.T) {
	base := &Metadata{
		Resource:     "https://r.example.com",
		ResourceName: "old name",
		JWKSURI:      "https://r.example.com/jwks",
	}
	signed := &SignedMetadata{
		Metadata: &Metadata{
			Resource:        "https://r.example.com",
			ResourceName:    "signed name",
			ScopesSupported: []string{"read"},
		},
	}

	merged, err := signed.Apply(base)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	// Signed wins on a member present in both.
	if merged.ResourceName != "signed name" {
		t.Errorf("ResourceName = %q, want signed name", merged.ResourceName)
	}
	// A member only in base is kept.
	if merged.JWKSURI != "https://r.example.com/jwks" {
		t.Errorf("JWKSURI = %q, want kept from base", merged.JWKSURI)
	}
	// A member only in signed is added.
	if len(merged.ScopesSupported) != 1 || merged.ScopesSupported[0] != "read" {
		t.Errorf("ScopesSupported = %v", merged.ScopesSupported)
	}
	// base is not modified.
	if base.ResourceName != "old name" {
		t.Errorf("base mutated: ResourceName = %q", base.ResourceName)
	}
}
