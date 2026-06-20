// Copyright 2026 The go-protected-resource-metadata Authors
// SPDX-License-Identifier: Apache-2.0

package prm

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"
)

// a representative RFC 9728 §2 metadata document with an extension member and an
// internationalized resource_name variant.
const exampleDoc = `{
  "resource": "https://resource.example.com",
  "authorization_servers": ["https://as1.example.com", "https://as2.example.com"],
  "jwks_uri": "https://resource.example.com/jwks",
  "scopes_supported": ["read", "write"],
  "bearer_methods_supported": ["header", "body"],
  "resource_name": "Example Resource",
  "resource_name#fr": "Ressource Protégée",
  "dpop_bound_access_tokens_required": true,
  "x_vendor_flag": "on"
}`

func TestUnmarshalRoutesTypedAndExtra(t *testing.T) {
	var m Metadata
	if err := json.Unmarshal([]byte(exampleDoc), &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if m.Resource != "https://resource.example.com" {
		t.Errorf("Resource = %q", m.Resource)
	}
	if got := m.AuthorizationServers; !reflect.DeepEqual(got, []string{"https://as1.example.com", "https://as2.example.com"}) {
		t.Errorf("AuthorizationServers = %v", got)
	}
	if !reflect.DeepEqual(m.BearerMethodsSupported, []string{BearerMethodHeader, BearerMethodBody}) {
		t.Errorf("BearerMethodsSupported = %v", m.BearerMethodsSupported)
	}
	if !m.DPoPBoundAccessTokensRequired {
		t.Error("DPoPBoundAccessTokensRequired = false, want true")
	}
	// The unknown member and the i18n variant must land in Extra, not be dropped.
	if _, ok := m.Extra["x_vendor_flag"]; !ok {
		t.Error("x_vendor_flag missing from Extra")
	}
	if _, ok := m.Extra["resource_name#fr"]; !ok {
		t.Error("resource_name#fr missing from Extra")
	}
	// A typed member must NOT leak into Extra.
	if _, ok := m.Extra["resource"]; ok {
		t.Error("typed member resource leaked into Extra")
	}
}

func TestRoundTripByteStable(t *testing.T) {
	var m Metadata
	if err := json.Unmarshal([]byte(exampleDoc), &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	first, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var m2 Metadata
	if err := json.Unmarshal(first, &m2); err != nil {
		t.Fatalf("re-unmarshal: %v", err)
	}
	second, err := json.Marshal(m2)
	if err != nil {
		t.Fatalf("re-marshal: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Errorf("not byte-stable:\n first  = %s\n second = %s", first, second)
	}
	if !reflect.DeepEqual(m, m2) {
		t.Errorf("round-trip changed the value:\n in  = %#v\n out = %#v", m, m2)
	}
}

func TestMarshalNoExtraKeepsResource(t *testing.T) {
	// resource has no omitempty: a minimal document still carries it, and the
	// no-extension path serializes in declared field order (resource first).
	m := Metadata{Resource: "https://r.example.com"}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if want := `{"resource":"https://r.example.com"}`; string(b) != want {
		t.Errorf("marshal = %s, want %s", b, want)
	}
}

func TestBoolOmitEmpty(t *testing.T) {
	b, err := json.Marshal(Metadata{Resource: "https://r.example.com"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if bytes.Contains(b, []byte("dpop_bound_access_tokens_required")) ||
		bytes.Contains(b, []byte("tls_client_certificate_bound_access_tokens")) {
		t.Errorf("false booleans should be omitted: %s", b)
	}
}

func TestGetSetExtra(t *testing.T) {
	m := &Metadata{Resource: "https://r.example.com"}

	if err := m.SetExtra("x_vendor", []string{"a", "b"}); err != nil {
		t.Fatalf("SetExtra: %v", err)
	}
	var got []string
	present, err := m.GetExtra("x_vendor", &got)
	if err != nil || !present {
		t.Fatalf("GetExtra present=%v err=%v", present, err)
	}
	if !reflect.DeepEqual(got, []string{"a", "b"}) {
		t.Errorf("GetExtra = %v", got)
	}

	// Missing member: present=false, no error.
	present, err = m.GetExtra("nope", &got)
	if present || err != nil {
		t.Errorf("GetExtra(missing) present=%v err=%v", present, err)
	}

	// A typed member cannot be set through Extra.
	if err := m.SetExtra("resource", "x"); err == nil {
		t.Error("SetExtra(resource) should error: it has a typed field")
	}
}

func TestLocalized(t *testing.T) {
	var m Metadata
	if err := json.Unmarshal([]byte(exampleDoc), &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	// Tagged variant, with case-insensitive tag matching.
	if v, ok := m.Localized("resource_name", "FR"); !ok || v != "Ressource Protégée" {
		t.Errorf("Localized(resource_name, FR) = %q, %v", v, ok)
	}
	// Untagged fallback when the requested tag has no variant.
	if v, ok := m.Localized("resource_name", "de"); !ok || v != "Example Resource" {
		t.Errorf("Localized(resource_name, de) = %q, %v", v, ok)
	}
	// Empty tag requests the untagged value.
	if v, ok := m.Localized("resource_name", ""); !ok || v != "Example Resource" {
		t.Errorf("Localized(resource_name, \"\") = %q, %v", v, ok)
	}
	// A member with no value at all reports ok=false.
	if v, ok := m.Localized("resource_tos_uri", "en"); ok || v != "" {
		t.Errorf("Localized(resource_tos_uri, en) = %q, %v; want \"\", false", v, ok)
	}
}
