// Copyright 2026 The go-protected-resource-metadata Authors
// SPDX-License-Identifier: Apache-2.0

package prm

import (
	"errors"
	"testing"
)

func TestValidateValid(t *testing.T) {
	m := &Metadata{
		Resource:               "https://resource.example.com/tenant1",
		AuthorizationServers:   []string{"https://as.example.com"},
		JWKSURI:                "https://resource.example.com/jwks",
		ScopesSupported:        []string{"read", "write"},
		BearerMethodsSupported: []string{BearerMethodHeader, BearerMethodBody, BearerMethodQuery},
		ResourceName:           "Example",
		ResourceDocumentation:  "https://docs.example.com",
		ResourcePolicyURI:      "https://policy.example.com",
		ResourceTOSURI:         "https://tos.example.com",
	}
	if err := m.Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil", err)
	}
}

func TestValidateFailures(t *testing.T) {
	cases := []struct {
		name  string
		m     Metadata
		field string
	}{
		{"missing resource", Metadata{}, "resource"},
		{"resource not https", Metadata{Resource: "http://r.example.com"}, "resource"},
		{"resource with fragment", Metadata{Resource: "https://r.example.com#x"}, "resource"},
		{"resource no host", Metadata{Resource: "https:///path"}, "resource"},
		{
			"bad bearer method",
			Metadata{Resource: "https://r.example.com", BearerMethodsSupported: []string{"smtp"}},
			"bearer_methods_supported",
		},
		{
			"jwks_uri not https",
			Metadata{Resource: "https://r.example.com", JWKSURI: "http://r.example.com/jwks"},
			"jwks_uri",
		},
		{
			"authorization_servers not https",
			Metadata{Resource: "https://r.example.com", AuthorizationServers: []string{"http://as.example.com"}},
			"authorization_servers",
		},
		{
			"resource_tos_uri not absolute",
			Metadata{Resource: "https://r.example.com", ResourceTOSURI: "/relative"},
			"resource_tos_uri",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.m.Validate()
			if err == nil {
				t.Fatalf("Validate() = nil, want error")
			}
			if !errors.Is(err, ErrValidation) {
				t.Errorf("errors.Is(err, ErrValidation) = false")
			}
			var ve *ValidationError
			if !errors.As(err, &ve) {
				t.Fatalf("errors.As(*ValidationError) = false (%v)", err)
			}
			if ve.Field != tc.field {
				t.Errorf("Field = %q, want %q", ve.Field, tc.field)
			}
		})
	}
}
