// Copyright 2026 The go-protected-resource-metadata Authors
// SPDX-License-Identifier: Apache-2.0

package prm

import (
	"errors"
	"testing"
)

func TestWellKnownPath(t *testing.T) {
	cases := []struct {
		name     string
		resource string
		want     string
	}{
		{
			"no path",
			"https://resource.example.com",
			"https://resource.example.com/.well-known/oauth-protected-resource",
		},
		{
			"trailing slash stripped",
			"https://resource.example.com/",
			"https://resource.example.com/.well-known/oauth-protected-resource",
		},
		{
			"with path — suffix inserted before the path",
			"https://resource.example.com/resource1",
			"https://resource.example.com/.well-known/oauth-protected-resource/resource1",
		},
		{
			"nested path",
			"https://resource.example.com/api/v2",
			"https://resource.example.com/.well-known/oauth-protected-resource/api/v2",
		},
		{
			"with port",
			"https://resource.example.com:8443/resource1",
			"https://resource.example.com:8443/.well-known/oauth-protected-resource/resource1",
		},
		{
			"with query preserved after inserted path",
			"https://resource.example.com/path?tenant=blue",
			"https://resource.example.com/.well-known/oauth-protected-resource/path?tenant=blue",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := WellKnownPath(tc.resource)
			if err != nil {
				t.Fatalf("WellKnownPath(%q) error: %v", tc.resource, err)
			}
			if got != tc.want {
				t.Errorf("WellKnownPath(%q)\n got  %q\n want %q", tc.resource, got, tc.want)
			}
		})
	}
}

func TestWellKnownPathErrors(t *testing.T) {
	cases := []struct {
		name     string
		resource string
	}{
		{"empty", ""},
		{"not https", "http://resource.example.com"},
		{"with fragment", "https://resource.example.com/r#section"},
		{"no host", "https:///resource1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := WellKnownPath(tc.resource); err == nil {
				t.Fatalf("WellKnownPath(%q) = nil error, want error", tc.resource)
			} else if !errors.Is(err, ErrValidation) {
				t.Errorf("error %v does not match ErrValidation", err)
			}
		})
	}
}
