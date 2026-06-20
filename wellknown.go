// Copyright 2026 The go-protected-resource-metadata Authors
// SPDX-License-Identifier: Apache-2.0

package prm

import (
	"net/url"
	"strings"
)

// WellKnownPath returns the URL of the protected resource metadata document for
// a resource identifier, following the construction rule of RFC 9728 §3.1.
//
// The well-known segment is inserted between the host and any path component of
// the resource identifier — it is not appended to the end:
//
//	https://resource.example.com           -> https://resource.example.com/.well-known/oauth-protected-resource
//	https://resource.example.com/resource1 -> https://resource.example.com/.well-known/oauth-protected-resource/resource1
//
// A single terminating slash after the host is removed before insertion, so a
// bare host and a host with a trailing slash yield the same URL. A query
// component, if present, is preserved after the inserted path.
//
// The resource identifier must be an https URL with no fragment (§2); otherwise
// WellKnownPath returns a *ValidationError.
func WellKnownPath(resource string) (string, error) {
	if resource == "" {
		return "", &ValidationError{Field: "resource", Message: "is required"}
	}
	if err := validateResourceID("resource", resource); err != nil {
		return "", err
	}
	u, err := url.Parse(resource)
	if err != nil { // unreachable: validateResourceID already parsed it
		return "", &ValidationError{Field: "resource", Message: "is not a valid URL"}
	}

	out := url.URL{
		Scheme:   u.Scheme,
		Host:     u.Host,
		Path:     WellKnownPathSegment + strings.TrimSuffix(u.Path, "/"),
		RawQuery: u.RawQuery,
	}
	return out.String(), nil
}
