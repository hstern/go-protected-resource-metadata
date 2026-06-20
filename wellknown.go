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
		Path:     wellKnownPathComponent(u),
		RawQuery: u.RawQuery,
	}
	return out.String(), nil
}

// WellKnownRequestPath returns the request path component at which a protected
// resource serves its metadata document — the server-side counterpart to
// WellKnownPath, suitable for registering a handler on an http.ServeMux. It is
// the path of the URL WellKnownPath produces (§3.1):
//
//	https://resource.example.com           -> /.well-known/oauth-protected-resource
//	https://resource.example.com/resource1 -> /.well-known/oauth-protected-resource/resource1
//
// Any query component of the resource identifier is not part of the mount path
// and is omitted. The resource identifier must be an https URL with no fragment
// (§2); otherwise WellKnownRequestPath returns a *ValidationError.
func WellKnownRequestPath(resource string) (string, error) {
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
	return wellKnownPathComponent(u), nil
}

// wellKnownPathComponent inserts the well-known segment before the resource's
// own path, removing a single terminating slash after the host first (§3.1).
func wellKnownPathComponent(u *url.URL) string {
	return WellKnownPathSegment + strings.TrimSuffix(u.Path, "/")
}
