// Copyright 2026 The go-protected-resource-metadata Authors
// SPDX-License-Identifier: Apache-2.0

package prm

import (
	"net/url"
	"strings"
)

// validBearerMethods is the closed set of bearer_methods_supported values
// permitted by RFC 9728 §2 (RFC 6750 §2).
var validBearerMethods = map[string]struct{}{
	BearerMethodHeader: {},
	BearerMethodBody:   {},
	BearerMethodQuery:  {},
}

// Validate reports whether the metadata document satisfies the structural
// requirements of RFC 9728 §2. It returns the first failure as a
// *ValidationError (matchable with errors.Is(err, ErrValidation)), or nil.
//
// Validate is document-structural only and is independent of how the document
// was obtained. The §3.3/§3.4 requirement that a fetched document's resource
// equal the requested resource identifier is a fetch-time check, not part of
// Validate.
func (m *Metadata) Validate() error {
	if m.Resource == "" {
		return &ValidationError{Field: "resource", Message: "is required"}
	}
	if err := validateResourceID("resource", m.Resource); err != nil {
		return err
	}

	for _, as := range m.AuthorizationServers {
		if err := validateResourceID("authorization_servers", as); err != nil {
			return err
		}
	}

	if m.JWKSURI != "" {
		if err := validateHTTPSURL("jwks_uri", m.JWKSURI); err != nil {
			return err
		}
	}

	for _, m2 := range m.BearerMethodsSupported {
		if _, ok := validBearerMethods[m2]; !ok {
			return &ValidationError{
				Field:   "bearer_methods_supported",
				Message: "must be one of header, body, or query",
			}
		}
	}

	for field, v := range map[string]string{
		"resource_documentation": m.ResourceDocumentation,
		"resource_policy_uri":    m.ResourcePolicyURI,
		"resource_tos_uri":       m.ResourceTOSURI,
	} {
		if v == "" {
			continue
		}
		if err := validateAbsURL(field, v); err != nil {
			return err
		}
	}

	return nil
}

// validateResourceID checks an identifier that RFC 9728 requires to be an https
// URL with no fragment (the resource identifier itself and each authorization
// server issuer identifier).
func validateResourceID(field, raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return &ValidationError{Field: field, Message: "is not a valid URL"}
	}
	if u.Scheme != "https" {
		return &ValidationError{Field: field, Message: "must be an https URL"}
	}
	if u.Host == "" {
		return &ValidationError{Field: field, Message: "must be an absolute URL with a host"}
	}
	// RFC 9728 forbids a fragment component; any '#' (even an empty fragment,
	// which url.Parse records indistinguishably from none) is a violation.
	if strings.Contains(raw, "#") {
		return &ValidationError{Field: field, Message: "must not contain a fragment"}
	}
	return nil
}

// validateHTTPSURL checks an optional member that RFC 9728 specifies as an https
// URL (e.g. jwks_uri).
func validateHTTPSURL(field, raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return &ValidationError{Field: field, Message: "is not a valid URL"}
	}
	if u.Scheme != "https" {
		return &ValidationError{Field: field, Message: "must be an https URL"}
	}
	if u.Host == "" {
		return &ValidationError{Field: field, Message: "must be an absolute URL with a host"}
	}
	return nil
}

// validateAbsURL checks an optional member specified as a URL, requiring an
// absolute URL with a scheme and host (http or https).
func validateAbsURL(field, raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return &ValidationError{Field: field, Message: "is not a valid URL"}
	}
	if !u.IsAbs() || u.Host == "" {
		return &ValidationError{Field: field, Message: "must be an absolute URL"}
	}
	return nil
}
