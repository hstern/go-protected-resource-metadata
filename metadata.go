// Copyright 2026 The go-protected-resource-metadata Authors
// SPDX-License-Identifier: Apache-2.0

package prm

import (
	"encoding/json"
	"fmt"
	"strings"
)

// WellKnownPathSegment is the well-known URI path under which a protected
// resource serves its metadata document (RFC 9728 §3.1). For a resource
// identifier with a path component, the resource's own path is appended after
// this segment; see [WellKnownPath] for the full construction rule.
const WellKnownPathSegment = "/.well-known/oauth-protected-resource"

// Bearer token transmission methods for BearerMethodsSupported (RFC 9728 §2,
// RFC 6750 §2): in the Authorization header, the form-encoded body, or the URI
// query.
const (
	BearerMethodHeader = "header"
	BearerMethodBody   = "body"
	BearerMethodQuery  = "query"
)

// Metadata is an RFC 9728 §2 OAuth 2.0 Protected Resource Metadata document.
//
// Resource is the only REQUIRED member; every other field is optional and is
// omitted from the wire when unset. Service-specific and future-registered
// members — including the internationalized "name#lang" variants of §2.1 — are
// preserved verbatim in Extra for byte-stable round-trips.
//
// Decoding is liberal (Postel's law): UnmarshalJSON accepts whatever the wire
// provides. Strict checks are opt-in via Validate. The resource-match check of
// §3.3/§3.4 is a fetch-time concern, not part of Validate.
type Metadata struct {
	// Resource is the protected resource's resource identifier (§2). REQUIRED.
	// It is an https URL with no fragment.
	Resource string `json:"resource"`

	// AuthorizationServers lists the issuer identifiers of authorization
	// servers that can be used with this protected resource (§2).
	AuthorizationServers []string `json:"authorization_servers,omitempty"`

	// JWKSURI is the URL of the protected resource's JWK Set document (§2).
	JWKSURI string `json:"jwks_uri,omitempty"`

	// ScopesSupported lists the scope values used in authorization requests to
	// access this protected resource (§2). RECOMMENDED.
	ScopesSupported []string `json:"scopes_supported,omitempty"`

	// BearerMethodsSupported lists the supported methods of sending an OAuth 2.0
	// bearer token to the resource (§2): some subset of BearerMethodHeader,
	// BearerMethodBody, and BearerMethodQuery.
	BearerMethodsSupported []string `json:"bearer_methods_supported,omitempty"`

	// ResourceSigningAlgValuesSupported lists the JWS "alg" values supported by
	// the resource for signing resource responses (§2).
	ResourceSigningAlgValuesSupported []string `json:"resource_signing_alg_values_supported,omitempty"`

	// ResourceName is a human-readable name of the protected resource intended
	// for display to the end user (§2). RECOMMENDED. Internationalized variants
	// are carried in Extra as "resource_name#<lang>"; read them with Localized.
	ResourceName string `json:"resource_name,omitempty"`

	// ResourceDocumentation is a URL of human-readable developer documentation
	// for the protected resource (§2). Internationalizable; see Localized.
	ResourceDocumentation string `json:"resource_documentation,omitempty"`

	// ResourcePolicyURI is a URL of human-readable information about the
	// resource's requirements on the client (§2). Internationalizable.
	ResourcePolicyURI string `json:"resource_policy_uri,omitempty"`

	// ResourceTOSURI is a URL of the resource's terms of service (§2).
	// Internationalizable.
	ResourceTOSURI string `json:"resource_tos_uri,omitempty"`

	// TLSClientCertificateBoundAccessTokens indicates support for mutual-TLS
	// client-certificate-bound access tokens (§2, RFC 8705). Absent means false.
	TLSClientCertificateBoundAccessTokens bool `json:"tls_client_certificate_bound_access_tokens,omitempty"`

	// AuthorizationDetailsTypesSupported lists the authorization_details type
	// values supported by the resource server (§2, RFC 9396).
	AuthorizationDetailsTypesSupported []string `json:"authorization_details_types_supported,omitempty"`

	// DPoPSigningAlgValuesSupported lists the JWS "alg" values supported by the
	// resource server for validating DPoP proof JWTs (§2, RFC 9449).
	DPoPSigningAlgValuesSupported []string `json:"dpop_signing_alg_values_supported,omitempty"`

	// DPoPBoundAccessTokensRequired indicates that the resource server always
	// requires DPoP-bound access tokens (§2, RFC 9449). Absent means false.
	DPoPBoundAccessTokensRequired bool `json:"dpop_bound_access_tokens_required,omitempty"`

	// SignedMetadata is a JWT (JWS Compact Serialization) whose claims restate
	// metadata parameters about the protected resource (§2.2). This library
	// surfaces it verbatim; verifying its signature is the caller's job.
	SignedMetadata string `json:"signed_metadata,omitempty"`

	// Extra holds members not captured by the typed fields above —
	// service-specific extensions, future registrations, and the §2.1
	// "name#lang" internationalized variants. Values are kept as raw JSON for
	// byte-stable round-trips and zero-cost pass-through.
	Extra map[string]json.RawMessage `json:"-"`
}

// knownMembers are the JSON keys mapped to typed Metadata fields. Anything else
// decoded from a metadata object lands in Extra.
var knownMembers = map[string]struct{}{
	"resource":                                   {},
	"authorization_servers":                      {},
	"jwks_uri":                                   {},
	"scopes_supported":                           {},
	"bearer_methods_supported":                   {},
	"resource_signing_alg_values_supported":      {},
	"resource_name":                              {},
	"resource_documentation":                     {},
	"resource_policy_uri":                        {},
	"resource_tos_uri":                           {},
	"tls_client_certificate_bound_access_tokens": {},
	"authorization_details_types_supported":      {},
	"dpop_signing_alg_values_supported":          {},
	"dpop_bound_access_tokens_required":          {},
	"signed_metadata":                            {},
}

// UnmarshalJSON decodes the typed members and routes every other member of the
// JSON object into Extra.
func (m *Metadata) UnmarshalJSON(data []byte) error {
	type alias Metadata
	var a alias
	if err := json.Unmarshal(data, &a); err != nil {
		return err
	}
	*m = Metadata(a)

	var all map[string]json.RawMessage
	if err := json.Unmarshal(data, &all); err != nil {
		return err
	}
	for k := range knownMembers {
		delete(all, k)
	}
	if len(all) > 0 {
		m.Extra = all
	}
	return nil
}

// MarshalJSON serializes the typed members and merges Extra back in. Typed
// members win on key collision. Output is byte-stable: with no extension members
// the typed members serialize in their declared order; with extensions the whole
// object serializes in encoding/json's sorted-key order. Either way a given
// Metadata value always marshals to the same bytes.
func (m Metadata) MarshalJSON() ([]byte, error) {
	type alias Metadata
	known, err := json.Marshal(alias(m))
	if err != nil {
		return nil, err
	}
	if len(m.Extra) == 0 {
		return known, nil
	}

	merged := make(map[string]json.RawMessage, len(m.Extra)+len(knownMembers))
	if err := json.Unmarshal(known, &merged); err != nil {
		return nil, err
	}
	for k, v := range m.Extra {
		if _, taken := merged[k]; taken {
			continue
		}
		merged[k] = v
	}
	return json.Marshal(merged)
}

// GetExtra unmarshals the extension member named name into v, which must be a
// non-nil pointer. It reports whether the member was present; a missing member
// is not an error (present == false, err == nil).
//
// Only members not captured by a typed field land in Extra, so GetExtra is the
// way to read extension members — including the §2.1 "name#lang" variants —
// byte-for-byte as the server sent them.
func (m *Metadata) GetExtra(name string, v any) (present bool, err error) {
	raw, ok := m.Extra[name]
	if !ok {
		return false, nil
	}
	if err := json.Unmarshal(raw, v); err != nil {
		return true, fmt.Errorf("prm: extension %q: %w", name, err)
	}
	return true, nil
}

// SetExtra marshals v and stores it as the extension member named name. It
// returns an error if name collides with a member that has its own typed field
// — set those through the field instead — or if v cannot be marshalled.
func (m *Metadata) SetExtra(name string, v any) error {
	if _, typed := knownMembers[name]; typed {
		return fmt.Errorf("prm: %q has a typed field; set it directly", name)
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("prm: extension %q: %w", name, err)
	}
	if m.Extra == nil {
		m.Extra = make(map[string]json.RawMessage, 1)
	}
	m.Extra[name] = raw
	return nil
}

// Localized returns the value of a human-readable member for a requested BCP 47
// language tag (RFC 9728 §2.1). member is the member's JSON name, e.g.
// "resource_name". Localized looks for a tagged variant "member#tag" among the
// extension members, matching the language tag case-insensitively, and falls
// back to the untagged member value. ok reports whether any value — tagged or
// untagged — was found.
//
// An empty tag requests the untagged value directly.
func (m *Metadata) Localized(member, tag string) (value string, ok bool) {
	if tag != "" {
		for k, raw := range m.Extra {
			base, lang, tagged := strings.Cut(k, "#")
			if !tagged || base != member || !strings.EqualFold(lang, tag) {
				continue
			}
			var s string
			if err := json.Unmarshal(raw, &s); err == nil {
				return s, true
			}
		}
	}
	if v := m.untaggedMember(member); v != "" {
		return v, true
	}
	return "", false
}

// untaggedMember returns the untagged value of a human-readable member: the
// typed field for the four §2.1 members, or the raw Extra value otherwise.
func (m *Metadata) untaggedMember(member string) string {
	switch member {
	case "resource_name":
		return m.ResourceName
	case "resource_documentation":
		return m.ResourceDocumentation
	case "resource_policy_uri":
		return m.ResourcePolicyURI
	case "resource_tos_uri":
		return m.ResourceTOSURI
	}
	if raw, ok := m.Extra[member]; ok {
		var s string
		if err := json.Unmarshal(raw, &s); err == nil {
			return s
		}
	}
	return ""
}
