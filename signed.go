// Copyright 2026 The go-protected-resource-metadata Authors
// SPDX-License-Identifier: Apache-2.0

package prm

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// ErrInvalidSignedMetadata reports a signed_metadata value that is not a
// well-formed JWS Compact Serialization, is missing the required iss claim, or
// nests a signed_metadata claim of its own (RFC 9728 §2.2).
var ErrInvalidSignedMetadata = errors.New("prm: invalid signed_metadata")

// SignedMetadata is the parsed — but NOT signature-verified — content of a
// signed_metadata JWT (RFC 9728 §2.2). The library decodes the JWS Compact
// Serialization and exposes its parts so the caller can verify the signature
// with a JOSE library and a key belonging to the issuer; verifying the signature
// is deliberately out of scope (the boundary the rest of the suite draws for
// JOSE).
type SignedMetadata struct {
	// Token is the original compact JWT string.
	Token string
	// Header is the decoded JWS protected header (alg, kid, typ, …).
	Header map[string]json.RawMessage
	// Issuer is the iss claim, REQUIRED by §2.2.
	Issuer string
	// Metadata is the protected resource metadata asserted by the JWT claims.
	Metadata *Metadata
	// SigningInput is the exact byte sequence the signature covers
	// (base64url(header) + "." + base64url(payload)), for the caller's verifier.
	SigningInput []byte
	// Signature is the decoded JWS signature bytes.
	Signature []byte
}

// ParseSignedMetadata parses a signed_metadata JWT (RFC 9728 §2.2) WITHOUT
// verifying its signature. It decodes the protected header, the metadata claims,
// and the iss claim, and exposes the signing input and signature for the caller
// to verify. It returns an error wrapping ErrInvalidSignedMetadata if token is
// not a three-part JWS Compact Serialization, if any part is not valid
// base64url/JSON, if the required iss claim is missing, or if the claims nest a
// signed_metadata of their own (§2.2 RECOMMENDED rejection).
//
// Verifying the signature against a trusted issuer key is the caller's
// responsibility; only after that should the signed values be trusted (see
// SignedMetadata.Apply for the §2.2 precedence merge).
func ParseSignedMetadata(token string) (*SignedMetadata, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return nil, fmt.Errorf("%w: not a JWS Compact Serialization", ErrInvalidSignedMetadata)
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("%w: header is not base64url: %v", ErrInvalidSignedMetadata, err)
	}
	var header map[string]json.RawMessage
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("%w: header is not JSON: %v", ErrInvalidSignedMetadata, err)
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("%w: payload is not base64url: %v", ErrInvalidSignedMetadata, err)
	}
	var claims Metadata
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, fmt.Errorf("%w: payload is not JSON: %v", ErrInvalidSignedMetadata, err)
	}

	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("%w: signature is not base64url: %v", ErrInvalidSignedMetadata, err)
	}

	var iss string
	switch present, err := claims.GetExtra("iss", &iss); {
	case err != nil:
		return nil, fmt.Errorf("%w: iss: %v", ErrInvalidSignedMetadata, err)
	case !present || iss == "":
		return nil, fmt.Errorf("%w: missing iss claim", ErrInvalidSignedMetadata)
	}

	if claims.SignedMetadata != "" {
		return nil, fmt.Errorf("%w: must not nest a signed_metadata claim", ErrInvalidSignedMetadata)
	}

	return &SignedMetadata{
		Token:        token,
		Header:       header,
		Issuer:       iss,
		Metadata:     &claims,
		SigningInput: []byte(parts[0] + "." + parts[1]),
		Signature:    sig,
	}, nil
}

// ParseSignedMetadata parses m.SignedMetadata (RFC 9728 §2.2) without verifying
// its signature. It returns (nil, nil) when no signed_metadata is present.
func (m *Metadata) ParseSignedMetadata() (*SignedMetadata, error) {
	if m.SignedMetadata == "" {
		return nil, nil
	}
	return ParseSignedMetadata(m.SignedMetadata)
}

// Apply returns a copy of base with the signed metadata's members overlaid, the
// signed values taking precedence on a per-member basis as RFC 9728 §2.2
// requires. base is not modified. A member the signed metadata does not carry is
// left as base has it.
//
// Call Apply only AFTER verifying the signature (SigningInput, Signature, Header)
// against a key belonging to a trusted Issuer. Applying unverified signed values
// would defeat the point of signing them.
func (sm *SignedMetadata) Apply(base *Metadata) (*Metadata, error) {
	baseObj, err := toObject(base)
	if err != nil {
		return nil, err
	}
	signedObj, err := toObject(sm.Metadata)
	if err != nil {
		return nil, err
	}
	// iss is a JWT claim that secures the bundle, not a §2 metadata member; it
	// must not leak into the merged document.
	delete(signedObj, "iss")
	for k, v := range signedObj {
		baseObj[k] = v // signed wins on every member it conveys
	}
	out, err := json.Marshal(baseObj)
	if err != nil {
		return nil, err
	}
	var merged Metadata
	if err := json.Unmarshal(out, &merged); err != nil {
		return nil, err
	}
	return &merged, nil
}

// toObject renders a Metadata as its JSON member map, so a merge operates on the
// exact wire members (omitempty-absent members do not override).
func toObject(m *Metadata) (map[string]json.RawMessage, error) {
	b, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(b, &obj); err != nil {
		return nil, err
	}
	return obj, nil
}
