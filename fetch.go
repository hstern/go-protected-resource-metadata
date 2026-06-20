// Copyright 2026 The go-protected-resource-metadata Authors
// SPDX-License-Identifier: Apache-2.0

package prm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

// maxMetadataBytes caps how much of a metadata response body is read, a
// defensive bound against an oversized or hostile document.
const maxMetadataBytes = 1 << 20 // 1 MiB

// Sentinel errors returned by Fetch and FetchMetadataURL. Match them with
// errors.Is; use errors.As with *HTTPError to read the status code.
var (
	// ErrResourceMismatch reports that the fetched document's resource value is
	// not identical to the requested resource identifier (RFC 9728 §3.3/§3.4).
	// The document MUST NOT be used; Fetch returns this and discards it.
	ErrResourceMismatch = errors.New("prm: fetched resource does not match requested resource identifier")
	// ErrUnexpectedStatus reports a non-200 HTTP status. The concrete error is an
	// *HTTPError carrying the status code.
	ErrUnexpectedStatus = errors.New("prm: unexpected HTTP status")
	// ErrInvalidResponse reports a 200 response whose body did not decode as a
	// metadata document.
	ErrInvalidResponse = errors.New("prm: invalid metadata response")
)

// HTTPError is returned when the metadata endpoint responds with a non-200
// status. It unwraps to ErrUnexpectedStatus.
type HTTPError struct {
	StatusCode int
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("prm: unexpected HTTP status %d", e.StatusCode)
}

func (e *HTTPError) Unwrap() error { return ErrUnexpectedStatus }

// Fetch retrieves and validates the protected resource metadata for a resource
// identifier. It builds the well-known URL with WellKnownPath (§3.1), performs a
// GET over c (defaulting to http.DefaultClient), decodes the JSON body, and
// enforces the §3.3/§3.4 anti-mix-up check: the returned resource value MUST be
// identical to resource. On mismatch it returns ErrResourceMismatch and does not
// return the document.
//
// The comparison is code-point exact (§6); pass resource in the same canonical
// form the protected resource publishes. Transport security (TLS per BCP 195) is
// the responsibility of c.
func Fetch(ctx context.Context, c *http.Client, resource string) (*Metadata, error) {
	metadataURL, err := WellKnownPath(resource)
	if err != nil {
		return nil, err
	}
	return fetchAndMatch(ctx, c, metadataURL, resource)
}

// FetchMetadataURL retrieves and validates a metadata document from a metadata
// URL obtained out of band — typically the resource_metadata parameter of a
// WWW-Authenticate challenge (RFC 9728 §5.1). Per §3.3, when the URL came from
// such a challenge the returned resource value MUST equal the URL the client
// used to call the resource server; pass that as expectedResource. On mismatch
// it returns ErrResourceMismatch.
//
// The comparison is code-point exact (§6).
func FetchMetadataURL(ctx context.Context, c *http.Client, metadataURL, expectedResource string) (*Metadata, error) {
	return fetchAndMatch(ctx, c, metadataURL, expectedResource)
}

func fetchAndMatch(ctx context.Context, c *http.Client, metadataURL, expectedResource string) (*Metadata, error) {
	if expectedResource == "" {
		// Guard the §3.4 match: an empty expected value would accept a document
		// with a missing resource. Fetch never hits this (WellKnownPath rejects an
		// empty resource); it protects a FetchMetadataURL caller.
		return nil, &ValidationError{Field: "resource", Message: "expected resource identifier is required"}
	}
	if c == nil {
		c = http.DefaultClient
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, metadataURL, nil)
	if err != nil {
		return nil, fmt.Errorf("prm: build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.Do(req)
	if err != nil {
		return nil, fmt.Errorf("prm: fetch metadata: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, &HTTPError{StatusCode: resp.StatusCode}
	}

	var m Metadata
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxMetadataBytes)).Decode(&m); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidResponse, err)
	}

	if m.Resource != expectedResource {
		return nil, fmt.Errorf("%w: got %q, want %q", ErrResourceMismatch, m.Resource, expectedResource)
	}
	return &m, nil
}
