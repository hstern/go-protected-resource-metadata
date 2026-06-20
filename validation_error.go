// Copyright 2026 The go-protected-resource-metadata Authors
// SPDX-License-Identifier: Apache-2.0

package prm

import (
	"errors"
	"fmt"
)

// ErrValidation is the sentinel that every *ValidationError unwraps to, so a
// caller can match any validation failure with errors.Is(err, ErrValidation) or
// inspect the specifics with errors.As.
var ErrValidation = errors.New("prm: validation failed")

// ValidationError reports a metadata member that does not satisfy an RFC 9728
// requirement — a missing required parameter, a non-https resource identifier,
// an unsupported bearer method, and the like. It names the offending member so a
// caller can report a precise problem.
type ValidationError struct {
	// Field is the member at fault, e.g. "resource".
	Field string
	// Message explains the problem, lowercase and without trailing punctuation.
	Message string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("prm: %s: %s", e.Field, e.Message)
}

func (e *ValidationError) Unwrap() error { return ErrValidation }
