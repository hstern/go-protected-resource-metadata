// Copyright 2026 The go-protected-resource-metadata Authors
// SPDX-License-Identifier: Apache-2.0

package prm

// ChallengeParamName is the WWW-Authenticate auth-param a protected resource
// uses to point a client at its metadata document (RFC 9728 §5.1).
const ChallengeParamName = "resource_metadata"

// ChallengeParam returns the WWW-Authenticate challenge parameter that points a
// client at the protected resource metadata document at metadataURL (RFC 9728
// §5.1). It yields the bare (name, value) pair — ("resource_metadata", the URL)
// — for the caller to add to a challenge it is already building, for example a
// bearer-token library's challenge "extra" parameters:
//
//	name, value := prm.ChallengeParam(metadataURL)
//	challenge.Extra[name] = value // serialized as resource_metadata="<url>"
//
// The value is the raw URL. The challenge serializer is responsible for wrapping
// it in the double-quoted auth-param quoted-string the header grammar requires
// (RFC 9110 §11.2); when writing the header by hand, quote it:
//
//	WWW-Authenticate: Bearer resource_metadata="https://.../.well-known/oauth-protected-resource"
//
// Keeping the seam to a plain string pair avoids a dependency on, and a
// duplicate of, any particular WWW-Authenticate challenge type. §5.1 permits the
// parameter with non-Bearer schemes (e.g. DPoP) and alongside other parameters.
func ChallengeParam(metadataURL string) (name, value string) {
	return ChallengeParamName, metadataURL
}
