// Copyright 2026 The go-protected-resource-metadata Authors
// SPDX-License-Identifier: Apache-2.0

package prm

import "testing"

func TestChallengeParam(t *testing.T) {
	const url = "https://resource.example.com/.well-known/oauth-protected-resource"
	name, value := ChallengeParam(url)
	if name != "resource_metadata" {
		t.Errorf("name = %q, want resource_metadata", name)
	}
	if name != ChallengeParamName {
		t.Errorf("name %q != ChallengeParamName %q", name, ChallengeParamName)
	}
	if value != url {
		t.Errorf("value = %q, want the bare URL %q", value, url)
	}
}
