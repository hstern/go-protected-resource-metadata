// Copyright 2026 The go-protected-resource-metadata Authors
// SPDX-License-Identifier: Apache-2.0

package prm_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"time"

	prm "github.com/hstern/go-protected-resource-metadata"
)

func ExampleChallengeParam() {
	name, value := prm.ChallengeParam("https://resource.example.com/.well-known/oauth-protected-resource")
	// A challenge serializer wraps the value in the quoted-string the header grammar wants.
	fmt.Printf("%s=%q\n", name, value)
	// Output: resource_metadata="https://resource.example.com/.well-known/oauth-protected-resource"
}

func ExampleWellKnownPath() {
	// The well-known segment is inserted before the resource's own path (§3.1).
	u, _ := prm.WellKnownPath("https://resource.example.com/resource1")
	fmt.Println(u)
	// Output: https://resource.example.com/.well-known/oauth-protected-resource/resource1
}

func ExampleMetadata_marshal() {
	m := &prm.Metadata{
		Resource:        "https://resource.example.com",
		ScopesSupported: []string{"profile", "email"},
	}
	b, _ := json.Marshal(m)
	fmt.Println(string(b))
	// Output: {"resource":"https://resource.example.com","scopes_supported":["profile","email"]}
}

func ExampleMetadata_Localized() {
	m := &prm.Metadata{
		ResourceName: "Example Protected Resource",
		Extra: map[string]json.RawMessage{
			"resource_name#fr": json.RawMessage(`"Ressource protégée"`),
		},
	}
	fr, _ := m.Localized("resource_name", "fr")
	de, _ := m.Localized("resource_name", "de") // no "de" variant: untagged fallback
	fmt.Println(fr)
	fmt.Println(de)
	// Output:
	// Ressource protégée
	// Example Protected Resource
}

func ExampleMetadata_Handler() {
	m := &prm.Metadata{Resource: "https://resource.example.com"}
	path, _ := prm.WellKnownRequestPath(m.Resource)

	mux := http.NewServeMux()
	mux.Handle(path, m.Handler(prm.WithMaxAge(time.Hour)))
	// http.ListenAndServe(":8080", mux)

	fmt.Println(path)
	// Output: /.well-known/oauth-protected-resource
}

func ExampleFetch() {
	// A protected resource publishing its metadata at the well-known path.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = prm.ServeMetadata(w, &prm.Metadata{
			Resource:        "https://" + r.Host,
			ScopesSupported: []string{"read"},
		})
	}))
	defer srv.Close()

	m, err := prm.Fetch(context.Background(), srv.Client(), srv.URL)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Println(m.ScopesSupported[0])
	// Output: read
}
