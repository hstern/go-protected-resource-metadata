// Copyright 2026 The go-protected-resource-metadata Authors
// SPDX-License-Identifier: Apache-2.0

package prm

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// ServeMetadata writes m to w as a protected resource metadata response: it
// validates m (never serve an invalid document), sets Content-Type to
// application/json, and writes the JSON with status 200. It writes nothing and
// returns the error if m is invalid (a *ValidationError) or cannot be marshaled.
//
// ServeMetadata is the à-la-carte primitive — it imposes no method handling or
// routing. Use it inside a handler you already run, or use Handler for a ready
// http.Handler. Mount either at the path from WellKnownRequestPath.
func ServeMetadata(w http.ResponseWriter, m *Metadata) error {
	body, err := marshalValidated(m)
	if err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, err = w.Write(body)
	return err
}

// Handler returns an http.Handler that serves the metadata document m. It
// answers GET and HEAD with the JSON document (200) and rejects other methods
// with 405 and an Allow header. The document is validated and marshaled once,
// when Handler is called; if m is invalid the handler responds 500 to every
// request — call m.Validate yourself first if you want to detect that up front.
//
// Register the handler at WellKnownRequestPath(m.Resource):
//
//	path, err := prm.WellKnownRequestPath(m.Resource)
//	// handle err
//	mux.Handle(path, m.Handler(prm.WithMaxAge(time.Hour)))
//
// Options configure HTTP caching (§7.10): WithMaxAge sets Cache-Control and
// WithETag sets an ETag and answers a matching If-None-Match with 304.
func (m *Metadata) Handler(opts ...HandlerOption) http.Handler {
	var cfg handlerConfig
	for _, o := range opts {
		o(&cfg)
	}
	body, buildErr := marshalValidated(m)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if buildErr != nil {
			http.Error(w, "invalid protected resource metadata", http.StatusInternalServerError)
			return
		}

		h := w.Header()
		h.Set("Content-Type", "application/json")
		if cfg.maxAge > 0 {
			h.Set("Cache-Control", "max-age="+strconv.Itoa(int(cfg.maxAge.Seconds())))
		}
		if cfg.etag != "" {
			h.Set("ETag", cfg.etag)
			if ifNoneMatch(r.Header.Get("If-None-Match"), cfg.etag) {
				w.WriteHeader(http.StatusNotModified)
				return
			}
		}
		if r.Method == http.MethodHead {
			h.Set("Content-Length", strconv.Itoa(len(body)))
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	})
}

// HandlerOption configures the http.Handler returned by Metadata.Handler.
type HandlerOption func(*handlerConfig)

type handlerConfig struct {
	maxAge time.Duration
	etag   string
}

// WithMaxAge sets a Cache-Control max-age on the served document (§7.10). A
// non-positive duration leaves Cache-Control unset.
func WithMaxAge(d time.Duration) HandlerOption {
	return func(c *handlerConfig) { c.maxAge = d }
}

// WithETag sets the ETag header on the served document and enables 304 Not
// Modified responses to a matching If-None-Match request. The tag is wrapped in
// the double quotes an entity-tag requires if it is not already quoted.
func WithETag(tag string) HandlerOption {
	return func(c *handlerConfig) { c.etag = quoteETag(tag) }
}

func marshalValidated(m *Metadata) ([]byte, error) {
	if err := m.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(m)
}

// quoteETag wraps tag in double quotes unless it is already a quoted (optionally
// weak, W/"...") entity-tag.
func quoteETag(tag string) string {
	if strings.HasPrefix(tag, `"`) || strings.HasPrefix(tag, `W/"`) {
		return tag
	}
	return `"` + tag + `"`
}

// ifNoneMatch reports whether an If-None-Match header value matches etag. It
// honors "*" and a comma-separated list of entity-tags, comparing on the strong
// validator (the weak prefix is ignored for the comparison).
func ifNoneMatch(header, etag string) bool {
	header = strings.TrimSpace(header)
	if header == "" {
		return false
	}
	if header == "*" {
		return true
	}
	want := strings.TrimPrefix(etag, "W/")
	for _, candidate := range strings.Split(header, ",") {
		if strings.TrimPrefix(strings.TrimSpace(candidate), "W/") == want {
			return true
		}
	}
	return false
}
