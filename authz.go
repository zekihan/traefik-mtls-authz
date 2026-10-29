// Package traefikmtlsauthz provides a deny-all skeleton for a Traefik middleware.
package traefikmtlsauthz

import (
	"context"
	"net/http"
)

// Config is intentionally empty until the authorization policy is implemented.
type Config struct{}

// CreateConfig returns the default plugin configuration.
func CreateConfig() *Config { return &Config{} }

// Middleware denies every request in the skeleton release.
type Middleware struct{}

// New implements Traefik's middleware constructor. No request can reach next.
func New(_ context.Context, _ http.Handler, _ *Config, _ string) (http.Handler, error) {
	return &Middleware{}, nil
}

// ServeHTTP fails closed until certificate authorization is implemented.
func (m *Middleware) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	http.Error(w, "Forbidden", http.StatusForbidden)
}
