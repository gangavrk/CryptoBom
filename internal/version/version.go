// Package version exposes the build version, overridden at release time via
// -ldflags "-X github.com/cryptobom/cryptobom/internal/version.Version=v1.2.3".
package version

// Version is the cryptobom build version ("dev" for unreleased builds).
var Version = "dev"
