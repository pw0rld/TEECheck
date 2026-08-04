package codedb

import (
	"context"
	"errors"
	"os"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/codeql"
)

// fakeEngine stands in for the CodeQL CLI. It is the codedb-sized slice of
// internal/trustirfacts's fake: this package only builds databases, so
// Analyze is not part of the contract it needs to satisfy.
type fakeEngine struct {
	available bool

	createDBCalls int
	createDBErr   error
}

func (f *fakeEngine) Available() bool { return f.available }

// CreateDatabase records the call and, on the canned-success path, creates
// DBPath on disk — mirroring the one on-disk effect the cache-marker logic
// depends on, without ever invoking a real extractor.
func (f *fakeEngine) CreateDatabase(_ context.Context, opts codeql.CreateDBOptions) error {
	f.createDBCalls++
	if f.createDBErr != nil {
		return f.createDBErr
	}
	return os.MkdirAll(opts.DBPath, 0o755)
}

var errBoom = errors.New("boom")
