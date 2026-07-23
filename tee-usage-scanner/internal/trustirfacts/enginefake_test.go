package trustirfacts

import (
	"context"
	"errors"
	"os"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/codeql"
)

// errBoom is a shared sentinel test error, distinct from any error this
// package's own logic might produce, so assertions can tell "the fake
// failed on purpose" apart from "something else broke".
var errBoom = errors.New("boom")

// fakeEngine is a canned test double for the Engine seam (see engine.go's
// doc comment on why this package depends on an interface rather than
// *codeql.Engine directly). It never shells out to the codeql binary and
// never builds or queries a real database — following the pattern
// internal/expert/run_test.go uses to fake llm.Client.
type fakeEngine struct {
	available bool

	createDBCalls int
	createDBErr   error

	analyzeCalls   int
	analyzeResults []codeql.Result
	analyzeErr     error
}

func (f *fakeEngine) Available() bool { return f.available }

// CreateDatabase records the call and, on the canned-success path, creates
// DBPath on disk — mirroring the one on-disk effect ensureDatabase's
// cache-marker logic depends on, without ever invoking a real extractor.
func (f *fakeEngine) CreateDatabase(_ context.Context, opts codeql.CreateDBOptions) error {
	f.createDBCalls++
	if f.createDBErr != nil {
		return f.createDBErr
	}
	return os.MkdirAll(opts.DBPath, 0o755)
}

func (f *fakeEngine) Analyze(_ context.Context, _ codeql.AnalyzeOptions) ([]codeql.Result, error) {
	f.analyzeCalls++
	if f.analyzeErr != nil {
		return nil, f.analyzeErr
	}
	return f.analyzeResults, nil
}

var _ Engine = (*fakeEngine)(nil)
