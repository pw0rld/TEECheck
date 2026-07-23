package trustirfacts

import (
	"context"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/codeql"
)

// Engine is the minimal CodeQL capability this package depends on, sized to
// exactly the three calls it makes. *codeql.Engine already satisfies this
// interface structurally — its Available/CreateDatabase/Analyze method set
// matches verbatim — so production callers pass a *codeql.Engine directly
// and no adapter type is needed. internal/codeql's exported surface is
// unchanged by this package.
//
// Tests construct a small stub implementing Engine (canned SARIF, a
// non-zero-exit error, a context-deadline error) instead of building a real
// database or running a real query — see run_test.go, following the pattern
// internal/expert/run_test.go uses to fake llm.Client.
type Engine interface {
	Available() bool
	CreateDatabase(ctx context.Context, opts codeql.CreateDBOptions) error
	Analyze(ctx context.Context, opts codeql.AnalyzeOptions) ([]codeql.Result, error)
}

// compile-time assertion that the real engine still satisfies our seam.
var _ Engine = (*codeql.Engine)(nil)
