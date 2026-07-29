package all

import (
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/executor"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/staticcheck"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/staticcheck/codeql"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/staticcheck/grep"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/staticcheck/joern"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/staticcheck/semgrep"
)

// NewDefaultRegistry returns the built-in adapters with no executor wired,
// so their subprocesses run but leave no record. It is the right
// constructor for tests and for callers with no event stream.
func NewDefaultRegistry() *staticcheck.Registry {
	return NewDefaultRegistryWithExecutor(nil)
}

// NewDefaultRegistryWithExecutor is the same registry with exec threaded
// into every adapter that shells out, so their calls land in the run's
// event stream. Following actions.NewDefaultRegistryWithFacts: a second
// constructor rather than a changed signature, so existing call sites keep
// compiling and the wiring stays explicit at the one site that has an
// executor to give.
//
// exec may be nil, which is exactly NewDefaultRegistry.
func NewDefaultRegistryWithExecutor(exec executor.Executor) *staticcheck.Registry {
	r := staticcheck.NewRegistry()
	r.Register(grep.New())
	r.Register(semgrep.NewWithExecutor(exec))
	r.Register(codeql.New())
	r.Register(joern.New())
	return r
}
