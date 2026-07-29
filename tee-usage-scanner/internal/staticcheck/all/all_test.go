package all

import (
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/executor"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/staticcheck/semgrep"
)

// The pipeline reaches the semgrep adapter only through this constructor,
// so this is the tripwire for "the registry stopped threading the executor
// through". Without it, the wiring would be checked by the compiler alone
// — nil satisfies executor.Executor just as well as a real one does.
func TestNewDefaultRegistryWithExecutor_ThreadsExecutorIntoSemgrep(t *testing.T) {
	exec := &executor.LocalExecutor{}
	r := NewDefaultRegistryWithExecutor(exec)

	a, ok := r.Get("semgrep")
	if !ok {
		t.Fatal("semgrep adapter is not registered")
	}
	sa, ok := a.(*semgrep.Adapter)
	if !ok {
		t.Fatalf("semgrep adapter has type %T", a)
	}
	if sa.Exec != executor.Executor(exec) {
		t.Errorf("semgrep adapter Exec = %v, want the executor passed to the constructor", sa.Exec)
	}
}

// The no-executor constructor must stay non-recording: it is what tests
// and standalone callers with no event stream get.
func TestNewDefaultRegistry_LeavesSemgrepUnwired(t *testing.T) {
	a, ok := NewDefaultRegistry().Get("semgrep")
	if !ok {
		t.Fatal("semgrep adapter is not registered")
	}
	if a.(*semgrep.Adapter).Exec != nil {
		t.Error("NewDefaultRegistry wired an executor; it must leave Exec nil")
	}
}
