package executor

import "context"

// Executor runs a Request and returns a Result. The interface is
// intentionally a single method so future implementations
// (sandboxed, dockerized, remote) drop in without changing call
// sites.
//
// Implementations MUST:
//   - apply DefaultTimeout when Profile.Timeout is zero
//   - apply DefaultMaxOutputBytes when Profile.MaxOutputBytes is zero
//   - produce a Result for every call, even on error
//
// Implementations SHOULD emit tool_call_started / tool_call_completed
// events when given a recorder, so call sites do not need to
// instrument themselves. See LocalExecutor for the canonical pattern.
type Executor interface {
	Run(ctx context.Context, req Request) Result
}
