package executor

import (
	"context"
	"errors"
	"os"
	"strconv"
	"strings"
)

// This file holds the small amount of surface a CALL SITE needs to route
// through the executor without inheriting the executor's vocabulary. It
// adds to the package; it changes nothing that was already here.
//
// Each piece exists because routing the four remaining direct-exec sites
// (semgrep, codeql, repomix, trustirfacts' git clone) turned up the same
// need four times over:
//
//   - Bind: a package like internal/codeql knows WHICH command it runs but
//     not which run or which agent it is running for. Without a binding
//     decorator every such package would have to grow RunID/Agent/Round
//     fields it has no other use for, and each would have to remember to
//     copy them onto every Request. Bind puts that decision once, at the
//     wiring site in internal/pipeline, where the stage identity is known.
//   - OrLocal: call sites must work with no executor supplied (tests,
//     standalone subcommands). Falling back to a silent LocalExecutor —
//     rather than to a separate os/exec code path — means there is exactly
//     ONE execution path, so the recorded and unrecorded cases cannot
//     drift apart.
//   - InheritedEnvNames: all four sites inherit the full parent
//     environment today. Preserving that through Profile.EnvAllowlist is
//     the difference between behaviour parity and a subtly different
//     child process (git's locale, npx's npm config, CodeQL's own knobs).
//   - Result.Err / Result.Combined: the call sites used to read
//     cmd.Run()/CombinedOutput() errors. These translate a Result back
//     into the same shapes so their error strings do not change.

// Binding is the event-correlation identity a call site cannot know for
// itself. Empty fields are left alone, so a Request that already carries
// its own (the planner's per-round calls) is not overwritten.
type Binding struct {
	RunID  string
	Agent  string
	CaseID string
	Round  int
}

// Bind returns an Executor that stamps b onto every Request it forwards.
// A nil inner executor yields nil, so a call site's OrLocal fallback still
// engages rather than being masked by a wrapper around nothing.
func Bind(inner Executor, b Binding) Executor {
	if inner == nil {
		return nil
	}
	return bound{inner: inner, b: b}
}

type bound struct {
	inner Executor
	b     Binding
}

func (x bound) Run(ctx context.Context, req Request) Result {
	if req.RunID == "" {
		req.RunID = x.b.RunID
	}
	if req.Agent == "" {
		req.Agent = x.b.Agent
	}
	if req.CaseID == "" {
		req.CaseID = x.b.CaseID
	}
	if req.Round == 0 {
		req.Round = x.b.Round
	}
	return x.inner.Run(ctx, req)
}

// OrLocal returns e, or a plain non-recording LocalExecutor when e is nil.
//
// Instrumentation must never be the reason a call fails: a package used
// from a unit test or a standalone subcommand has no event stream, and
// must still run its tool.
func OrLocal(e Executor) Executor {
	if e == nil {
		return &LocalExecutor{}
	}
	return e
}

// InheritedEnvNames returns the name of every variable in the current
// process environment, for use as Profile.EnvAllowlist.
//
// It expresses "this child inherits the parent environment, exactly as it
// did before it was routed through the executor". That is not the same as
// leaving EnvAllowlist empty, which inherits only PATH and HOME — a real
// behaviour change for every tool here: git's diagnostics are localised
// via LANG, npx reads npm_config_*, and CodeQL reads its own CODEQL_* and
// JAVA_* settings.
//
// Tightening these into per-tool allowlists is a separate decision with
// real breakage risk; it is deliberately NOT bundled into the change that
// merely moved these calls behind the chokepoint.
func InheritedEnvNames() []string {
	env := os.Environ()
	names := make([]string, 0, len(env))
	for _, kv := range env {
		if i := strings.IndexByte(kv, '='); i > 0 {
			names = append(names, kv[:i])
		}
	}
	return names
}

// PrependPATH builds the Env overlay that puts extra at the front of the
// child's PATH, or nil when extra is empty.
//
// The overlay is applied after the allowlist in buildEnv, and os/exec
// de-duplicates env entries keeping the LAST occurrence, so this reliably
// wins over the inherited PATH.
func PrependPATH(extra string) map[string]string {
	if strings.TrimSpace(extra) == "" {
		return nil
	}
	return map[string]string{"PATH": extra + string(os.PathListSeparator) + os.Getenv("PATH")}
}

// Err returns the error a call site would have received from
// cmd.Run()/cmd.Output() for this Result, or nil if the command succeeded.
//
// The two failure families stay distinct, matching Result's documented
// contract: a process that started and exited non-zero yields the same
// "exit status N" text os/exec's ExitError produces, while a genuine
// execution failure (timeout, binary not found) yields the executor's own
// message. Call sites that branch on which family they are in — semgrep
// treats a non-zero exit as a normal outcome, and only a true exec failure
// as fatal — keep that branch by testing Result.Error directly rather than
// unwrapping this.
func (r Result) Err() error {
	switch {
	case r.Error != "":
		return errors.New(r.Error)
	case r.OK:
		return nil
	default:
		return errors.New("exit status " + strconv.Itoa(r.ExitCode))
	}
}

// Combined returns Stdout followed by Stderr, the stand-in for the
// cmd.CombinedOutput() the codeql and git call sites used to take.
//
// It is a concatenation, not an interleave: the executor captures the two
// streams separately (deliberately — see Event.ToolOutputBlob's comment on
// why a merged blob would lose which stream said what), so the exact
// interleaving of a process that wrote to both is not recoverable. For the
// only consumer, a tail() of the last 2000 bytes embedded in an error
// message, this means the tail is now the end of stderr rather than the
// end of whichever stream flushed last — which is where a failing tool's
// explanation lives anyway.
//
// When the executor truncated either stream a marker is appended, because
// a tail() of a capped buffer is no longer the tail of what the process
// actually said, and a shortened diagnostic that does not admit it is the
// exact defect this instrumentation exists to close.
func (r Result) Combined() []byte {
	out := make([]byte, 0, len(r.Stdout)+len(r.Stderr)+64)
	out = append(out, r.Stdout...)
	out = append(out, r.Stderr...)
	if r.Truncated {
		out = append(out, "\n[output truncated by the executor's max-output cap; "+
			"the full stream did not survive]"...)
	}
	return out
}
