// Package executor provides a single chokepoint for command-execution
// tools (ripgrep, semgrep, codeql, go test, repo scripts, ...). It is
// deliberately scoped to subprocess invocations only — pure file APIs
// like read_file, list_dir, and tree_sitter_outline stay outside this
// boundary.
//
// The first version is a single LocalExecutor that runs commands in
// the current process, with timeout enforcement and output-size
// capping. Network and write-policy fields on Profile are recorded as
// metadata and surfaced in events; OS-level enforcement (sandboxing,
// cgroups, docker) is a later commit.
//
// Why this exists, in short:
//
//   - All future security-relevant tools (semgrep, codeql, go test
//     against an unknown repo, build.rs side-effects from cargo
//     invocations) need a single place to attach policy and
//     instrumentation. Without a chokepoint, each call site grows its
//     own ad-hoc subset of these concerns.
//   - The event stream from commit 1-2 already defines the right
//     event shape (tool_call_started / tool_call_completed). The
//     executor is the natural emitter — call sites stop having to
//     remember to instrument.
package executor

import "time"

// NetworkPolicy declares whether the command may reach the network.
// Today this is metadata only; LocalExecutor records it on events
// but does not enforce it. A future SandboxExecutor will block
// outbound traffic when the policy is None.
type NetworkPolicy string

const (
	NetworkNone       NetworkPolicy = "none"       // no network access
	NetworkRestricted NetworkPolicy = "restricted" // allowlist (TBD)
	NetworkAllow      NetworkPolicy = "allow"      // unrestricted (e.g. git clone)
)

// WritePolicy declares where the command may write. Recorded as
// metadata today; future enforcement will mount filesystems
// read-only outside the listed scope.
type WritePolicy string

const (
	WriteNone       WritePolicy = "none"         // pure read-only command
	WriteRunDirOnly WritePolicy = "run-dir-only" // may write under runDir
	WriteWorkspace  WritePolicy = "workspace"    // may write anywhere under workspace
)

// Profile is the policy envelope every command runs under. Callers
// fill it according to the tool's needs; LocalExecutor enforces the
// fields it can today (timeout, output cap) and records the rest.
//
// Defaults (zero value) are intentionally restrictive:
//   - Network = ""    → treat as NetworkNone in event emission
//   - Write   = ""    → treat as WriteNone in event emission
//   - Timeout = 0     → DefaultTimeout applied by LocalExecutor
//   - MaxOutputBytes = 0 → DefaultMaxOutputBytes applied
type Profile struct {
	Network        NetworkPolicy `json:"network,omitempty"`
	Write          WritePolicy   `json:"write,omitempty"`
	Timeout        time.Duration `json:"timeout,omitempty"`
	EnvAllowlist   []string      `json:"env_allowlist,omitempty"`
	MaxOutputBytes int           `json:"max_output_bytes,omitempty"`
}

// DefaultTimeout is applied when Profile.Timeout is zero.
const DefaultTimeout = 60 * time.Second

// DefaultMaxOutputBytes is applied when Profile.MaxOutputBytes is
// zero. Generous enough for typical ripgrep / semgrep output but
// bounded so a runaway tool can't OOM the harness.
const DefaultMaxOutputBytes = 4 * 1024 * 1024 // 4 MiB

// Request is what callers hand to Executor.Run. Name is the logical
// tool name surfaced to events ("ripgrep", "semgrep", "go-test"); it
// does not have to equal the binary on disk. Command + Args are the
// actual argv. WorkDir defaults to the current working directory
// when empty.
//
// AgentID/CaseID/Round populate the corresponding fields in any
// emitted event. Empty values stay omitted from JSON.
type Request struct {
	Name    string            // logical tool name for events
	Command string            // binary or PATH-resolved name
	Args    []string          // argv after Command
	WorkDir string            // empty = inherit
	Stdin   []byte            // optional stdin
	Env     map[string]string // explicit env overlay (in addition to allowlist)
	Profile Profile

	// Event correlation. AgentID is required when Recorder is set;
	// the rest are optional.
	RunID  string
	Agent  string
	CaseID string
	Round  int
}

// Result is what Executor.Run returns. OK is true iff the process
// exited 0 and no policy/timeout error fired. Stdout/Stderr are
// capped to MaxOutputBytes per stream; Truncated indicates this
// happened. DurationMs measures wall clock from the Run call to the
// process exit (not just CPU time).
type Result struct {
	OK         bool
	ExitCode   int
	Stdout     []byte
	Stderr     []byte
	DurationMs int64
	Truncated  bool
	// Error captures policy denial, timeout, binary-not-found, or
	// any other failure that prevents producing a valid exit code.
	// When the process started and exited (even non-zero), Error is
	// empty and ExitCode carries the status.
	Error string
}
