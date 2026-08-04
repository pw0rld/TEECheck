package pipeline

import (
	"os"
	"strings"
)

// secretFlags are the flags whose values must never reach events.jsonl.
// The event stream is the artifact most likely to be attached to a bug
// report or committed alongside a benchmark result.
var secretFlags = map[string]bool{
	"--llm-api-key": true,
	"-llm-api-key":  true,
}

const redacted = "[REDACTED]"

// launchCommand renders the process argv as a single line, with any API key
// value replaced.
//
// It records what the run was asked to do. Everything else in the stream
// records what it then did — and on run-b that left the invocation
// unrecoverable: the manifest showed a repository and a commit that git could
// not have detected for the scanned tree, so the identity overrides had to be
// inferred, and the target, run-id and hint could not be recovered at all.
//
// argv is the honest source. Reconstructing the line from the parsed Config
// would print flags that were never typed and hide values that came from the
// environment, which is the opposite of a record.
func launchCommand(argv []string) string {
	out := make([]string, 0, len(argv))
	skipNext := false
	for _, arg := range argv {
		if skipNext {
			out = append(out, redacted)
			skipNext = false
			continue
		}
		// --llm-api-key=VALUE keeps the flag name and drops the value.
		if eq := strings.IndexByte(arg, '='); eq > 0 && secretFlags[arg[:eq]] {
			out = append(out, arg[:eq]+"="+redacted)
			continue
		}
		if secretFlags[arg] {
			out = append(out, arg)
			skipNext = true
			continue
		}
		out = append(out, arg)
	}
	return strings.Join(out, " ")
}

// processCommand is launchCommand applied to this process.
func processCommand() string { return launchCommand(os.Args) }
