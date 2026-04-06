package all

import (
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/scanner"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/scanner/codeql"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/scanner/joern"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/scanner/regex"
	scanSemgrep "github.com/pw0rld/TEECheck/tee-usage-scanner/internal/scanner/semgrep"
)

// NewDefaultGraphRegistry returns a GraphRegistry pre-loaded with all
// built-in graph adapters. Adapters that require external tools (semgrep,
// codeql, joern) self-report as unavailable when those tools are absent;
// only the regex adapter is always available.
func NewDefaultGraphRegistry() *scanner.GraphRegistry {
	r := scanner.NewGraphRegistry()
	r.Register(regex.New())
	r.Register(scanSemgrep.New())
	r.Register(codeql.New())
	r.Register(joern.New())
	return r
}
