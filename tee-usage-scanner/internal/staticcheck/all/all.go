package all

import (
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/staticcheck"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/staticcheck/codeql"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/staticcheck/grep"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/staticcheck/joern"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/staticcheck/semgrep"
)

func NewDefaultRegistry() *staticcheck.Registry {
	r := staticcheck.NewRegistry()
	r.Register(grep.New())
	r.Register(semgrep.New())
	r.Register(codeql.New())
	r.Register(joern.New())
	return r
}
