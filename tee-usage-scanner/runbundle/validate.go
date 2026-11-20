// Package runbundle exposes the scanner's offline integrity gate to clients
// such as the independent benchmark runner without duplicating its rules.
package runbundle

import (
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runvalidate"
)

type Report = runvalidate.Report
type Issue = runvalidate.Issue

func Validate(runDir string) Report { return runvalidate.Validate(runDir) }
