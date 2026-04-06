package semgrep

import (
	"context"
	"os/exec"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/scanner"
)

type Adapter struct{}

func New() *Adapter { return &Adapter{} }

func (a *Adapter) Name() string { return "semgrep" }

func (a *Adapter) Available() bool {
	_, err := exec.LookPath("semgrep")
	return err == nil
}

func (a *Adapter) ExtractGraph(_ context.Context, _ scanner.GraphRequest) (scanner.GraphResult, error) {
	return scanner.GraphResult{}, nil
}
