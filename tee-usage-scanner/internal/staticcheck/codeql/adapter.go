package codeql

import (
	"context"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/staticcheck"
)

type Adapter struct{}

func New() *Adapter { return &Adapter{} }

func (a *Adapter) Name() string    { return "codeql" }
func (a *Adapter) Available() bool { return false }

func (a *Adapter) Run(_ context.Context, _ staticcheck.CheckRequest) ([]staticcheck.CheckFinding, error) {
	return nil, staticcheck.ErrNotImplemented
}
