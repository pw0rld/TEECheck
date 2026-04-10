package codeql

import (
	"context"
	"errors"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/scanner"
)

type Adapter struct{}

func New() *Adapter { return &Adapter{} }

func (a *Adapter) Name() string { return "codeql" }

func (a *Adapter) Available() bool { return false }

func (a *Adapter) ExtractGraph(_ context.Context, _ scanner.GraphRequest) (scanner.GraphResult, error) {
	return scanner.GraphResult{}, errors.New("codeql graph adapter not implemented")
}
