//go:build !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd

package codedb

import (
	"context"
	"fmt"
)

func lockCache(ctx context.Context, path string) (func(), error) {
	return nil, fmt.Errorf("shared CodeQL cache requires OS file-lock support on this platform")
}
