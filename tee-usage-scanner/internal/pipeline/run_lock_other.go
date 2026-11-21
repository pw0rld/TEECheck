//go:build !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd

package pipeline

import "fmt"

func lockRunDirectory(_ string, resume bool) (func(), error) {
	if resume {
		return nil, fmt.Errorf("safe resume requires OS file locking on this platform")
	}
	return func() {}, nil
}
