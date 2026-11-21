package codeql

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Resource options are resolved per invocation so callers can change defaults
// between runs. Explicit nonzero fields win: the database recovery path must
// be able to force one thread even when the environment requests many.
func resourceArgs(ram, threads int) ([]string, error) {
	var err error
	if ram == 0 {
		ram, err = resourceEnvInt("TEECHECK_CODEQL_RAM")
		if err != nil {
			return nil, err
		}
	}
	if ram < 0 {
		return nil, fmt.Errorf("CodeQL RAM must not be negative")
	}
	if threads == 0 {
		threads, err = resourceEnvInt("TEECHECK_CODEQL_THREADS")
		if err != nil {
			return nil, err
		}
	}
	var args []string
	if ram != 0 {
		args = append(args, "--ram="+strconv.Itoa(ram))
	}
	if threads != 0 {
		args = append(args, "--threads="+strconv.Itoa(threads))
	}
	return args, nil
}

func resourceEnvInt(name string) (int, error) {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("%s must be an integer: %w", name, err)
	}
	return n, nil
}
