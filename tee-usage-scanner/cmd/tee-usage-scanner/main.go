package main

import (
	"fmt"
	"os"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/config"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/kgpack"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/scan"
)

func main() {
	cfg, err := config.Parse(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	var runErr error
	switch cfg.Command {
	case "scan":
		runErr = scan.Run(cfg)
	case "kgpack":
		runErr = kgpack.Run(cfg)
	default:
		runErr = fmt.Errorf("unsupported command: %s", cfg.Command)
	}

	if runErr != nil {
		fmt.Fprintln(os.Stderr, runErr)
		os.Exit(1)
	}
}
