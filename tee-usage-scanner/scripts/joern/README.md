# Joern Scripts

These scripts define the intended Joern integration boundary for the scanner.

The current demo still runs from fixture evidence because `joern` is not installed locally, but the data shape in `fixtures/` mirrors what these scripts should eventually emit.

Planned script responsibilities:

- locate OP-TEE TA command handlers
- locate `params[i].memref` uses
- locate dominating `param_types` checks
- emit evidence package JSON for the Go rule engine
