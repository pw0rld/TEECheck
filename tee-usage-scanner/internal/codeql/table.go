package codeql

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// QueryTableOptions configures one query evaluated for its result table
// rather than for findings.
type QueryTableOptions struct {
	// DBPath is an existing database directory.
	DBPath string
	// QueryFile is a single .ql file. Directories and suites are not
	// accepted: a suite can produce several result sets and the caller would
	// have no way to say which table it wanted.
	QueryFile string
	// AdditionalPacks is prepended to CodeQL's package search path so a
	// custom pack resolves its dependencies against a local bundle.
	AdditionalPacks []string
	ExtraPATH       string
}

// QueryTable evaluates a @kind table query and returns its rows as strings.
//
// Analyze cannot serve this. It runs `database analyze --format=sarifv2.1.0`
// and reads findings out of SARIF, which has a place for a message and a
// location and nowhere to put an eight-column row. The program index is not
// a set of findings — it is a table — so it takes its own path:
//
//	codeql query run --database=<db> --output=<tmp>.bqrs <query>
//	codeql bqrs decode --format=json --result-set='#select' <tmp>.bqrs
//
// Every cell is returned as a string. The caller knows its own column types;
// a shared decoder that guessed them would be one more place for the query
// and the Go code to disagree silently, and the disagreement would surface
// as a wrong index rather than as an error.
func (e *Engine) QueryTable(ctx context.Context, opts QueryTableOptions) ([][]string, error) {
	// Both preconditions are checked here rather than left to CodeQL so a
	// failure names the input instead of an exit code. A wrong path is the
	// most likely mistake in a caller wiring up a new query pack.
	if opts.QueryFile == "" {
		return nil, fmt.Errorf("codeql query table: a query file is required")
	}
	if _, err := os.Stat(opts.QueryFile); err != nil {
		return nil, fmt.Errorf("codeql query table: query file %s: %w", opts.QueryFile, err)
	}
	if _, err := os.Stat(opts.DBPath); err != nil {
		return nil, fmt.Errorf("codeql query table: database %s: %w", opts.DBPath, err)
	}
	if !e.Available() {
		return nil, fmt.Errorf("codeql not available (bin=%q)", e.bin)
	}

	tmp, err := os.MkdirTemp("", "teecheck-bqrs-*")
	if err != nil {
		return nil, fmt.Errorf("codeql query table: temp dir: %w", err)
	}
	defer os.RemoveAll(tmp)
	bqrsPath := filepath.Join(tmp, "result.bqrs")

	runArgs := []string{
		"query", "run",
		"--database=" + opts.DBPath,
		"--output=" + bqrsPath,
	}
	for _, pack := range opts.AdditionalPacks {
		runArgs = append(runArgs, "--additional-packs="+pack)
	}
	runArgs = append(runArgs, opts.QueryFile)

	res := e.run(ctx, "codeql-query-run", runArgs, codeqlAnalyzeTimeout, opts.ExtraPATH)
	if err := res.Err(); err != nil {
		return nil, fmt.Errorf("codeql query run failed: %w\n%s", err, tail(res.Combined(), 2000))
	}

	// --result-set is named explicitly: a query with a @kind annotation can
	// carry more than one result set, and the default is not guaranteed to
	// be the select clause the caller wrote.
	decodeArgs := []string{
		"bqrs", "decode",
		"--format=json",
		"--result-set=#select",
		bqrsPath,
	}
	dec := e.run(ctx, "codeql-bqrs-decode", decodeArgs, codeqlAnalyzeTimeout, opts.ExtraPATH)
	if err := dec.Err(); err != nil {
		return nil, fmt.Errorf("codeql bqrs decode failed: %w\n%s", err, tail(dec.Combined(), 2000))
	}

	rows, err := decodeBQRS(dec.Stdout)
	if err != nil {
		return nil, fmt.Errorf("codeql query table: %w", err)
	}
	return rows, nil
}

// bqrsResultSet is what `bqrs decode --format=json --result-set=<name>`
// produces: the named set alone, with its columns and its tuples.
//
// Without --result-set the payload is instead a map of every set by name,
// and the select clause has to be looked up inside it. Naming the set is
// what makes the shape predictable, so this decoder only handles the named
// form and QueryTable always passes the flag.
type bqrsResultSet struct {
	Columns []struct {
		Name string `json:"name"`
		Kind string `json:"kind"`
	} `json:"columns"`
	Tuples *[][]any `json:"tuples"`
}

// decodeBQRS flattens the result set to strings.
//
// Cells arrive as JSON values — a line number is a number, a symbol is a
// string — and are rendered rather than type-switched into typed columns.
// The caller parses what it knows it asked for; a decoder that returned
// typed cells would have to agree with the query about column types, and a
// silent disagreement there produces a wrong index instead of an error.
func decodeBQRS(body []byte) ([][]string, error) {
	var set bqrsResultSet
	if err := json.Unmarshal(body, &set); err != nil {
		return nil, fmt.Errorf("decode bqrs json: %w", err)
	}
	// A pointer distinguishes "tuples: []" — a query that matched nothing,
	// which is a legitimate answer — from a payload with no tuples key at
	// all, which is not a result set. Collapsing the two would make "the
	// index found nothing" indistinguishable from "the decode was wrong".
	if set.Tuples == nil {
		return nil, fmt.Errorf("bqrs payload has no tuples — not a decoded result set; " +
			"check that --result-set named a set the query actually produces")
	}

	rows := make([][]string, 0, len(*set.Tuples))
	for _, tuple := range *set.Tuples {
		row := make([]string, 0, len(tuple))
		for _, cell := range tuple {
			row = append(row, renderCell(cell))
		}
		rows = append(rows, row)
	}
	return rows, nil
}

// renderCell turns one JSON cell into a string. Numbers decode to float64,
// so an integer column would otherwise render as "262" or as "262.000000"
// depending on the formatter; this pins it.
func renderCell(cell any) string {
	switch v := cell.(type) {
	case nil:
		return ""
	case string:
		return v
	case float64:
		if v == float64(int64(v)) {
			return fmt.Sprintf("%d", int64(v))
		}
		return fmt.Sprintf("%g", v)
	case bool:
		return fmt.Sprintf("%t", v)
	default:
		// An entity column (a location, say) decodes to an object. Render it
		// as JSON rather than as Go's map formatting so a caller that does
		// want it can parse it back.
		if data, err := json.Marshal(v); err == nil {
			return string(data)
		}
		return fmt.Sprint(v)
	}
}
