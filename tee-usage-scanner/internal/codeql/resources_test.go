package codeql

import (
	"context"
	"reflect"
	"strings"
	"testing"
)

func TestResourceArgs_DefaultExplicitAndEnvironment(t *testing.T) {
	for _, tc := range []struct {
		name, envRAM, envThreads string
		ram, threads             int
		want                     []string
		wantError                bool
	}{
		{name: "default"},
		{name: "zero environment", envRAM: "0", envThreads: "0"},
		{name: "environment", envRAM: "4096", envThreads: "8", want: []string{"--ram=4096", "--threads=8"}},
		{name: "explicit", envRAM: "4096", envThreads: "8", ram: 2048, threads: 1, want: []string{"--ram=2048", "--threads=1"}},
		{name: "negative threads", envThreads: "-2", want: []string{"--threads=-2"}},
		{name: "explicit overrides malformed environment", envRAM: "invalid", envThreads: "invalid", ram: 1024, threads: 1, want: []string{"--ram=1024", "--threads=1"}},
		{name: "bad environment", envRAM: "invalid", wantError: true},
		{name: "negative ram", ram: -1, wantError: true},
		{name: "negative ram environment", envRAM: "-10", wantError: true},
		{name: "bad thread environment", envThreads: "2.5", wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("TEECHECK_CODEQL_RAM", tc.envRAM)
			t.Setenv("TEECHECK_CODEQL_THREADS", tc.envThreads)
			got, err := resourceArgs(tc.ram, tc.threads)
			if (err != nil) != tc.wantError {
				t.Fatalf("args=%v error=%v", got, err)
			}
			if !tc.wantError && !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestCreateAndAnalyzePassResourceFlags(t *testing.T) {
	for _, analyze := range []bool{false, true} {
		name := "create"
		if analyze {
			name = "analyze"
		}
		t.Run(name, func(t *testing.T) {
			t.Setenv("TEECHECK_CODEQL_RAM", "4096")
			t.Setenv("TEECHECK_CODEQL_THREADS", "8")
			t.Setenv("TEECHECK_CODEQL_ANALYZE_THREADS", "invalid")
			bin, argv := fakeCodeQL(t, "", "", emptySARIF, 0)
			engine := NewWithBin(bin)
			if analyze {
				if _, err := engine.Analyze(context.Background(), AnalyzeOptions{DBPath: "/db", Queries: []string{"check.ql"}, Threads: 1}); err != nil {
					t.Fatal(err)
				}
			} else if err := engine.CreateDatabase(context.Background(), CreateDBOptions{Language: "cpp", SourceRoot: "/src", DBPath: "/db", Threads: 1}); err != nil {
				t.Fatal(err)
			}
			args := strings.Join(readArgv(t, argv), "\n")
			if !strings.Contains(args, "--ram=4096") || !strings.Contains(args, "--threads=1") || strings.Contains(args, "--threads=8") {
				t.Fatalf("resource flags not forwarded: %s", args)
			}
		})
	}
}

func TestAnalyzeResourceArgs_ThreadPrecedence(t *testing.T) {
	for _, tc := range []struct {
		name, shared, analysis string
		explicit               int
		want                   []string
		wantError              bool
	}{
		{name: "unset"},
		{name: "shared fallback", shared: "1", want: []string{"--threads=1"}},
		{name: "analysis override", shared: "1", analysis: "2", want: []string{"--threads=2"}},
		{name: "explicit override", shared: "1", analysis: "2", explicit: 4, want: []string{"--threads=4"}},
		{name: "zero falls back", shared: "1", analysis: "0", want: []string{"--threads=1"}},
		{name: "negative override", shared: "1", analysis: "-2", want: []string{"--threads=-2"}},
		{name: "invalid analysis", shared: "1", analysis: "invalid", wantError: true},
		{name: "explicit ignores invalid analysis", shared: "invalid", analysis: "invalid", explicit: 1, want: []string{"--threads=1"}},
		{name: "analysis ignores invalid shared", shared: "invalid", analysis: "2", want: []string{"--threads=2"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("TEECHECK_CODEQL_RAM", "")
			t.Setenv("TEECHECK_CODEQL_THREADS", tc.shared)
			t.Setenv("TEECHECK_CODEQL_ANALYZE_THREADS", tc.analysis)
			got, err := analyzeResourceArgs(0, tc.explicit)
			if (err != nil) != tc.wantError || !tc.wantError && !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("args=%v err=%v, want %v error=%v", got, err, tc.want, tc.wantError)
			}
		})
	}
}

func TestCreateAndAnalyzeSeparateThreadEnvironments(t *testing.T) {
	for _, analysis := range []string{"2", "invalid"} {
		t.Run(analysis, func(t *testing.T) {
			t.Setenv("TEECHECK_CODEQL_RAM", "")
			t.Setenv("TEECHECK_CODEQL_THREADS", "1")
			t.Setenv("TEECHECK_CODEQL_ANALYZE_THREADS", analysis)
			bin, argv := fakeCodeQL(t, "", "", emptySARIF, 0)
			engine := NewWithBin(bin)
			if err := engine.CreateDatabase(context.Background(), CreateDBOptions{Language: "cpp", SourceRoot: "/src", DBPath: "/db"}); err != nil {
				t.Fatalf("analysis override affected create: %v", err)
			}
			createArgs := readArgv(t, argv)
			if args := strings.Join(createArgs, "\n"); !strings.Contains(args, "--threads=1") || strings.Contains(args, "--threads=2") {
				t.Fatalf("create thread setting changed: %s", args)
			}
			_, err := engine.Analyze(context.Background(), AnalyzeOptions{DBPath: "/db", Queries: []string{"check.ql"}})
			if analysis == "invalid" {
				if err == nil || !strings.Contains(err.Error(), "TEECHECK_CODEQL_ANALYZE_THREADS") {
					t.Fatalf("analysis error=%v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if args := strings.Join(readArgv(t, argv)[len(createArgs):], "\n"); !strings.Contains(args, "--threads=2") || strings.Contains(args, "--threads=1") {
				t.Fatalf("analysis override missing: %s", args)
			}
		})
	}
}
