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
