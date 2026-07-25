package main

import (
	"strings"
	"testing"
)

func TestParseStatsArgs(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		want    statsArgs
		wantErr string
	}{
		{
			name: "flag before positional",
			args: []string{"--repo-root", "/r", "/run"},
			want: statsArgs{RunDir: "/run", RepoRoot: "/r"},
		},
		{
			name: "flag after positional (the bug case)",
			args: []string{"/run", "--repo-root", "/r"},
			want: statsArgs{RunDir: "/run", RepoRoot: "/r"},
		},
		{
			name: "flags on both sides",
			args: []string{"--json", "/run", "--repo-root", "/r"},
			want: statsArgs{RunDir: "/run", RepoRoot: "/r", AsJSON: true},
		},
		{
			name: "just positional",
			args: []string{"/run"},
			want: statsArgs{RunDir: "/run"},
		},
		{
			name: "all options",
			args: []string{"/run", "--repo-root", "/r", "--json", "--write", "/out.json"},
			want: statsArgs{RunDir: "/run", RepoRoot: "/r", AsJSON: true, WriteFile: "/out.json"},
		},
		{
			name:    "no positional",
			args:    []string{"--repo-root", "/r"},
			wantErr: "usage:",
		},
		{
			name:    "extra positional rejected",
			args:    []string{"/run1", "/run2"},
			wantErr: "unexpected extra positional",
		},
		{
			name:    "extra positional after flag rejected",
			args:    []string{"/run1", "--repo-root", "/r", "/run2"},
			wantErr: "unexpected extra positional",
		},
		{
			name:    "unknown flag",
			args:    []string{"/run", "--bogus"},
			wantErr: "flag provided but not defined",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseStatsArgs(tt.args)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("error=%q want contains %q", err.Error(), tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if got != tt.want {
				t.Errorf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}
