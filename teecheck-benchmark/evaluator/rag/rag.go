// Package rag contains the benchmark-side retrieval layer. It is deliberately
// outside the scanner process: benchmark truth is never supplied to TEECheck.
package rag

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

type Finding struct {
	FindingID string   `json:"finding_id"`
	Status    string   `json:"status"`
	Files     []string `json:"files"`
	Summary   string   `json:"summary"`
	Evidence  []string `json:"evidence"`
}

type Report struct {
	SchemaVersion string    `json:"schema_version"`
	RunID         string    `json:"run_id"`
	Findings      []Finding `json:"findings"`
}

type Document struct {
	CaseID   string `json:"case_id"`
	Kind     string `json:"kind"`
	Text     string `json:"text"`
	File     string `json:"file,omitempty"`
	Function string `json:"function,omitempty"`
	Variant  string `json:"variant,omitempty"`
}

type Case struct {
	ID               string
	Weakness         string
	PrimaryFile      string
	PrimaryFunction  string
	MatchTerms       []string
	RequiredEvidence []string
	FixedEvidence    []string
	TWEFamily        string
	Documents        []Document
}

type Hit struct {
	CaseID string  `json:"case_id"`
	Score  float64 `json:"score"`
	Case   Case    `json:"case"`
}

type oracle struct {
	ID               string   `json:"id"`
	Weakness         string   `json:"weakness"`
	PrimaryFile      string   `json:"primary_file"`
	PrimaryFunction  string   `json:"primary_function"`
	MatchTerms       []string `json:"match_terms"`
	RequiredEvidence []string `json:"required_evidence"`
	FixedEvidence    []string `json:"fixed_evidence"`
	TWEFamily        string   `json:"twe_family"`
}

var tokenRE = regexp.MustCompile(`[A-Za-z0-9_./:-]{3,}`)

func Load(casesDir string) ([]Case, error) {
	entries, err := os.ReadDir(casesDir)
	if err != nil {
		return nil, err
	}
	var out []Case
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		root := filepath.Join(casesDir, entry.Name())
		var o oracle
		b, err := os.ReadFile(filepath.Join(root, "oracle.yaml"))
		if err != nil {
			return nil, fmt.Errorf("%s oracle: %w", entry.Name(), err)
		}
		if err := json.Unmarshal(b, &o); err != nil {
			return nil, fmt.Errorf("%s oracle: %w", entry.Name(), err)
		}
		c := Case{ID: o.ID, Weakness: o.Weakness, PrimaryFile: o.PrimaryFile, PrimaryFunction: o.PrimaryFunction, MatchTerms: o.MatchTerms, RequiredEvidence: o.RequiredEvidence, FixedEvidence: o.FixedEvidence, TWEFamily: o.TWEFamily}
		c.Documents = append(c.Documents, Document{CaseID: c.ID, Kind: "oracle", Text: strings.Join(append([]string{o.Weakness, o.PrimaryFile, o.PrimaryFunction}, append(o.MatchTerms, o.RequiredEvidence...)...), " "), File: o.PrimaryFile, Function: o.PrimaryFunction})
		for _, variant := range []string{"vulnerable", "fixed"} {
			path := filepath.Join(root, variant, filepath.FromSlash(o.PrimaryFile))
			code, err := os.ReadFile(path)
			if err != nil {
				return nil, fmt.Errorf("%s %s source: %w", c.ID, variant, err)
			}
			if len(code) > 20000 {
				code = code[:20000]
			}
			c.Documents = append(c.Documents, Document{CaseID: c.ID, Kind: "code", Text: string(code), File: o.PrimaryFile, Function: o.PrimaryFunction, Variant: variant})
		}
		if patch, err := os.ReadFile(filepath.Join(root, "patches", "fix.patch")); err == nil {
			if len(patch) > 20000 {
				patch = patch[:20000]
			}
			c.Documents = append(c.Documents, Document{CaseID: c.ID, Kind: "patch", Text: string(patch), File: o.PrimaryFile, Function: o.PrimaryFunction, Variant: "diff"})
		}
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func Retrieve(cases []Case, report Report, limit int) []Hit {
	if limit <= 0 {
		limit = 5
	}
	query := strings.Join(reportText(report), " ")
	qt := tokenSet(query)
	var hits []Hit
	for _, c := range cases {
		docText := strings.Join(func() []string {
			var x []string
			for _, d := range c.Documents {
				if d.Kind == "oracle" {
					x = append(x, d.Text)
				}
			}
			return x
		}(), " ")
		dt := tokenSet(docText)
		common := 0
		for t := range qt {
			if dt[t] {
				common++
			}
		}
		fileBoost := 0.0
		for _, f := range reportFiles(report) {
			if strings.EqualFold(filepath.ToSlash(f), filepath.ToSlash(c.PrimaryFile)) {
				fileBoost = 3
				break
			}
		}
		score := float64(common) + fileBoost
		if score > 0 {
			hits = append(hits, Hit{CaseID: c.ID, Score: score, Case: c})
		}
	}
	sort.Slice(hits, func(i, j int) bool {
		if hits[i].Score == hits[j].Score {
			return hits[i].CaseID < hits[j].CaseID
		}
		return hits[i].Score > hits[j].Score
	})
	if len(hits) > limit {
		hits = hits[:limit]
	}
	return hits
}

func reportText(r Report) []string {
	var out []string
	for _, f := range r.Findings {
		out = append(out, f.Summary, strings.Join(f.Files, " "), strings.Join(f.Evidence, " "))
	}
	return out
}
func reportFiles(r Report) []string {
	var out []string
	for _, f := range r.Findings {
		out = append(out, f.Files...)
	}
	return out
}
func tokenSet(s string) map[string]bool {
	out := map[string]bool{}
	for _, t := range tokenRE.FindAllString(strings.ToLower(s), -1) {
		out[t] = true
	}
	return out
}
