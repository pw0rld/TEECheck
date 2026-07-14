// Package twexpert is the LLM front of the TWE pipeline: it asks the model to
// LOCATE the TrustIR roles a TWE requires in source code. The model only points
// at code — which lines play which roles — it never decides whether a
// vulnerability exists. That decision is made downstream by CodeQL and the
// solver. This is the "fill in the blanks" contract: the model fills a fixed
// form, it does not render a verdict.
package twexpert

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/agentutil"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/twe"
)

const systemPrompt = "You are TEECheck's TrustIR extraction agent. Your only job is to LOCATE " +
	"code roles for a TEE weakness entry: say which source line plays each role. " +
	"You do NOT decide whether a vulnerability exists — that is judged later by a " +
	"static analyzer. Return exactly one JSON object and nothing else."

// ExtractCandidate asks the model to fill the TWE's required TrustIR roles from
// the given source file. The returned candidate is NOT yet validated against
// the catalog; the caller validates it (workflow step 8, the deterministic
// gate). Roles the model cannot locate are simply absent, which validation
// will then reject.
func ExtractCandidate(ctx context.Context, client llm.Client, entry twe.Entry, path, source string, temperature float64) (twe.TrustIRCandidate, error) {
	resp, err := client.Generate(ctx, llm.GenerateRequest{
		SystemPrompt: systemPrompt,
		Messages:     []llm.Message{{Role: "user", Content: buildPrompt(entry, path, source)}},
		Temperature:  temperature,
		JSONMode:     true,
	})
	if err != nil {
		return twe.TrustIRCandidate{}, err
	}

	var parsed struct {
		SiteID string `json:"site_id"`
		Roles  map[string]struct {
			Enum   string `json:"enum"`
			Path   string `json:"path"`
			Line   int    `json:"line"`
			Symbol string `json:"symbol"`
		} `json:"roles"`
	}
	if err := agentutil.UnmarshalJSONObject(resp.Text, &parsed); err != nil {
		return twe.TrustIRCandidate{}, fmt.Errorf("parse expert json: %w", err)
	}

	cand := twe.TrustIRCandidate{TWEID: entry.ID, SiteID: parsed.SiteID}
	if strings.TrimSpace(cand.SiteID) == "" {
		cand.SiteID = entry.ID + "-site"
	}
	cand.Roles = make(map[string]twe.RoleCandidate, len(parsed.Roles))
	for role, r := range parsed.Roles {
		loc := twe.Loc{Path: r.Path, Line: r.Line, Symbol: r.Symbol}
		if strings.TrimSpace(loc.Path) == "" {
			loc.Path = path
		}
		cand.Roles[role] = twe.RoleCandidate{Enum: r.Enum, Loc: loc}
	}
	return cand, nil
}

func buildPrompt(entry twe.Entry, path, source string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Weakness %s (%s): %s\n\n", entry.ID, entry.Family, strings.TrimSpace(entry.Summary))
	fmt.Fprintf(&b, "In the file %s, locate each of these roles. Give the 1-based line number, the\n", path)
	b.WriteString("symbol at that location, and pick exactly one enum from the role's allowed list.\n")
	b.WriteString("For a role that names an attested field, the symbol should be the exact field\n")
	b.WriteString("access that holds the attested value (for example a verified report's key field).\n\n")
	b.WriteString("Roles and allowed enums:\n")
	for _, role := range entry.RequiredTrustIR {
		enums := entry.AllowedEnums[role]
		sort.Strings(enums)
		if len(enums) > 0 {
			fmt.Fprintf(&b, "  - %s: [%s]\n", role, strings.Join(enums, ", "))
		} else {
			fmt.Fprintf(&b, "  - %s\n", role)
		}
	}
	b.WriteString("\nReturn JSON exactly in this shape (omit a role you cannot find):\n")
	b.WriteString("{\n")
	b.WriteString("  \"site_id\": \"<short id>\",\n")
	b.WriteString("  \"roles\": {\n")
	b.WriteString("    \"<role>\": { \"enum\": \"<one allowed enum>\", \"path\": \"" + path + "\", \"line\": <int>, \"symbol\": \"<code symbol>\" }\n")
	b.WriteString("  }\n")
	b.WriteString("}\n\n")
	b.WriteString("Do not judge exploitability. Only locate the roles.\n\n")
	fmt.Fprintf(&b, "Source (%s), line-numbered:\n", path)
	for i, line := range strings.Split(source, "\n") {
		fmt.Fprintf(&b, "%d: %s\n", i+1, line)
	}
	return b.String()
}
