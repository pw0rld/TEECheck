package codeql

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/twe"
)

// WriteQueryPack writes a generated query into destDir as a minimal CodeQL
// query pack: the .ql file plus a qlpack.yml declaring the codeql/rust-all
// dependency. Combined with AnalyzeOptions.AdditionalPacks pointing at a
// bundle's resolved rust libraries (see RustLibrariesPath), `import rust`
// resolves offline. Returns the path to the written query file.
func WriteQueryPack(destDir, fileName, queryContent string) (string, error) {
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return "", err
	}
	qlpack := "name: teecheck/generated\nversion: 0.0.1\ndependencies:\n  codeql/rust-all: \"*\"\n"
	if err := os.WriteFile(filepath.Join(destDir, "qlpack.yml"), []byte(qlpack), 0o644); err != nil {
		return "", err
	}
	queryPath := filepath.Join(destDir, fileName)
	if err := os.WriteFile(queryPath, []byte(queryContent), 0o644); err != nil {
		return "", err
	}
	return queryPath, nil
}

// GenerateBindingQuery emits a self-contained CodeQL query for one TWE-BIND
// site. Unlike a static hand-written module, the query is derived from the
// TrustIR the LLM produced: the authority function is located by the
// authority_subject role's source position, and the attested field to look for
// comes from the claim_field role's symbol. Nothing about the target code
// (function names, field names) is hardcoded in the module — it all flows in
// from TrustIR, which is the point of query generation.
//
// The binding relation is the one proven to discriminate in the M2 spike: a
// violation is a function holding the authority point that never references the
// attested field. Hardening this to full inter-procedural data flow is future
// work — the spike found Rust content-flow (tracking a value through a field
// read) needs more modeling than DataFlow::localFlow gives out of the box.
func GenerateBindingQuery(cand twe.TrustIRCandidate) (string, error) {
	claim, ok := cand.Roles["claim_field"]
	if !ok {
		return "", fmt.Errorf("candidate %s: missing role claim_field", cand.SiteID)
	}
	authority, ok := cand.Roles["authority_subject"]
	if !ok {
		return "", fmt.Errorf("candidate %s: missing role authority_subject", cand.SiteID)
	}
	field := attestedFieldName(claim.Loc.Symbol)
	if field == "" {
		return "", fmt.Errorf("candidate %s: cannot derive attested field name from claim symbol %q", cand.SiteID, claim.Loc.Symbol)
	}
	authFile := filepath.Base(authority.Loc.Path)
	if authFile == "" || authFile == "." || authority.Loc.Line <= 0 {
		return "", fmt.Errorf("candidate %s: authority_subject needs a file and line", cand.SiteID)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "/**\n")
	fmt.Fprintf(&b, " * @name TWE-BIND-001 generated for %s\n", cand.SiteID)
	fmt.Fprintf(&b, " * @description Authority granted at %s:%d without an accepted binding to the attested field %q.\n", authFile, authority.Loc.Line, field)
	fmt.Fprintf(&b, " * @kind problem\n")
	fmt.Fprintf(&b, " * @problem.severity error\n")
	fmt.Fprintf(&b, " * @id teecheck/generated/binding/%s\n", sanitizeID(cand.SiteID))
	fmt.Fprintf(&b, " * @tags security\n")
	fmt.Fprintf(&b, " */\n\n")
	b.WriteString("import rust\n\n")
	b.WriteString("from Function f\n")
	b.WriteString("where\n")
	fmt.Fprintf(&b, "  // authority point located by TrustIR: %s:%d\n", authFile, authority.Loc.Line)
	b.WriteString("  exists(AstNode a |\n")
	b.WriteString("    a.getEnclosingCallable() = f and\n")
	fmt.Fprintf(&b, "    a.getLocation().getFile().getBaseName() = %q and\n", authFile)
	fmt.Fprintf(&b, "    a.getLocation().getStartLine() = %d\n", authority.Loc.Line)
	b.WriteString("  ) and\n")
	fmt.Fprintf(&b, "  // no reference to the attested field %q on the authority path\n", field)
	b.WriteString("  not exists(FieldExpr fe |\n")
	b.WriteString("    fe.getEnclosingCallable() = f and\n")
	fmt.Fprintf(&b, "    fe.getIdentifier().getText() = %q\n", field)
	b.WriteString("  )\n")
	// Surface the function name CodeQL resolved so downstream matching and
	// review can name the code element, not just its location.
	fmt.Fprintf(&b, "select f, \"TWE-BIND-001: \" + f.getName().getText() + \" grants authority without binding to attested field '%s' (%s)\"\n", field, cand.SiteID)
	return b.String(), nil
}

// attestedFieldName pulls the field name out of a claim symbol like
// "report.pubkey" (-> "pubkey") or a bare "pubkey" (-> "pubkey").
func attestedFieldName(symbol string) string {
	s := strings.TrimSpace(symbol)
	if s == "" {
		return ""
	}
	if i := strings.LastIndex(s, "."); i >= 0 {
		s = s[i+1:]
	}
	return strings.TrimSpace(s)
}

// sanitizeID makes a site id safe for a CodeQL @id (lowercase, hyphen-joined).
func sanitizeID(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	return strings.Trim(b.String(), "-")
}
