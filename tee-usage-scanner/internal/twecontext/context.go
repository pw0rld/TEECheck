// Package twecontext loads experience-oriented TWE playbooks and compiles the
// complete catalog into compact prior knowledge shared by security agents.
// It intentionally does not perform retrieval or project-based selection.
//
// Playbook context is two-tiered: a brief tier (scenario, look_for) is
// compiled into every agent's prompt by Compile, and a detail tier (the full
// investigation method) is served on demand, per TWE id, by Detail — see the
// Planner's twe_playbook_detail action. Each tier enforces its own token
// ceiling as a hard failure rather than a silent truncation: Compile rejects
// an oversized brief block at compile time (maxBriefContextTokens), and
// Load's Validate step rejects an oversized detail block at load time
// (maxDetailContextTokens). Both ceilings exist for the same reason: the
// cost of either tier is multiplied across every place it is injected, so a
// playbook that has grown too large must block the run, not silently shrink
// into a truncated context.
package twecontext

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/twe"
	"gopkg.in/yaml.v3"
)

const SchemaVersion = "teecheck.twe_playbook.v1"

var tweIDPattern = regexp.MustCompile(`^TWE-[A-Z0-9-]+$`)

// maxBriefContextTokens bounds the tier that is injected into EVERY agent
// (Planner, Architecture, Invariant, Expert, Challenger, Verifier, Arbiter),
// for every playbook, on every LLM call. That multiplier is why this tier
// carries only what an agent needs to judge relevance — scenario and
// look_for. Measured: rollback.yml's brief is ~213 tokens.
const maxBriefContextTokens = 250

// maxDetailContextTokens bounds the tier the Planner pulls on demand via the
// twe_playbook_detail action. It is paid for only when an agent asks for a
// specific TWE, so it can afford the real investigation method: concrete API
// names, code patterns, and the reasoning behind each defense. Measured:
// rollback.yml's detail is ~720 tokens, leaving room to grow ~4x.
const maxDetailContextTokens = 3000

// estimateTokens approximates an LLM token count from raw text without a
// tokenizer dependency. ~4 characters per token is the standard
// order-of-magnitude heuristic for English technical prose. Rounding up means
// the budget check can only be stricter than a real tokenizer's count, never
// looser — the ceiling must never pass something a real tokenizer would
// reject.
func estimateTokens(s string) int {
	return (len(s) + 3) / 4
}

// Playbook is prior audit knowledge for reasoning agents. Unlike the legacy
// executable TWE Entry, it expresses a weakness scenario and an investigation
// method without binding the knowledge to CodeQL or another tool.
type Playbook struct {
	SchemaVersion        string        `yaml:"schema_version" json:"schema_version"`
	ID                   string        `yaml:"id" json:"id"`
	Name                 string        `yaml:"name" json:"name"`
	Family               twe.Family    `yaml:"family" json:"family"`
	Scenario             string        `yaml:"scenario" json:"scenario"`
	AttackerCapabilities []string      `yaml:"attacker_capabilities" json:"attacker_capabilities"`
	LookFor              []string      `yaml:"look_for" json:"look_for"`
	InvestigationSteps   []string      `yaml:"investigation_steps" json:"investigation_steps"`
	RequiredEvidence     []string      `yaml:"required_evidence" json:"required_evidence"`
	CommonDefenses       []string      `yaml:"common_defenses" json:"common_defenses"`
	CommonFalsePositives []string      `yaml:"common_false_positives" json:"common_false_positives"`
	RelatedTWEs          []string      `yaml:"related_twes" json:"related_twes"`
	TrustIRHints         []string      `yaml:"trustir_hints" json:"trustir_hints"`
	CodeExamples         []CodeExample `yaml:"code_examples,omitempty" json:"code_examples,omitempty"`
}

// CodeExample is a CVE-grounded vulnerable/fixed code pair that teaches the
// model what this TWE looks like in real code. It is served only in the detail
// tier (on demand via the twe_playbook_detail action), never in the brief
// tier: source snippets are too large for the per-playbook brief ceiling and
// must not be multiplied across every agent call.
type CodeExample struct {
	CVE        string `yaml:"cve" json:"cve"`
	CWE        string `yaml:"cwe" json:"cwe"`
	Title      string `yaml:"title" json:"title"`
	Vulnerable string `yaml:"vulnerable" json:"vulnerable"`
	Fixed      string `yaml:"fixed" json:"fixed"`
	Fix        string `yaml:"fix" json:"fix"`
	Why        string `yaml:"why" json:"why"`
}

type Catalog struct {
	playbooks     []Playbook
	catalogSHA256 string
}

// Compiled is the exact context injected into agents and its reproducibility
// metadata. All playbooks are included; no project profile filters this set.
//
// ContextTokenEstimate is the whole-catalog counterpart of the per-playbook
// ceiling Compile enforces (§11.1, §9.4). It is mirrored into Manifest so the
// number survives into the persisted run artifact, not just this struct.
type Compiled struct {
	Text                 string
	ContextTokenEstimate int
	Manifest             artifacts.TWEKnowledgeManifest
}

func Load(dir string) (*Catalog, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read TWE playbook dir %s: %w", dir, err)
	}
	var paths []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		ext := strings.ToLower(filepath.Ext(entry.Name()))
		if ext == ".yml" || ext == ".yaml" {
			paths = append(paths, filepath.Join(dir, entry.Name()))
		}
	}
	sort.Strings(paths)

	byID := make(map[string]Playbook, len(paths))
	for _, path := range paths {
		playbook, err := loadPlaybook(path)
		if err != nil {
			return nil, err
		}
		if _, exists := byID[playbook.ID]; exists {
			return nil, fmt.Errorf("duplicate TWE playbook id %q (%s)", playbook.ID, path)
		}
		byID[playbook.ID] = playbook
	}
	if len(byID) == 0 {
		return nil, fmt.Errorf("TWE playbook dir %s contains no YAML playbooks", dir)
	}

	playbooks := make([]Playbook, 0, len(byID))
	for _, playbook := range byID {
		playbooks = append(playbooks, playbook)
	}
	sort.Slice(playbooks, func(i, j int) bool { return playbooks[i].ID < playbooks[j].ID })
	canonical, err := json.Marshal(playbooks)
	if err != nil {
		return nil, fmt.Errorf("encode canonical TWE catalog: %w", err)
	}
	return &Catalog{playbooks: playbooks, catalogSHA256: digest(canonical)}, nil
}

func loadPlaybook(path string) (Playbook, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Playbook{}, fmt.Errorf("read %s: %w", path, err)
	}
	var playbook Playbook
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(&playbook); err != nil {
		return Playbook{}, fmt.Errorf("parse %s: %w", path, err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return Playbook{}, fmt.Errorf("parse %s: multiple YAML documents are not allowed", path)
		}
		return Playbook{}, fmt.Errorf("parse %s: %w", path, err)
	}
	if err := playbook.Validate(); err != nil {
		return Playbook{}, fmt.Errorf("invalid TWE playbook in %s: %w", path, err)
	}
	return playbook, nil
}

func (p Playbook) Validate() error {
	if p.SchemaVersion != SchemaVersion {
		return fmt.Errorf("%s: schema_version must be %q", p.ID, SchemaVersion)
	}
	if strings.TrimSpace(p.ID) == "" {
		return fmt.Errorf("id is required")
	}
	if !tweIDPattern.MatchString(p.ID) {
		return fmt.Errorf("%s: id must match %s", p.ID, tweIDPattern)
	}
	if strings.TrimSpace(p.Name) == "" {
		return fmt.Errorf("%s: name is required", p.ID)
	}
	if !twe.ValidFamilies[p.Family] {
		return fmt.Errorf("%s: unknown family %q", p.ID, p.Family)
	}
	if strings.TrimSpace(p.Scenario) == "" {
		return fmt.Errorf("%s: scenario is required", p.ID)
	}
	lists := []struct {
		name   string
		values []string
	}{
		{"attacker_capabilities", p.AttackerCapabilities},
		{"look_for", p.LookFor},
		{"investigation_steps", p.InvestigationSteps},
		{"required_evidence", p.RequiredEvidence},
		{"common_defenses", p.CommonDefenses},
		{"common_false_positives", p.CommonFalsePositives},
		{"trustir_hints", p.TrustIRHints},
	}
	for _, list := range lists {
		if err := validateList(p.ID, list.name, list.values, true); err != nil {
			return err
		}
	}
	if err := validateList(p.ID, "related_twes", p.RelatedTWEs, false); err != nil {
		return err
	}
	for _, related := range p.RelatedTWEs {
		if !tweIDPattern.MatchString(related) {
			return fmt.Errorf("%s: related_twes contains invalid id %q", p.ID, related)
		}
	}
	for i, ex := range p.CodeExamples {
		// Every field twe-playbook.v1.json marks required is enforced here
		// too (cwe is optional and so unchecked). Load-time validation must
		// not be weaker than the schema, or an exemplar that fails the schema
		// could still load and ship to agents.
		for _, field := range []struct {
			name, value string
		}{
			{"cve", ex.CVE},
			{"title", ex.Title},
			{"vulnerable", ex.Vulnerable},
			{"fixed", ex.Fixed},
			{"fix", ex.Fix},
			{"why", ex.Why},
		} {
			if strings.TrimSpace(field.value) == "" {
				return fmt.Errorf("%s: code_examples[%d].%s is required", p.ID, i, field.name)
			}
		}
	}
	if tokens := estimateTokens(compileDetailBlock(p)); tokens > maxDetailContextTokens {
		return fmt.Errorf(
			"%s: detail context is ~%d tokens, which exceeds the %d-token ceiling; shrink the playbook — this is checked at load so an oversized playbook fails during preprocess, not when an agent pulls it",
			p.ID, tokens, maxDetailContextTokens,
		)
	}
	return nil
}

func validateList(id, name string, values []string, required bool) error {
	if required && len(values) == 0 {
		return fmt.Errorf("%s: %s must be non-empty", id, name)
	}
	seen := make(map[string]bool, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			return fmt.Errorf("%s: %s contains an empty value", id, name)
		}
		if seen[value] {
			return fmt.Errorf("%s: %s contains duplicate %q", id, name, value)
		}
		seen[value] = true
	}
	return nil
}

func (c *Catalog) All() []Playbook {
	out := make([]Playbook, len(c.playbooks))
	for i, playbook := range c.playbooks {
		out[i] = clonePlaybook(playbook)
	}
	return out
}

// Detail returns the full rendering of one playbook. ok is false when no
// playbook carries that TWE id — callers surface that as an explicit miss
// rather than an empty result, so an agent never reads "no text" as "no
// weakness".
func (c *Catalog) Detail(tweID string) (string, bool) {
	for _, p := range c.playbooks {
		if p.ID == tweID {
			return compileDetailBlock(p), true
		}
	}
	return "", false
}

func clonePlaybook(p Playbook) Playbook {
	p.AttackerCapabilities = cloneStrings(p.AttackerCapabilities)
	p.LookFor = cloneStrings(p.LookFor)
	p.InvestigationSteps = cloneStrings(p.InvestigationSteps)
	p.RequiredEvidence = cloneStrings(p.RequiredEvidence)
	p.CommonDefenses = cloneStrings(p.CommonDefenses)
	p.CommonFalsePositives = cloneStrings(p.CommonFalsePositives)
	p.RelatedTWEs = cloneStrings(p.RelatedTWEs)
	p.TrustIRHints = cloneStrings(p.TrustIRHints)
	p.CodeExamples = cloneCodeExamples(p.CodeExamples)
	return p
}

func cloneCodeExamples(in []CodeExample) []CodeExample {
	if in == nil {
		return nil
	}
	out := make([]CodeExample, len(in))
	copy(out, in)
	return out
}

// cloneStrings copies s into an independent slice. Unlike
// append([]string(nil), s...), it preserves a non-nil-but-empty s as
// non-nil: RelatedTWEs is schema-optional but, when present, must marshal
// as `[]`, not `null` — twe-playbook.v1.json requires the key but not a
// minimum length, and json.Marshal renders a nil slice as `null`, which
// fails the schema's "type": "array" check.
func cloneStrings(s []string) []string {
	out := make([]string, len(s))
	copy(out, s)
	return out
}

const contextHeader = "TWE PRIOR KNOWLEDGE (complete catalog, brief tier; apply every relevant playbook, do not treat it as a finding; the full investigation method for a TWE is available to the Planner on request.)\n"

// Compile renders the full playbook catalog into one compact Agent context.
// It fails, rather than truncating, if any single playbook's brief block
// exceeds maxBriefContextTokens — see that constant's comment for why a
// per-playbook ceiling exists and how it was chosen.
func (c *Catalog) Compile() (Compiled, error) {
	var out strings.Builder
	out.WriteString(contextHeader)
	for _, p := range c.playbooks {
		block := compileBriefBlock(p)
		if tokens := estimateTokens(block); tokens > maxBriefContextTokens {
			return Compiled{}, fmt.Errorf(
				"%s: brief context is ~%d tokens (%d chars), which exceeds the %d-token compile-time ceiling; shrink the playbook's scenario or look_for — Compile must fail closed here, not truncate",
				p.ID, tokens, len(block), maxBriefContextTokens,
			)
		}
		out.WriteString(block)
	}
	text := out.String()
	ids := make([]string, 0, len(c.playbooks))
	for _, p := range c.playbooks {
		ids = append(ids, p.ID)
	}
	total := estimateTokens(text)
	return Compiled{
		Text:                 text,
		ContextTokenEstimate: total,
		Manifest: artifacts.TWEKnowledgeManifest{
			SchemaVersion:        "teecheck.twe_knowledge_manifest.v1",
			CatalogVersion:       SchemaVersion,
			CatalogSHA256:        c.catalogSHA256,
			ContextSHA256:        digest([]byte(text)),
			TWEIDs:               ids,
			ContextTokenEstimate: total,
		},
	}, nil
}

// compileBriefBlock renders the always-injected tier: enough for an agent to
// decide whether this weakness family is relevant to the code in front of it,
// and nothing more. The full method lives in compileDetailBlock.
func compileBriefBlock(p Playbook) string {
	var b strings.Builder
	fmt.Fprintf(&b, "\n[%s] %s | family=%s\n", p.ID, p.Name, p.Family)
	writeField(&b, "Scenario", []string{p.Scenario})
	writeField(&b, "Look for", p.LookFor)
	return b.String()
}

// compileDetailBlock renders one playbook's full context block, carrying
// every field. Compile measures and appends brief blocks one at a time —
// rather than assembling the whole document and measuring the total — so the
// ceiling attributes cleanly to the one playbook that is too large instead of
// to "the catalog" in aggregate; Detail and Validate reuse this renderer for
// the on-demand detail tier.
func compileDetailBlock(p Playbook) string {
	var b strings.Builder
	fmt.Fprintf(&b, "\n[%s] %s | family=%s\n", p.ID, p.Name, p.Family)
	writeField(&b, "Scenario", []string{p.Scenario})
	writeField(&b, "Attacker", p.AttackerCapabilities)
	writeField(&b, "Look for", p.LookFor)
	writeField(&b, "Investigate", p.InvestigationSteps)
	writeField(&b, "Evidence required", p.RequiredEvidence)
	writeField(&b, "Defenses", p.CommonDefenses)
	writeField(&b, "False positives", p.CommonFalsePositives)
	writeField(&b, "Related", p.RelatedTWEs)
	writeField(&b, "Tool hints", p.TrustIRHints)
	writeCodeExamples(&b, p.CodeExamples)
	return b.String()
}

// writeCodeExamples renders CVE-grounded code pairs verbatim (no whitespace
// folding — the source layout is the point) under the detail tier only. The
// detail-tier ceiling (maxDetailContextTokens) is enforced by Validate on the
// whole compileDetailBlock output, so an oversized example set fails the run
// closed at load time rather than being silently truncated.
func writeCodeExamples(out *strings.Builder, examples []CodeExample) {
	if len(examples) == 0 {
		return
	}
	out.WriteString("Code examples:\n")
	for _, ex := range examples {
		cwe := strings.TrimSpace(ex.CWE)
		if cwe != "" {
			fmt.Fprintf(out, "  - %s (%s): %s\n", ex.CVE, cwe, strings.TrimSpace(ex.Title))
		} else {
			fmt.Fprintf(out, "  - %s: %s\n", ex.CVE, strings.TrimSpace(ex.Title))
		}
		out.WriteString("    vulnerable:\n")
		out.WriteString(indentBlock(ex.Vulnerable, "      "))
		out.WriteString("    fixed:\n")
		out.WriteString(indentBlock(ex.Fixed, "      "))
		fmt.Fprintf(out, "    fix: %s\n", strings.Join(strings.Fields(ex.Fix), " "))
		fmt.Fprintf(out, "    why: %s\n", strings.Join(strings.Fields(ex.Why), " "))
	}
}

// indentBlock prefixes every line of s with pad. Code examples are rendered
// verbatim, so unlike writeField the interior whitespace and newlines are
// preserved.
func indentBlock(s, pad string) string {
	trimmed := strings.TrimRight(s, "\n")
	if trimmed == "" {
		return ""
	}
	lines := strings.Split(trimmed, "\n")
	for i, line := range lines {
		lines[i] = pad + line
	}
	return strings.Join(lines, "\n") + "\n"
}

func writeField(out *strings.Builder, label string, values []string) {
	if len(values) == 0 {
		return
	}
	normalized := make([]string, len(values))
	for i, value := range values {
		normalized[i] = strings.Join(strings.Fields(value), " ")
	}
	fmt.Fprintf(out, "%s: %s\n", label, strings.Join(normalized, "; "))
}

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
