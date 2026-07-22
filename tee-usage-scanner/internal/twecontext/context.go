// Package twecontext loads experience-oriented TWE playbooks and compiles the
// complete catalog into compact prior knowledge shared by security agents.
// It intentionally does not perform retrieval or project-based selection.
// Compile enforces a per-playbook token ceiling as a compile-time hard
// failure (§11.1, §20.4) — the catalog cost is multiplied across every
// injection point, so a playbook that has grown too large must block the
// run, not silently shrink into a truncated context.
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

// maxPlaybookContextTokens is the compile-time hard limit on a single
// playbook's compact context block (§11.1, §20.4 of the merge design). 16
// playbooks land in 6 agent injection points (Planner, Architecture,
// Invariant, Expert, Challenger, Verifier), so a single playbook growing is a
// 6x cost multiplier before a second playbook is even added — this bound
// exists to catch that growth at compile time, as a hard failure, rather than
// let Compile silently truncate the offending playbook or let the multiplied
// cost show up later as a token bill.
//
// Measured: knowledge/twe/playbooks/rollback.yml — the only playbook shipped
// so far, and the only one required to cover two distinct attack shapes
// instead of one (§8.9, §20.2) — compiles to ~720 tokens (2877 chars at the
// ~4-chars-per-token estimate below). 900 leaves ~25% headroom for a
// legitimately more detailed playbook while still failing closed on anything
// that has drifted into prose.
const maxPlaybookContextTokens = 900

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
	SchemaVersion        string     `yaml:"schema_version" json:"schema_version"`
	ID                   string     `yaml:"id" json:"id"`
	Name                 string     `yaml:"name" json:"name"`
	Family               twe.Family `yaml:"family" json:"family"`
	Scenario             string     `yaml:"scenario" json:"scenario"`
	AttackerCapabilities []string   `yaml:"attacker_capabilities" json:"attacker_capabilities"`
	LookFor              []string   `yaml:"look_for" json:"look_for"`
	InvestigationSteps   []string   `yaml:"investigation_steps" json:"investigation_steps"`
	RequiredEvidence     []string   `yaml:"required_evidence" json:"required_evidence"`
	CommonDefenses       []string   `yaml:"common_defenses" json:"common_defenses"`
	CommonFalsePositives []string   `yaml:"common_false_positives" json:"common_false_positives"`
	RelatedTWEs          []string   `yaml:"related_twes" json:"related_twes"`
	TrustIRHints         []string   `yaml:"trustir_hints" json:"trustir_hints"`
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

func clonePlaybook(p Playbook) Playbook {
	p.AttackerCapabilities = cloneStrings(p.AttackerCapabilities)
	p.LookFor = cloneStrings(p.LookFor)
	p.InvestigationSteps = cloneStrings(p.InvestigationSteps)
	p.RequiredEvidence = cloneStrings(p.RequiredEvidence)
	p.CommonDefenses = cloneStrings(p.CommonDefenses)
	p.CommonFalsePositives = cloneStrings(p.CommonFalsePositives)
	p.RelatedTWEs = cloneStrings(p.RelatedTWEs)
	p.TrustIRHints = cloneStrings(p.TrustIRHints)
	return p
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

const contextHeader = "TWE PRIOR KNOWLEDGE (complete catalog; apply every relevant playbook, do not treat it as a finding)\n"

// Compile renders the full playbook catalog into one compact Agent context.
// It fails, rather than truncating, if any single playbook's compact block
// exceeds maxPlaybookContextTokens — see that constant's comment for why a
// per-playbook ceiling exists and how it was chosen.
func (c *Catalog) Compile() (Compiled, error) {
	var out strings.Builder
	out.WriteString(contextHeader)
	for _, p := range c.playbooks {
		block := compilePlaybookBlock(p)
		if tokens := estimateTokens(block); tokens > maxPlaybookContextTokens {
			return Compiled{}, fmt.Errorf(
				"%s: compact context is ~%d tokens (%d chars), which exceeds the %d-token compile-time ceiling (§11.1); shrink the playbook — TWEContextCompiler must fail closed here, not truncate",
				p.ID, tokens, len(block), maxPlaybookContextTokens,
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

// compilePlaybookBlock renders one playbook's compact context block. Compile
// measures and appends these one at a time — rather than assembling the whole
// document and measuring the total — so the ceiling attributes cleanly to the
// one playbook that is too large instead of to "the catalog" in aggregate.
func compilePlaybookBlock(p Playbook) string {
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
	return b.String()
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
