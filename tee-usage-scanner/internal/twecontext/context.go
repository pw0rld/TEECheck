// Package twecontext loads experience-oriented TWE playbooks and compiles the
// complete catalog into compact prior knowledge shared by security agents.
// It intentionally does not perform retrieval or project-based selection.
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
type Compiled struct {
	Text     string
	Manifest artifacts.TWEKnowledgeManifest
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
	p.AttackerCapabilities = append([]string(nil), p.AttackerCapabilities...)
	p.LookFor = append([]string(nil), p.LookFor...)
	p.InvestigationSteps = append([]string(nil), p.InvestigationSteps...)
	p.RequiredEvidence = append([]string(nil), p.RequiredEvidence...)
	p.CommonDefenses = append([]string(nil), p.CommonDefenses...)
	p.CommonFalsePositives = append([]string(nil), p.CommonFalsePositives...)
	p.RelatedTWEs = append([]string(nil), p.RelatedTWEs...)
	p.TrustIRHints = append([]string(nil), p.TrustIRHints...)
	return p
}

func (c *Catalog) Compile() Compiled {
	var out strings.Builder
	out.WriteString("TWE PRIOR KNOWLEDGE (complete catalog; apply every relevant playbook, do not treat it as a finding)\n")
	for _, p := range c.playbooks {
		fmt.Fprintf(&out, "\n[%s] %s | family=%s\n", p.ID, p.Name, p.Family)
		writeField(&out, "Scenario", []string{p.Scenario})
		writeField(&out, "Attacker", p.AttackerCapabilities)
		writeField(&out, "Look for", p.LookFor)
		writeField(&out, "Investigate", p.InvestigationSteps)
		writeField(&out, "Evidence required", p.RequiredEvidence)
		writeField(&out, "Defenses", p.CommonDefenses)
		writeField(&out, "False positives", p.CommonFalsePositives)
		writeField(&out, "Related", p.RelatedTWEs)
		writeField(&out, "Tool hints", p.TrustIRHints)
	}
	text := out.String()
	ids := make([]string, 0, len(c.playbooks))
	for _, p := range c.playbooks {
		ids = append(ids, p.ID)
	}
	return Compiled{
		Text: text,
		Manifest: artifacts.TWEKnowledgeManifest{
			SchemaVersion:  "teecheck.twe_knowledge_manifest.v1",
			CatalogVersion: SchemaVersion,
			CatalogSHA256:  c.catalogSHA256,
			ContextSHA256:  digest([]byte(text)),
			TWEIDs:         ids,
		},
	}
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
