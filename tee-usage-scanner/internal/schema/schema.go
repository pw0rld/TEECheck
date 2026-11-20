// Package schema binds the eight canonical TEECheck data contracts (§9 of
// the merge design) to their JSON Schema definitions and provides the one
// runtime gate LLM-produced or otherwise untrusted JSON must pass before the
// rest of the Go pipeline treats it as an ArchitectureModel,
// ProjectInvariant, TWEKnowledgeManifest, TWEPlaybook, ToolFact,
// TWEInvestigation, or UnifiedFinding.
//
// The schemas/ directory at the repository root is the single source of
// truth; it sits outside this Go module (the module root is
// tee-usage-scanner/), and //go:embed cannot reach outside its module via a
// ".." path, so a byte-identical copy is vendored under
// internal/schema/schemas/. TestEmbeddedSchemasMatchCanonical in
// schema_test.go compares every embedded file against the repository-root
// original on every test run, so the copy cannot silently drift into a
// second, disagreeing definition — the failure mode this package exists to
// prevent in the first place. A symlink was considered instead of a copy,
// but go:embed does not reliably follow symlinks that point outside the
// module tree across platforms/toolchains, and a copy plus an equality test
// is simpler to reason about than relying on that behavior.
package schema

import (
	"bytes"
	"embed"
	"fmt"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

//go:embed schemas/*.json
var embedded embed.FS

// Name identifies one of the canonical contracts by its schema file
// basename (without the .json extension).
type Name string

const (
	CaseInvariantV2        Name = "case-invariant.v2"
	InvariantAssessmentV1  Name = "invariant-assessment.v1"
	ArchitectureV1         Name = "architecture.v1"
	RepoFactsV1            Name = "repo-facts.v1"
	ProjectMapV1           Name = "project-map.v1"
	ProjectInvariantV1     Name = "project-invariant.v1"
	TWEKnowledgeManifestV1 Name = "twe-knowledge-manifest.v1"
	TWEPlaybookV1          Name = "twe-playbook.v1"
	TrustIRToolV1          Name = "trustir-tool.v1"
	TWEInvestigationV1     Name = "twe-investigation.v1"
	FindingsV2             Name = "findings.v2"
	FindingV3              Name = "finding.v3"
)

// All lists every canonical schema name this package compiles and validates
// against. Keep in sync with the schema files under schemas/ — a mismatch is
// caught by TestEmbeddedSchemasMatchCanonical.
var All = []Name{
	CaseInvariantV2, InvariantAssessmentV1,
	ArchitectureV1,
	RepoFactsV1,
	ProjectMapV1,
	ProjectInvariantV1,
	TWEKnowledgeManifestV1,
	TWEPlaybookV1,
	TrustIRToolV1,
	TWEInvestigationV1,
	FindingsV2,
	FindingV3,
}

var (
	registryOnce sync.Once
	registry     map[Name]*jsonschema.Schema
	registryErr  error
)

// compiled lazily compiles every embedded schema exactly once. Compilation
// resolves each schema's own "$id" as its canonical resource URL, so
// internal $ref use (e.g. architecture.v1.json's element/relation $defs)
// resolves the same way here as it would for any other draft-2020-12
// consumer of schemas/.
func compiled() (map[Name]*jsonschema.Schema, error) {
	registryOnce.Do(func() {
		c := jsonschema.NewCompiler()
		ids := make(map[Name]string, len(All))
		for _, name := range All {
			data, err := embedded.ReadFile("schemas/" + string(name) + ".json")
			if err != nil {
				registryErr = fmt.Errorf("read embedded schema %s: %w", name, err)
				return
			}
			doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
			if err != nil {
				registryErr = fmt.Errorf("parse embedded schema %s: %w", name, err)
				return
			}
			id, ok := schemaID(doc)
			if !ok {
				registryErr = fmt.Errorf("embedded schema %s: missing string $id", name)
				return
			}
			if err := c.AddResource(id, doc); err != nil {
				registryErr = fmt.Errorf("register schema %s (%s): %w", name, id, err)
				return
			}
			ids[name] = id
		}
		if registryErr != nil {
			return
		}
		out := make(map[Name]*jsonschema.Schema, len(All))
		for _, name := range All {
			sch, err := c.Compile(ids[name])
			if err != nil {
				registryErr = fmt.Errorf("compile schema %s: %w", name, err)
				return
			}
			out[name] = sch
		}
		registry = out
	})
	return registry, registryErr
}

func schemaID(doc any) (string, bool) {
	obj, ok := doc.(map[string]any)
	if !ok {
		return "", false
	}
	id, ok := obj["$id"].(string)
	return id, ok && id != ""
}

// Validate checks data — typically the output of json.Marshal on a canonical
// Go struct, or raw agent/tool JSON — against the named schema. It is the
// single point where LLM output is trusted or rejected before the rest of
// the pipeline treats it as a canonical artifact.
func Validate(name Name, data []byte) error {
	schemas, err := compiled()
	if err != nil {
		return err
	}
	sch, ok := schemas[name]
	if !ok {
		return fmt.Errorf("unknown schema %q", name)
	}
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("decode instance for schema %s: %w", name, err)
	}
	return sch.Validate(inst)
}
