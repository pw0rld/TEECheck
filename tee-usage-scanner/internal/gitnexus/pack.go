package gitnexus

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type Export struct {
	SourcePath string
	Nodes      []Node
	Edges      []Edge
	Metadata   map[string]any
}

type Node struct {
	ID       string
	Type     string
	Name     string
	Path     string
	File     string
	Language string
	Raw      map[string]any
}

type Edge struct {
	Source string
	Target string
	Type   string
	Raw    map[string]any
}

type KnowledgePack struct {
	SchemaVersion    string            `json:"schema_version"`
	Source           KnowledgeSource   `json:"source"`
	Overview         Overview          `json:"overview"`
	TopNodeTypes     []Count           `json:"top_node_types"`
	TopEdgeTypes     []Count           `json:"top_edge_types"`
	RelevantFiles    []Candidate       `json:"relevant_files"`
	RelevantSymbols  []Candidate       `json:"relevant_symbols"`
	AuditQuestions   []string          `json:"audit_questions"`
	AnalystNotes     []string          `json:"analyst_notes"`
	CompressionHints map[string]string `json:"compression_hints"`
}

type KnowledgeSource struct {
	GraphJSON  string `json:"graph_json"`
	SourcePath string `json:"source_path,omitempty"`
	FocusArea  string `json:"focus_area"`
	NodeCount  int    `json:"node_count"`
	EdgeCount  int    `json:"edge_count"`
}

type Overview struct {
	FocusSummary    string `json:"focus_summary"`
	HotspotSummary  string `json:"hotspot_summary"`
	GraphSummary    string `json:"graph_summary"`
	LimitationsNote string `json:"limitations_note"`
}

type Count struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

type Candidate struct {
	Label  string `json:"label"`
	Type   string `json:"type"`
	Path   string `json:"path,omitempty"`
	Reason string `json:"reason"`
	Score  int    `json:"score"`
}

func LoadExport(path string) (Export, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Export{}, err
	}

	var root map[string]any
	if err := json.Unmarshal(data, &root); err != nil {
		return Export{}, fmt.Errorf("parse graph export: %w", err)
	}

	nodesRaw := objectList(root["nodes"])
	if len(nodesRaw) == 0 {
		if graph, ok := root["graph"].(map[string]any); ok {
			nodesRaw = objectList(graph["nodes"])
		}
	}

	edgesRaw := objectList(root["edges"])
	if len(edgesRaw) == 0 {
		edgesRaw = objectList(root["relationships"])
	}
	if len(edgesRaw) == 0 {
		if graph, ok := root["graph"].(map[string]any); ok {
			edgesRaw = objectList(graph["edges"])
			if len(edgesRaw) == 0 {
				edgesRaw = objectList(graph["relationships"])
			}
		}
	}

	exp := Export{
		SourcePath: stringValue(root, "sourcePath", "source_path", "repoPath", "repo_path"),
		Metadata:   root,
	}
	for _, raw := range nodesRaw {
		exp.Nodes = append(exp.Nodes, normalizeNode(raw))
	}
	for _, raw := range edgesRaw {
		exp.Edges = append(exp.Edges, normalizeEdge(raw))
	}

	return exp, nil
}

func BuildKnowledgePack(graphJSONPath string, exp Export, focus string) KnowledgePack {
	focus = strings.TrimSpace(strings.ToLower(focus))
	if focus == "" {
		focus = "tee"
	}

	nodeTypeCounts := countNames(exp.Nodes, func(n Node) string { return normalizedName(n.Type, "unknown") })
	edgeTypeCounts := countNames(exp.Edges, func(e Edge) string { return normalizedName(e.Type, "unknown") })
	degrees := buildDegreeIndex(exp.Edges)
	files := rankCandidates(exp.Nodes, degrees, focus, true)
	symbols := rankCandidates(exp.Nodes, degrees, focus, false)

	return KnowledgePack{
		SchemaVersion: "teecheck.gitnexus.pack.v1",
		Source: KnowledgeSource{
			GraphJSON:  filepath.ToSlash(graphJSONPath),
			SourcePath: exp.SourcePath,
			FocusArea:  focus,
			NodeCount:  len(exp.Nodes),
			EdgeCount:  len(exp.Edges),
		},
		Overview: Overview{
			FocusSummary:    buildFocusSummary(focus, files, symbols),
			HotspotSummary:  buildHotspotSummary(files, symbols),
			GraphSummary:    fmt.Sprintf("The imported GitNexus graph contains %d nodes and %d edges.", len(exp.Nodes), len(exp.Edges)),
			LimitationsNote: "This MVP consumes exported graph structure and does not yet call a live GitNexus backend. Use it as compressed context for AI review, not as a vulnerability verdict.",
		},
		TopNodeTypes:    topCounts(nodeTypeCounts, 8),
		TopEdgeTypes:    topCounts(edgeTypeCounts, 8),
		RelevantFiles:   files,
		RelevantSymbols: symbols,
		AuditQuestions:  auditQuestionsForFocus(focus),
		AnalystNotes: []string{
			"GitNexus is treated as a structure compressor in this MVP.",
			"Candidates are heuristic hotspots based on graph degree plus focus keywords.",
			"AI should reason over these hotspots together with TEE misuse skills and original code snippets.",
		},
		CompressionHints: map[string]string{
			"intended_ai_role": "Use this pack to understand repository structure, trust boundaries, and likely audit hotspots before reading raw code.",
			"review_mode":      "human_in_the_loop",
		},
	}
}

func objectList(value any) []map[string]any {
	rawList, ok := value.([]any)
	if !ok {
		return nil
	}
	result := make([]map[string]any, 0, len(rawList))
	for _, item := range rawList {
		if obj, ok := item.(map[string]any); ok {
			result = append(result, obj)
		}
	}
	return result
}

func normalizeNode(raw map[string]any) Node {
	path := stringValue(raw, "path", "filepath", "uri", "location")
	file := stringValue(raw, "file", "filepath", "path", "uri")
	return Node{
		ID:       stringValue(raw, "id", "key", "uid"),
		Type:     stringValue(raw, "type", "kind", "label", "nodeType", "__typename"),
		Name:     stringValue(raw, "name", "label", "symbol", "title", "fullName"),
		Path:     path,
		File:     file,
		Language: stringValue(raw, "language", "lang"),
		Raw:      raw,
	}
}

func normalizeEdge(raw map[string]any) Edge {
	return Edge{
		Source: stringValue(raw, "source", "from", "start", "src"),
		Target: stringValue(raw, "target", "to", "end", "dst"),
		Type:   stringValue(raw, "type", "kind", "label", "relationshipType"),
		Raw:    raw,
	}
}

func stringValue(obj map[string]any, keys ...string) string {
	for _, key := range keys {
		value, ok := obj[key]
		if !ok {
			continue
		}
		switch v := value.(type) {
		case string:
			if strings.TrimSpace(v) != "" {
				return v
			}
		case fmt.Stringer:
			return v.String()
		}
	}
	return ""
}

func countNames[T any](items []T, nameFn func(T) string) map[string]int {
	counts := map[string]int{}
	for _, item := range items {
		counts[nameFn(item)]++
	}
	return counts
}

func topCounts(counts map[string]int, limit int) []Count {
	result := make([]Count, 0, len(counts))
	for name, count := range counts {
		result = append(result, Count{Name: name, Count: count})
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Count == result[j].Count {
			return result[i].Name < result[j].Name
		}
		return result[i].Count > result[j].Count
	})
	if len(result) > limit {
		result = result[:limit]
	}
	return result
}

func buildDegreeIndex(edges []Edge) map[string]int {
	degrees := map[string]int{}
	for _, edge := range edges {
		if edge.Source != "" {
			degrees[edge.Source]++
		}
		if edge.Target != "" {
			degrees[edge.Target]++
		}
	}
	return degrees
}

func rankCandidates(nodes []Node, degrees map[string]int, focus string, filesOnly bool) []Candidate {
	keywords := focusKeywords(focus)
	var result []Candidate
	seen := map[string]bool{}
	for _, node := range nodes {
		if filesOnly && !looksLikeFile(node) {
			continue
		}
		if !filesOnly && !looksLikeSymbol(node) {
			continue
		}

		text := strings.ToLower(strings.Join([]string{
			node.Name,
			node.Path,
			node.File,
			node.Type,
		}, " "))

		matchCount := 0
		for _, keyword := range keywords {
			if strings.Contains(text, keyword) {
				matchCount++
			}
		}
		score := degrees[node.ID] + (matchCount * 3)
		if score == 0 {
			continue
		}
		if focus == "tee" && matchCount == 0 && score < 4 {
			continue
		}

		label := firstNonEmpty(node.Name, filepath.Base(node.Path), filepath.Base(node.File), node.ID)
		path := firstNonEmpty(node.Path, node.File)
		dedupeKey := label + "::" + path + "::" + normalizedName(node.Type, "unknown")
		if filesOnly {
			dedupeKey = filepath.ToSlash(path)
		}
		if dedupeKey != "" && seen[dedupeKey] {
			continue
		}

		reason := "high graph connectivity"
		if matchCount > 0 {
			reason = fmt.Sprintf("matches %d focus keyword(s) and has high graph connectivity", matchCount)
		}

		result = append(result, Candidate{
			Label:  label,
			Type:   normalizedName(node.Type, "unknown"),
			Path:   filepath.ToSlash(path),
			Reason: reason,
			Score:  score,
		})
		if dedupeKey != "" {
			seen[dedupeKey] = true
		}
	}

	sort.Slice(result, func(i, j int) bool {
		if result[i].Score == result[j].Score {
			if result[i].Path == result[j].Path {
				return result[i].Label < result[j].Label
			}
			return result[i].Path < result[j].Path
		}
		return result[i].Score > result[j].Score
	})
	if len(result) > 8 {
		result = result[:8]
	}
	return result
}

func focusKeywords(focus string) []string {
	switch focus {
	case "tee":
		return []string{
			"tee", "attest", "quote", "qe", "tcb", "collateral", "identity",
			"session", "handle", "memref", "invoke", "command", "trusted",
			"enclave", "sgx", "tdx", "seal", "unseal", "report", "verify",
			"pck", "root", "nonce", "rollback", "key",
		}
	default:
		return []string{focus}
	}
}

func looksLikeFile(node Node) bool {
	typ := strings.ToLower(node.Type)
	if looksLikeSymbol(node) {
		return false
	}
	if strings.Contains(typ, "file") || strings.Contains(typ, "module") {
		return true
	}

	if node.Path != "" {
		ext := strings.ToLower(filepath.Ext(node.Path))
		return ext != ""
	}

	return false
}

func looksLikeSymbol(node Node) bool {
	if node.Name == "" {
		return false
	}
	typ := strings.ToLower(node.Type)
	return strings.Contains(typ, "function") ||
		strings.Contains(typ, "method") ||
		strings.Contains(typ, "class") ||
		strings.Contains(typ, "symbol") ||
		strings.Contains(typ, "interface") ||
		strings.Contains(typ, "type")
}

func buildFocusSummary(focus string, files, symbols []Candidate) string {
	return fmt.Sprintf("Focus area %q currently points to %d likely files and %d likely symbols for review.", focus, len(files), len(symbols))
}

func buildHotspotSummary(files, symbols []Candidate) string {
	fileLabel := "none"
	symbolLabel := "none"
	if len(files) > 0 {
		fileLabel = files[0].Label
	}
	if len(symbols) > 0 {
		symbolLabel = symbols[0].Label
	}
	return fmt.Sprintf("Top file hotspot: %s. Top symbol hotspot: %s.", fileLabel, symbolLabel)
}

func auditQuestionsForFocus(focus string) []string {
	switch focus {
	case "tee":
		return []string{
			"Which modules or entrypoints appear to cross a trust boundary between trusted and untrusted worlds?",
			"Which high-connectivity files look responsible for attestation, key handling, command dispatch, or session state?",
			"Do any hotspot symbols look like they make trust decisions without nearby verification or binding logic?",
			"Where should a human reviewer start if they want to validate session binding, attestation validation, or insecure fallback behavior?",
		}
	default:
		return []string{
			"Which files and symbols look most central to the selected focus area?",
			"Which hotspots deserve manual review first?",
		}
	}
}

func normalizedName(value, fallback string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	if value == "" {
		return fallback
	}
	return value
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
