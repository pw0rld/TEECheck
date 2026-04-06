package repomap

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/config"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
)

type node struct {
	ID       string
	Kind     string
	Name     string
	Path     string
	Language string
}

type edge struct {
	Source string
	Target string
	Kind   string
}

type graph struct {
	Nodes  map[string]*node
	Edges  []edge
	Degree map[string]int
}

type scoreItem struct {
	Path     string
	Symbol   string
	Score    int
	Reasons  []string
	Priority string
}

func Run(cfg config.Config) error {
	manifest, err := runfs.LoadManifest(cfg.RunDir)
	if err != nil {
		return fmt.Errorf("load manifest: %w", err)
	}

	g, err := loadGraph(cfg.GraphJSONPath)
	if err != nil {
		return fmt.Errorf("load graph: %w", err)
	}

	repoMap := buildRepoMap(manifest, g)
	if err := runfs.WriteJSON(runfs.RepoMapPath(cfg.RunDir), repoMap); err != nil {
		return fmt.Errorf("write repo_map: %w", err)
	}

	fmt.Printf("Repo map written to %s\n", runfs.RepoMapPath(cfg.RunDir))
	return nil
}

func buildRepoMap(manifest artifacts.Manifest, g graph) artifacts.RepoMap {
	importantFiles := rankImportantFiles(manifest.Focus, g)
	importantSymbols := rankImportantSymbols(manifest.Focus, g)

	return artifacts.RepoMap{
		SchemaVersion: "teecheck.repo_map.v1",
		Repo: artifacts.RepoRef{
			URL:    manifest.RepoURL,
			Commit: manifest.Commit,
			Focus:  manifest.Focus,
		},
		Modules:          deriveModules(g),
		Entrypoints:      deriveEntrypoints(g),
		Boundaries:       deriveBoundaries(importantFiles, importantSymbols),
		ImportantFiles:   importantFiles,
		ImportantSymbols: importantSymbols,
		CrossLangLinks:   deriveCrossLangLinks(g),
		Notes: []string{
			"repo_map was generated heuristically from the supplied structure graph",
			"important_files and important_symbols are ranked for audit utility rather than architectural completeness",
		},
	}
}

func loadGraph(graphPath string) (graph, error) {
	data, err := os.ReadFile(graphPath)
	if err != nil {
		return graph{}, err
	}

	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return graph{}, err
	}

	nodesRaw := firstObjectArray(raw, "nodes")
	if len(nodesRaw) == 0 {
		if sub := firstMap(raw, "graph"); sub != nil {
			nodesRaw = firstObjectArray(sub, "nodes", "vertices")
		}
	}

	edgesRaw := firstObjectArray(raw, "edges", "relationships")
	if len(edgesRaw) == 0 {
		if sub := firstMap(raw, "graph"); sub != nil {
			edgesRaw = firstObjectArray(sub, "edges", "relationships")
		}
	}

	if len(nodesRaw) == 0 {
		return graph{}, fmt.Errorf("graph export did not contain nodes")
	}

	g := graph{
		Nodes:  map[string]*node{},
		Degree: map[string]int{},
	}

	for idx, item := range nodesRaw {
		id := firstString(item, "id", "key", "node_id")
		if id == "" {
			id = fmt.Sprintf("node-%03d", idx+1)
		}

		n := &node{
			ID:       id,
			Kind:     normalizeLower(firstString(item, "kind", "type", "node_type", "label")),
			Name:     firstString(item, "name", "symbol", "display_name", "identifier"),
			Path:     normalizePath(firstString(item, "path", "file_path", "relative_path", "filepath", "file")),
			Language: normalizeLower(firstString(item, "language", "lang")),
		}

		if n.Kind == "" {
			if labels := firstStrings(item, "labels"); len(labels) > 0 {
				n.Kind = normalizeLower(strings.Join(labels, "/"))
			}
		}
		if n.Name == "" && n.Path != "" {
			n.Name = path.Base(n.Path)
		}
		if n.Kind == "" {
			if isFileLikePath(n.Path) {
				n.Kind = "file"
			} else if n.Name != "" {
				n.Kind = "symbol"
			}
		}

		g.Nodes[n.ID] = n
	}

	for _, item := range edgesRaw {
		e := edge{
			Source: firstString(item, "source", "from", "src", "outV"),
			Target: firstString(item, "target", "to", "dst", "inV"),
			Kind:   normalizeLower(firstString(item, "kind", "type", "relation", "label")),
		}
		if e.Source == "" || e.Target == "" {
			continue
		}
		if e.Kind == "" {
			e.Kind = "related_to"
		}
		g.Edges = append(g.Edges, e)
		g.Degree[e.Source]++
		g.Degree[e.Target]++
	}

	fillMissingPaths(g)
	return g, nil
}

func fillMissingPaths(g graph) {
	for _, e := range g.Edges {
		src := g.Nodes[e.Source]
		dst := g.Nodes[e.Target]
		if src == nil || dst == nil {
			continue
		}

		if src.Path == "" && !isFileNode(src) && dst.Path != "" && isFileNode(dst) {
			src.Path = dst.Path
		}
		if dst.Path == "" && !isFileNode(dst) && src.Path != "" && isFileNode(src) {
			dst.Path = src.Path
		}
	}
}

func rankImportantFiles(focus string, g graph) []artifacts.ImportantFile {
	candidates := []scoreItem{}
	for _, n := range g.Nodes {
		if !isFileNode(n) || n.Path == "" {
			continue
		}

		score, reasons := scoreValue(n.Path, focus, g.Degree[n.ID])
		if hasCrossLangPath(g, n.Path) {
			score += 2
			reasons = append(reasons, "cross-language bridge")
		}
		candidates = append(candidates, scoreItem{
			Path:     n.Path,
			Score:    score,
			Reasons:  uniqStrings(reasons),
			Priority: priorityForScore(score),
		})
	}

	sortScoreItems(candidates)
	seen := map[string]bool{}
	result := []artifacts.ImportantFile{}
	for _, candidate := range candidates {
		if seen[candidate.Path] {
			continue
		}
		seen[candidate.Path] = true
		result = append(result, artifacts.ImportantFile{
			Path:     candidate.Path,
			Reasons:  candidate.Reasons,
			Priority: candidate.Priority,
		})
		if len(result) == 16 {
			break
		}
	}
	return result
}

func rankImportantSymbols(focus string, g graph) []artifacts.ImportantSymbol {
	candidates := []scoreItem{}
	for _, n := range g.Nodes {
		if isFileNode(n) || n.Name == "" || n.Path == "" {
			continue
		}

		score, reasons := scoreValue(strings.Join([]string{n.Path, n.Name}, " "), focus, g.Degree[n.ID])
		if isEntrypointName(n.Name) {
			score += 3
			reasons = append(reasons, "entrypoint-like symbol")
		}
		candidates = append(candidates, scoreItem{
			Path:     n.Path,
			Symbol:   n.Name,
			Score:    score,
			Reasons:  uniqStrings(reasons),
			Priority: priorityForScore(score),
		})
	}

	sortScoreItems(candidates)
	seen := map[string]bool{}
	result := []artifacts.ImportantSymbol{}
	for _, candidate := range candidates {
		key := candidate.Path + "::" + candidate.Symbol
		if seen[key] {
			continue
		}
		seen[key] = true
		result = append(result, artifacts.ImportantSymbol{
			Path:     candidate.Path,
			Symbol:   candidate.Symbol,
			Reasons:  candidate.Reasons,
			Priority: candidate.Priority,
		})
		if len(result) == 16 {
			break
		}
	}
	return result
}

func deriveModules(g graph) []artifacts.Module {
	modulePaths := map[string][]string{}
	for _, n := range g.Nodes {
		if !isFileNode(n) || n.Path == "" {
			continue
		}
		key := moduleKey(n.Path)
		modulePaths[key] = append(modulePaths[key], n.Path)
	}

	keys := make([]string, 0, len(modulePaths))
	for key := range modulePaths {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	modules := []artifacts.Module{}
	for idx, key := range keys {
		paths := uniqStrings(modulePaths[key])
		sort.Strings(paths)
		if len(paths) > 8 {
			paths = paths[:8]
		}
		modules = append(modules, artifacts.Module{
			ID:          fmt.Sprintf("module-%03d", idx+1),
			Name:        key,
			Paths:       paths,
			Description: moduleDescription(key),
		})
	}
	return modules
}

func deriveEntrypoints(g graph) []artifacts.Entrypoint {
	result := []artifacts.Entrypoint{}
	seen := map[string]bool{}
	for _, n := range g.Nodes {
		if isFileNode(n) || n.Path == "" || n.Name == "" || !isEntrypointName(n.Name) {
			continue
		}
		key := n.Path + "::" + n.Name
		if seen[key] {
			continue
		}
		seen[key] = true
		result = append(result, artifacts.Entrypoint{
			ID:          fmt.Sprintf("entry-%03d", len(result)+1),
			Path:        n.Path,
			Symbol:      n.Name,
			Description: "heuristic entrypoint based on symbol name and graph position",
		})
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Path == result[j].Path {
			return result[i].Symbol < result[j].Symbol
		}
		return result[i].Path < result[j].Path
	})
	return result
}

func deriveBoundaries(files []artifacts.ImportantFile, symbols []artifacts.ImportantSymbol) []artifacts.Boundary {
	type candidate struct {
		Path   string
		Symbol string
	}
	candidates := []candidate{}
	for _, file := range files {
		candidates = append(candidates, candidate{Path: file.Path})
	}
	for _, symbol := range symbols {
		candidates = append(candidates, candidate{Path: symbol.Path, Symbol: symbol.Symbol})
	}

	seen := map[string]bool{}
	boundaries := []artifacts.Boundary{}
	for _, candidate := range candidates {
		kind, direction, description := classifyBoundary(candidate.Path, candidate.Symbol)
		if kind == "" {
			continue
		}
		key := kind + "::" + candidate.Path + "::" + candidate.Symbol
		if seen[key] {
			continue
		}
		seen[key] = true
		boundary := artifacts.Boundary{
			ID:          fmt.Sprintf("boundary-%03d", len(boundaries)+1),
			Kind:        kind,
			Direction:   direction,
			Paths:       []string{candidate.Path},
			Description: description,
		}
		if candidate.Symbol != "" {
			boundary.Symbols = []string{candidate.Symbol}
		}
		boundaries = append(boundaries, boundary)
		if len(boundaries) == 16 {
			break
		}
	}
	return boundaries
}

func deriveCrossLangLinks(g graph) []artifacts.CrossLanguageRef {
	refs := []artifacts.CrossLanguageRef{}
	seen := map[string]bool{}
	for _, e := range g.Edges {
		src := g.Nodes[e.Source]
		dst := g.Nodes[e.Target]
		if src == nil || dst == nil {
			continue
		}
		if src.Path == "" || dst.Path == "" || src.Language == "" || dst.Language == "" || src.Language == dst.Language {
			continue
		}
		key := src.Path + "->" + dst.Path + ":" + e.Kind
		if seen[key] {
			continue
		}
		seen[key] = true
		refs = append(refs, artifacts.CrossLanguageRef{
			FromPath: src.Path,
			ToPath:   dst.Path,
			Kind:     e.Kind,
		})
	}
	sort.Slice(refs, func(i, j int) bool {
		if refs[i].FromPath == refs[j].FromPath {
			if refs[i].ToPath == refs[j].ToPath {
				return refs[i].Kind < refs[j].Kind
			}
			return refs[i].ToPath < refs[j].ToPath
		}
		return refs[i].FromPath < refs[j].FromPath
	})
	return refs
}

func firstMap(raw map[string]any, keys ...string) map[string]any {
	for _, key := range keys {
		value, ok := raw[key]
		if !ok {
			continue
		}
		if sub, ok := value.(map[string]any); ok {
			return sub
		}
	}
	return nil
}

func firstObjectArray(raw map[string]any, keys ...string) []map[string]any {
	for _, key := range keys {
		value, ok := raw[key]
		if !ok {
			continue
		}
		if arr, ok := value.([]any); ok {
			result := []map[string]any{}
			for _, item := range arr {
				if obj, ok := item.(map[string]any); ok {
					result = append(result, obj)
				}
			}
			if len(result) > 0 {
				return result
			}
		}
	}
	return nil
}

func firstString(raw map[string]any, keys ...string) string {
	maps := []map[string]any{raw}
	for _, nested := range []string{"properties", "attrs", "attributes", "data"} {
		if sub := firstMap(raw, nested); sub != nil {
			maps = append(maps, sub)
		}
	}
	for _, current := range maps {
		for _, key := range keys {
			if value, ok := current[key]; ok {
				if s := asString(value); s != "" {
					return s
				}
			}
		}
	}
	return ""
}

func firstStrings(raw map[string]any, key string) []string {
	maps := []map[string]any{raw}
	for _, nested := range []string{"properties", "attrs", "attributes", "data"} {
		if sub := firstMap(raw, nested); sub != nil {
			maps = append(maps, sub)
		}
	}
	for _, current := range maps {
		value, ok := current[key]
		if !ok {
			continue
		}
		switch typed := value.(type) {
		case []any:
			result := []string{}
			for _, item := range typed {
				if s := asString(item); s != "" {
					result = append(result, s)
				}
			}
			if len(result) > 0 {
				return result
			}
		}
	}
	return nil
}

func asString(value any) string {
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed)
	case float64:
		return fmt.Sprintf("%.0f", typed)
	case int:
		return fmt.Sprintf("%d", typed)
	case json.Number:
		return typed.String()
	default:
		return ""
	}
}

func isFileNode(n *node) bool {
	if n == nil {
		return false
	}
	if strings.Contains(n.Kind, "file") {
		return true
	}
	return isFileLikePath(n.Path)
}

func isFileLikePath(filePath string) bool {
	filePath = normalizePath(filePath)
	if filePath == "" {
		return false
	}
	base := path.Base(filePath)
	ext := path.Ext(base)
	return ext != ""
}

func normalizePath(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	value = filepath.ToSlash(value)
	value = strings.TrimPrefix(value, "./")
	return value
}

func normalizeLower(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func moduleKey(filePath string) string {
	parts := strings.Split(normalizePath(filePath), "/")
	if len(parts) == 0 || parts[0] == "" {
		return "root"
	}
	generic := map[string]bool{
		"src":      true,
		"lib":      true,
		"pkg":      true,
		"cmd":      true,
		"internal": true,
	}
	if generic[parts[0]] && len(parts) > 1 {
		return parts[0]
	}
	return parts[0]
}

func moduleDescription(module string) string {
	lower := strings.ToLower(module)
	switch {
	case strings.Contains(lower, "runtime"):
		return "Runtime-facing code cluster"
	case strings.Contains(lower, "rofl"):
		return "ROFL or app-side interaction cluster"
	case strings.Contains(lower, "client"):
		return "Client-facing integration cluster"
	case strings.Contains(lower, "binding"):
		return "Language or API binding cluster"
	case strings.Contains(lower, "test"):
		return "Testing-oriented code cluster"
	default:
		return "Heuristic module grouping derived from file paths"
	}
}

func isEntrypointName(name string) bool {
	lower := strings.ToLower(strings.TrimSpace(name))
	for _, keyword := range []string{
		"main", "run", "start", "init", "handle", "verify", "execute",
		"query", "submit", "dispatch", "route", "apply", "process",
	} {
		if strings.Contains(lower, keyword) {
			return true
		}
	}
	return false
}

func hasCrossLangPath(g graph, filePath string) bool {
	for _, ref := range deriveCrossLangLinks(g) {
		if ref.FromPath == filePath || ref.ToPath == filePath {
			return true
		}
	}
	return false
}

func scoreValue(value, focus string, degree int) (int, []string) {
	score := degree
	reasons := []string{}
	if degree >= 3 {
		reasons = append(reasons, "high graph connectivity")
	}

	for _, keyword := range focusKeywords(focus) {
		if strings.Contains(strings.ToLower(value), keyword) {
			score += 4
			reasons = append(reasons, fmt.Sprintf("matches focus keyword '%s'", keyword))
		}
	}

	for _, keyword := range globalSecurityKeywords() {
		if strings.Contains(strings.ToLower(value), keyword) {
			score += 2
			reasons = append(reasons, fmt.Sprintf("security-relevant keyword '%s'", keyword))
			break
		}
	}

	if len(reasons) == 0 {
		reasons = append(reasons, "structurally connected code path")
	}
	return score, reasons
}

func focusKeywords(focus string) []string {
	switch strings.ToLower(strings.TrimSpace(focus)) {
	case "runtime":
		return []string{"runtime", "tx", "state", "module", "core", "dispatch", "handler"}
	case "attestation":
		return []string{"attest", "quote", "report", "verify", "identity", "tcb", "cert", "collateral"}
	case "rofl":
		return []string{"rofl", "appd", "socket", "tx", "app", "runtime"}
	default:
		return []string{"tee", "verify", "attest", "runtime", "identity", "policy", "tx", "state", "key"}
	}
}

func globalSecurityKeywords() []string {
	return []string{
		"attest", "verify", "identity", "quote", "report", "state", "key",
		"secret", "policy", "auth", "tx", "route", "runtime", "tee",
		"enclave", "rofl", "storage", "replay",
	}
}

func classifyBoundary(filePath, symbol string) (string, string, string) {
	value := strings.ToLower(strings.Join([]string{filePath, symbol}, " "))
	switch {
	case hasAny(value, []string{"attest", "quote", "report", "qe", "identity", "collateral", "cert", "tcb"}):
		return "attestation", "ingress", "attestation or identity verification boundary"
	case hasAny(value, []string{"auth", "authorize", "acl", "role", "permission", "caller", "session"}):
		return "authorization", "ingress", "authorization or caller-binding boundary"
	case hasAny(value, []string{"state", "epoch", "nonce", "replay", "sequence"}):
		return "state_machine", "bidirectional", "state or replay-sensitive boundary"
	case hasAny(value, []string{"key", "secret", "sign", "seal", "kms", "crypto"}):
		return "key_management", "internal", "key or secret handling boundary"
	case hasAny(value, []string{"fallback", "retry", "degrade", "debug", "unsafe"}):
		return "fallback", "egress", "failure or fallback boundary"
	case hasAny(value, []string{"ffi", "binding", "bridge", "ecall", "ocall"}):
		return "ffi_boundary", "bidirectional", "cross-language or host bridge boundary"
	case hasAny(value, []string{"route", "handler", "api", "rpc", "request", "response", "socket", "tx", "submit"}):
		return "host_interface", "ingress", "host-facing or client-facing boundary"
	case hasAny(value, []string{"runtime", "module", "dispatch", "execute", "query"}):
		return "runtime_entry", "ingress", "runtime-facing execution entry boundary"
	default:
		return "", "", ""
	}
}

func priorityForScore(score int) string {
	switch {
	case score >= 10:
		return "high"
	case score >= 6:
		return "medium"
	default:
		return "low"
	}
}

func hasAny(value string, keywords []string) bool {
	for _, keyword := range keywords {
		if strings.Contains(value, keyword) {
			return true
		}
	}
	return false
}

func uniqStrings(values []string) []string {
	seen := map[string]bool{}
	result := []string{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		result = append(result, value)
	}
	return result
}

func sortScoreItems(items []scoreItem) {
	sort.Slice(items, func(i, j int) bool {
		if items[i].Score == items[j].Score {
			if items[i].Path == items[j].Path {
				return items[i].Symbol < items[j].Symbol
			}
			return items[i].Path < items[j].Path
		}
		return items[i].Score > items[j].Score
	})
}
