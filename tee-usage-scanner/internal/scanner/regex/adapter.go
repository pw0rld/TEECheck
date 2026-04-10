package regex

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/scanner"
)

type Adapter struct{}

func New() *Adapter { return &Adapter{} }

func (a *Adapter) Name() string   { return "regex" }
func (a *Adapter) Available() bool { return true }

func (a *Adapter) ExtractGraph(ctx context.Context, req scanner.GraphRequest) (scanner.GraphResult, error) {
	var result scanner.GraphResult
	symbolsByFile := make(map[string][]string)

	err := filepath.Walk(req.RepoRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if info.IsDir() {
			if skipDirs[info.Name()] {
				return filepath.SkipDir
			}
			return nil
		}

		ext := strings.ToLower(filepath.Ext(info.Name()))
		lang := langForExt(ext)

		rel, relErr := filepath.Rel(req.RepoRoot, path)
		if relErr != nil {
			return nil
		}
		rel = filepath.ToSlash(rel)

		fileID := fmt.Sprintf("file-%s", sanitizeID(rel))
		langName := ""
		if lang != nil {
			langName = lang.Name
		}

		result.Nodes = append(result.Nodes, scanner.GraphNode{
			ID:       fileID,
			Kind:     "file",
			Name:     info.Name(),
			Path:     rel,
			Language: langName,
		})

		if lang == nil {
			return nil
		}

		symbols := extractSymbols(path, rel, lang)
		for _, sym := range symbols {
			result.Nodes = append(result.Nodes, sym.node)
			result.Edges = append(result.Edges, scanner.GraphEdge{
				Source: fileID,
				Target: sym.node.ID,
				Kind:   "defines",
			})
			symbolsByFile[rel] = append(symbolsByFile[rel], sym.node.Name)
		}

		return nil
	})
	if err != nil {
		return scanner.GraphResult{}, err
	}

	callEdges := detectCrossFileRefs(req.RepoRoot, result.Nodes, symbolsByFile)
	result.Edges = append(result.Edges, callEdges...)

	return result, nil
}

type symbolInfo struct {
	node scanner.GraphNode
}

func extractSymbols(fullPath, relPath string, lang *LangRule) []symbolInfo {
	f, err := os.Open(fullPath)
	if err != nil {
		return nil
	}
	defer f.Close()

	var symbols []symbolInfo
	seen := make(map[string]bool)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()

		if lang.FuncDef != nil {
			if matches := lang.FuncDef.FindStringSubmatch(line); len(matches) > 1 {
				name := matches[1]
				if !seen[name] && len(name) >= 2 {
					seen[name] = true
					symbols = append(symbols, symbolInfo{
						node: scanner.GraphNode{
							ID:       fmt.Sprintf("sym-%s-%s", sanitizeID(relPath), name),
							Kind:     "function",
							Name:     name,
							Path:     relPath,
							Language: lang.Name,
						},
					})
				}
			}
		}

		if lang.StructDef != nil {
			if matches := lang.StructDef.FindStringSubmatch(line); len(matches) > 1 {
				name := matches[1]
				if !seen[name] && len(name) >= 2 {
					seen[name] = true
					symbols = append(symbols, symbolInfo{
						node: scanner.GraphNode{
							ID:       fmt.Sprintf("sym-%s-%s", sanitizeID(relPath), name),
							Kind:     "struct",
							Name:     name,
							Path:     relPath,
							Language: lang.Name,
						},
					})
				}
			}
		}
	}
	return symbols
}

func detectCrossFileRefs(repoRoot string, nodes []scanner.GraphNode, symbolsByFile map[string][]string) []scanner.GraphEdge {
	type symRef struct {
		id   string
		path string
	}
	funcSymbols := make(map[string]symRef)
	for _, n := range nodes {
		if n.Kind == "function" {
			funcSymbols[n.Name] = symRef{id: n.ID, path: n.Path}
		}
	}

	var edges []scanner.GraphEdge
	seen := make(map[string]bool)

	for filePath, symsInFile := range symbolsByFile {
		fullPath := filepath.Join(repoRoot, filepath.FromSlash(filePath))
		content, err := os.ReadFile(fullPath)
		if err != nil {
			continue
		}
		text := string(content)

		for name, ref := range funcSymbols {
			if ref.path == filePath {
				continue
			}
			if strings.Contains(text, name) {
				for _, localSym := range symsInFile {
					localID := fmt.Sprintf("sym-%s-%s", sanitizeID(filePath), localSym)
					edgeKey := localID + "->" + ref.id
					if !seen[edgeKey] {
						seen[edgeKey] = true
						edges = append(edges, scanner.GraphEdge{
							Source: localID,
							Target: ref.id,
							Kind:   "calls",
						})
						break
					}
				}
			}
		}
	}
	return edges
}

func sanitizeID(s string) string {
	r := strings.NewReplacer("/", "-", "\\", "-", ".", "-", " ", "-")
	return r.Replace(s)
}
