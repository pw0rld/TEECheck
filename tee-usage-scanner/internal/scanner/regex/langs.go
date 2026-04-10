package regex

import "regexp"

type LangRule struct {
	Name       string
	Extensions []string
	FuncDef    *regexp.Regexp
	StructDef  *regexp.Regexp
}

var defaultLangs = []LangRule{
	{
		Name:       "rust",
		Extensions: []string{".rs"},
		FuncDef:    regexp.MustCompile(`(?:pub\s+)?(?:async\s+)?fn\s+(\w+)`),
		StructDef:  regexp.MustCompile(`(?:pub\s+)?(?:struct|trait|enum)\s+(\w+)`),
	},
	{
		Name:       "go",
		Extensions: []string{".go"},
		FuncDef:    regexp.MustCompile(`func\s+(?:\([^)]*\)\s+)?(\w+)`),
		StructDef:  regexp.MustCompile(`type\s+(\w+)\s+struct`),
	},
	{
		Name:       "typescript",
		Extensions: []string{".ts", ".tsx", ".js", ".jsx"},
		FuncDef:    regexp.MustCompile(`(?:export\s+)?(?:async\s+)?function\s+(\w+)`),
		StructDef:  regexp.MustCompile(`(?:export\s+)?class\s+(\w+)`),
	},
	{
		Name:       "python",
		Extensions: []string{".py"},
		FuncDef:    regexp.MustCompile(`def\s+(\w+)`),
		StructDef:  regexp.MustCompile(`class\s+(\w+)`),
	},
	{
		Name:       "solidity",
		Extensions: []string{".sol"},
		FuncDef:    regexp.MustCompile(`function\s+(\w+)`),
		StructDef:  regexp.MustCompile(`(?:contract|interface|library)\s+(\w+)`),
	},
}

var skipDirs = map[string]bool{
	".git": true, "vendor": true, "node_modules": true, "target": true,
	"build": true, "dist": true, "__pycache__": true, ".venv": true,
}

func langForExt(ext string) *LangRule {
	for i := range defaultLangs {
		for _, e := range defaultLangs[i].Extensions {
			if e == ext {
				return &defaultLangs[i]
			}
		}
	}
	return nil
}
