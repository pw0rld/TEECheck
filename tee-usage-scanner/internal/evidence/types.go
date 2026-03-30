package evidence

type Package struct {
	SchemaVersion      string            `json:"schema_version"`
	Metadata           map[string]string `json:"metadata"`
	Candidate          Candidate         `json:"candidate"`
	Checks             []Check           `json:"checks"`
	Bindings           []Binding         `json:"bindings"`
	KeySites           []Site            `json:"key_sites,omitempty"`
	CodeSnippets       []CodeSnippet     `json:"code_snippets"`
	ControlFlowSummary []string          `json:"control_flow_summary"`
	DataFlowSummary    []string          `json:"data_flow_summary"`
}

type Candidate struct {
	ID            string   `json:"id"`
	SDK           string   `json:"sdk"`
	File          string   `json:"file"`
	Function      string   `json:"function"`
	Line          int      `json:"line"`
	Expression    string   `json:"expression"`
	OperationKind string   `json:"operation_kind"`
	ParamIndex    int      `json:"param_index"`
	Notes         []string `json:"notes"`
}

type Check struct {
	Kind            string   `json:"kind"`
	File            string   `json:"file"`
	Line            int      `json:"line"`
	Expression      string   `json:"expression"`
	DominatesTarget bool     `json:"dominates_target"`
	Fields          []string `json:"fields,omitempty"`
	Notes           []string `json:"notes"`
}

type Binding struct {
	Kind   string   `json:"kind"`
	Status string   `json:"status"`
	Notes  []string `json:"notes"`
}

type Site struct {
	Kind       string   `json:"kind"`
	File       string   `json:"file"`
	Line       int      `json:"line"`
	Function   string   `json:"function,omitempty"`
	Expression string   `json:"expression,omitempty"`
	Notes      []string `json:"notes,omitempty"`
}

type CodeSnippet struct {
	Label string `json:"label"`
	File  string `json:"file"`
	Line  int    `json:"line"`
	Code  string `json:"code"`
}
