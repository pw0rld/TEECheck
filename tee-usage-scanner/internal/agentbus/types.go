package agentbus

type Query struct {
	QueryID   string `json:"query_id"`
	FromAgent string `json:"from_agent"`
	ToAgent   string `json:"to_agent"`
	Kind      string `json:"kind"`
	Question  string `json:"question"`
	Context   any    `json:"context,omitempty"`
}

type Response struct {
	QueryID   string   `json:"query_id"`
	FromAgent string   `json:"from_agent"`
	Answer    string   `json:"answer"`
	Facts     []string `json:"facts,omitempty"`
}

type Round struct {
	Query    Query    `json:"query"`
	Response Response `json:"response"`
}

type Dialog struct {
	CaseID string  `json:"case_id"`
	Rounds []Round `json:"rounds"`
}
