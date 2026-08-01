package agentbus

type Query struct {
	QueryID   string `json:"query_id"`
	FromAgent string `json:"from_agent"`
	ToAgent   string `json:"to_agent"`
	Kind      string `json:"kind"`
	Question  string `json:"question"`

	// Evidence is everything the answering agent is allowed to reason from:
	// the case pack slice, the ToolFacts, whatever the caller can vouch for.
	// It is not optional decoration — NewLLMHandler refuses a query that
	// arrives without it. A bus agent has no file access and no tools, so an
	// empty Evidence means the only possible answer is invented, and on
	// 2026-08-01 one such answer overrode a CodeQL ToolFact and turned a
	// vulnerable-side run into no_issue_observed.
	Evidence string `json:"evidence,omitempty"`

	Context any `json:"context,omitempty"`
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
