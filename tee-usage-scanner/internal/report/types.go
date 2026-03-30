package report

type Report struct {
	SchemaVersion string    `json:"schema_version"`
	RuleCount     int       `json:"rule_count"`
	EvidenceCount int       `json:"evidence_count"`
	FindingCount  int       `json:"finding_count"`
	Findings      []Finding `json:"findings"`
}

type Finding struct {
	ID             string   `json:"id"`
	RuleID         string   `json:"rule_id"`
	Severity       string   `json:"severity"`
	Status         string   `json:"status"`
	File           string   `json:"file"`
	Line           int      `json:"line"`
	Function       string   `json:"function"`
	Expression     string   `json:"expression"`
	Message        string   `json:"message"`
	MissingChecks  []string `json:"missing_checks"`
	ObservedChecks []string `json:"observed_checks"`
	NeedsReview    bool     `json:"needs_review"`
}
