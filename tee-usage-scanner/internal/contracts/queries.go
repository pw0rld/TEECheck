package contracts

import (
	"fmt"
	"regexp"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
)

const StructFieldWriteOperation = "cpp.contract.direct_struct_field_assignment"

var queryIdentifier = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// ValidateVerificationQueries checks the executable verification plan without
// running a query. Unsupported properties can still be represented accurately
// by leaving VerificationQueries empty for independent source review.
func ValidateVerificationQueries(c artifacts.CaseInvariantV2) error {
	for i, q := range c.VerificationQueries {
		if q.Backend != "codeql" || q.Operation != StructFieldWriteOperation {
			return fmt.Errorf("verification_queries[%d]: unsupported verification query %q/%q; leave verification_queries empty when no registered query matches the property", i, q.Backend, q.Operation)
		}
		if _, _, _, err := StructFieldWriteTarget(c, q); err != nil {
			return fmt.Errorf("verification_queries[%d]: %w", i, err)
		}
	}
	return nil
}

// StructFieldWriteTarget validates the narrow registered AST property and
// selects its exact subject. It does not establish value propagation, path
// dominance, aliasing, or any other stronger security property.
func StructFieldWriteTarget(c artifacts.CaseInvariantV2, q artifacts.ContractQuery) (subject artifacts.ContractSubject, typeName, field string, err error) {
	if q.Backend != "codeql" || q.Operation != StructFieldWriteOperation || c.RequiredProperty.Kind != "direct_struct_field_assignment" || len(c.Subjects) == 0 || len(q.Parameters) < 2 || len(q.Parameters) > 3 {
		return subject, "", "", fmt.Errorf("query does not describe one registered struct-field property")
	}
	for name := range q.Parameters {
		if name != "type" && name != "field" && name != "subject" {
			return subject, "", "", fmt.Errorf("unknown query parameter %q", name)
		}
	}

	target := q.Parameters["subject"]
	if target == "" && len(c.Subjects) == 1 {
		subject = c.Subjects[0]
	} else {
		matches := 0
		for _, s := range c.Subjects {
			if target == s.Path+"::"+s.Symbol {
				subject = s
				matches++
			}
		}
		if matches != 1 {
			return subject, "", "", fmt.Errorf("query requires a unique subject parameter for its target definition")
		}
	}
	typeName, field = q.Parameters["type"], q.Parameters["field"]
	if !queryIdentifier.MatchString(typeName) || !queryIdentifier.MatchString(field) || !queryIdentifier.MatchString(subject.Symbol) {
		return subject, "", "", fmt.Errorf("invalid query identifier")
	}
	if c.RequiredProperty.Destination != typeName+"."+field || len(c.RequiredProperty.TargetFields) != 1 || c.RequiredProperty.TargetFields[0] != field || c.RequiredProperty.Source != "" || c.RequiredProperty.Authority != "" {
		return subject, "", "", fmt.Errorf("query parameters differ from the declared property")
	}
	return subject, typeName, field, nil
}
