package trustirfacts

import (
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/codeql"
)

// The query's conclusion has to survive the SARIF-to-ToolFact conversion.
// This is where it was lost: ParseSARIF produced the message and the related
// sites, ToolFact kept only the primary location, and five agent prompts in a
// row said "status=success locations=core/crypto/signed_hdr.c:262" while
// check_update_version and ree_fs_ta appeared in none of them.
func TestToolFindings_CarriesMessageAndRelated(t *testing.T) {
	got := toolFindings([]codeql.Result{{
		Message:   "TWE-STATE-001: producer never propagates rollback field 'version'.",
		Path:      "core/crypto/signed_hdr.c",
		StartLine: 262,
		Related: []codeql.RelatedLocation{
			{Path: "core/crypto/signed_hdr.c", StartLine: 262, Symbol: "shdr_load_pub_key"},
			{Path: "core/kernel/ree_fs_ta.c", StartLine: 639, Symbol: "check_update_version"},
		},
	}})

	if len(got) != 1 {
		t.Fatalf("findings = %d, want 1", len(got))
	}
	if got[0].Message == "" {
		t.Error("the message is the query's answer; it must survive")
	}
	if len(got[0].Related) != 2 {
		t.Fatalf("related = %+v, want 2", got[0].Related)
	}
	if got[0].Related[1].Symbol != "check_update_version" || got[0].Related[1].Path != "core/kernel/ree_fs_ta.c" {
		t.Errorf("related[1] = %+v, want check_update_version in ree_fs_ta.c", got[0].Related[1])
	}
}

// A zero-result analyze produces no findings — and that is different from a
// finding with an empty message.
func TestToolFindings_EmptyResults(t *testing.T) {
	if got := toolFindings(nil); got != nil {
		t.Fatalf("findings = %+v, want nil", got)
	}
}
