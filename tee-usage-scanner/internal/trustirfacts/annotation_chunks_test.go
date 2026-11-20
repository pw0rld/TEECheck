package trustirfacts

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm"
)

// This model double can only select names that were actually presented.
// It catches candidate loss rather than relying on a fake that hallucinates
// the correct answer even when the prompt truncated it away.
type visibleAnnotationClient struct{ calls int }

func (c *visibleAnnotationClient) Generate(_ context.Context, req llm.GenerateRequest) (llm.GenerateResponse, error) {
	c.calls++
	prompt := req.Messages[0].Content
	producer, authority := "[]", "[]"
	if strings.Contains(prompt, "- shdr_load_pub_key\n") {
		producer = `[{"function":"shdr_load_pub_key","role":"security_version"}]`
	}
	if strings.Contains(prompt, "- check_update_version\n") {
		authority = `[{"function":"check_update_version","kind":"state_restore_acceptance"}]`
	}
	return llm.GenerateResponse{Text: fmt.Sprintf(`{"claim_producers":%s,"rollback_authorities":%s,"rollback_fields":["version"],"produced_structs":["shdr_pub_key"]}`, producer, authority)}, nil
}

func TestAnnotateFactTable_VisitsCandidatesBeyondFirstChunk(t *testing.T) {
	dir := writeRollbackFixtureTree(t)
	var body strings.Builder
	for i := 0; i < maxPromptFunctionNames+40; i++ {
		fmt.Fprintf(&body, "int aaa_%04d(void) { return 0; }\n", i)
	}
	writeFile(t, filepath.Join(dir, "lib", "many.c"), body.String())
	client := &visibleAnnotationClient{}
	table, _, err := AnnotateFactTable(context.Background(), client, realRegistry(t), dir)
	if err != nil {
		t.Fatal(err)
	}
	if client.calls < 2 || len(table.ClaimProducers) != 1 || len(table.RollbackAuthorities) != 1 {
		t.Fatalf("candidate coverage lost: calls=%d table=%+v", client.calls, table)
	}
}

func TestAnnotateFactTable_PairedSourceRevisionsHaveStableDigest(t *testing.T) {
	vulnerable := writeRollbackFixtureTree(t)
	fixed := writeRollbackFixtureTree(t)
	// Change implementation behavior without changing the identities being
	// annotated. Query results may differ; the role vocabulary must not.
	fixedSource := strings.Replace(rollbackFixtureC, "/* deliberately missing: key->version = subkey->subkey_version; */", "key->version = subkey->subkey_version;", 1)
	writeFile(t, filepath.Join(fixed, "core", "crypto", "signed_hdr.c"), fixedSource)
	a, _, err := AnnotateFactTable(context.Background(), &visibleAnnotationClient{}, realRegistry(t), vulnerable)
	if err != nil {
		t.Fatal(err)
	}
	b, _, err := AnnotateFactTable(context.Background(), &visibleAnnotationClient{}, realRegistry(t), fixed)
	if err != nil {
		t.Fatal(err)
	}
	da, err := tableDigest(a)
	if err != nil {
		t.Fatal(err)
	}
	db, err := tableDigest(b)
	if err != nil || da != db {
		t.Fatalf("paired identities changed: %s != %s (err=%v)", da, db, err)
	}
}
