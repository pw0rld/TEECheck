package trustirfacts

import "testing"

func TestRequestValidate(t *testing.T) {
	valid := Request{
		RunDir: "run", Repository: "repo", Commit: "abc",
		Operation: OperationRollbackVersionPropagation, QueryPackDir: "pack",
	}
	if err := valid.validate(); err != nil {
		t.Fatalf("expected valid request to pass, got %v", err)
	}

	cases := []struct {
		name string
		req  Request
	}{
		{"missing RunDir", Request{Repository: "r", Commit: "c", Operation: "op", QueryPackDir: "p"}},
		{"missing Repository", Request{RunDir: "d", Commit: "c", Operation: "op", QueryPackDir: "p"}},
		{"missing Commit", Request{RunDir: "d", Repository: "r", Operation: "op", QueryPackDir: "p"}},
		{"missing Operation", Request{RunDir: "d", Repository: "r", Commit: "c", QueryPackDir: "p"}},
		{"missing QueryPackDir", Request{RunDir: "d", Repository: "r", Commit: "c", Operation: "op"}},
		{"all missing", Request{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.req.validate(); err == nil {
				t.Fatalf("expected an error for %s", tc.name)
			}
		})
	}
}

func TestArgumentsSHA256_StableAndDiscriminating(t *testing.T) {
	a := Request{Repository: "repo-a", Commit: "commit-1", Operation: OperationRollbackVersionPropagation}
	b := a
	if a.argumentsSHA256() != b.argumentsSHA256() {
		t.Fatal("identical requests must hash identically")
	}

	variants := []Request{
		{Repository: "repo-b", Commit: "commit-1", Operation: OperationRollbackVersionPropagation}, // repo differs
		{Repository: "repo-a", Commit: "commit-2", Operation: OperationRollbackVersionPropagation}, // commit differs
		{Repository: "repo-a", Commit: "commit-1", Operation: "other-op"},                          // operation differs
	}
	base := a.argumentsSHA256()
	for i, v := range variants {
		if v.argumentsSHA256() == base {
			t.Errorf("variant %d should hash differently from base, both = %q", i, base)
		}
	}

	if got := len(a.argumentsSHA256()); got != 64 { // sha256 hex length
		t.Errorf("argumentsSHA256 length = %d, want 64", got)
	}
}

func TestFactID_DeterministicAndRunDirIndependent(t *testing.T) {
	a := Request{RunDir: "run-1", Repository: "repo", Commit: "abc", Operation: OperationRollbackVersionPropagation}
	b := Request{RunDir: "run-2", Repository: "repo", Commit: "abc", Operation: OperationRollbackVersionPropagation}
	// RunDir does not participate in factID: the same evidence produced in
	// two different run directories is still the same fact.
	if a.factID() != b.factID() {
		t.Errorf("factID should not depend on RunDir: %q vs %q", a.factID(), b.factID())
	}

	c := Request{RunDir: "run-1", Repository: "repo", Commit: "different", Operation: OperationRollbackVersionPropagation}
	if a.factID() == c.factID() {
		t.Error("factID should change when Commit changes")
	}
}
