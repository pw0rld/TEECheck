package llm

import "testing"

func TestClientRequiresConfiguration(t *testing.T) {
	if _, err := (Client{}).Complete(t.Context(), "test"); err == nil {
		t.Fatal("expected configuration error")
	}
}
