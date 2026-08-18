package llm

import (
	"context"
	"testing"
)

func TestClientRequiresConfiguration(t *testing.T) {
	if _, err := (Client{}).Complete(context.Background(), "test"); err == nil {
		t.Fatal("expected configuration error")
	}
}
