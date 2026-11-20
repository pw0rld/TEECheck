package config

import (
	"testing"
)

func TestVerifyContractParsing(t *testing.T) {
	c, err := Parse([]string{"verify-contract", "--contract", "c.json", "--repo-root", "fixed", "--commit", "revision"})
	if err != nil {
		t.Fatal(err)
	}
	if c.ContractPath != "c.json" || c.LocalPath != "fixed" || c.OutputDir != "contract-rechecks" || c.Command != "verify-contract" {
		t.Fatalf("wrong config: %+v", c)
	}
	if _, err = Parse([]string{"verify-contract", "--contract", "c.json"}); err == nil {
		t.Fatal("accepted missing fixed source")
	}
}
