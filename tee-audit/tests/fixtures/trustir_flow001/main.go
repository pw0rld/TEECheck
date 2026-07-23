// TWE-FLOW-001 fixture: a host-controlled input reaches a signing sink with no
// intervening TEE trust guard. Used by tests/test_trustir_fixture_fire.py to
// prove the FLOW-001 query FIRES on a known-good annotation + DB (hermetic — no
// suave DB, no LLM).
package main

// Sign is the security-relevant sink (role: signing_input).
func Sign(data []byte) []byte {
	out := append([]byte("sig:"), data...)
	return out
}

// HandleRequest is the host entry point. userInput (role: host_input) flows
// unguarded into Sign — a concrete TWE-FLOW-001 source->sink path.
func HandleRequest(userInput []byte) []byte {
	return Sign(userInput)
}

func main() {}
