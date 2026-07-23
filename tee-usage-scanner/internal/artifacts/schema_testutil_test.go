package artifacts

import (
	"encoding/json"
	"testing"
)

// This file holds generic JSON-mutation helpers shared by the per-schema
// validation tests in schema_validation_test.go. The canonical Go structs
// are deliberately built so a normal Go value already satisfies its schema
// (that is the whole point of PR-01), so constructing an *invalid* instance
// means mutating already-valid JSON rather than fighting the struct's own
// zero values.
//
// A path is a mix of string (object key) and int (array index) segments,
// e.g. mustMutate(t, data, "rejected", "agent_assessment", "status").

func marshalJSON(t *testing.T, v any) []byte {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return data
}

func decodeAny(t *testing.T, data []byte) any {
	t.Helper()
	var v any
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return v
}

func navigateToParent(t *testing.T, root any, path []any) any {
	t.Helper()
	cur := root
	for _, seg := range path[:len(path)-1] {
		switch s := seg.(type) {
		case string:
			m, ok := cur.(map[string]any)
			if !ok {
				t.Fatalf("path segment %q: not an object", s)
			}
			cur = m[s]
		case int:
			arr, ok := cur.([]any)
			if !ok {
				t.Fatalf("path segment %d: not an array", s)
			}
			cur = arr[s]
		default:
			t.Fatalf("unsupported path segment %v (%T)", seg, seg)
		}
	}
	return cur
}

// withField returns data with the field at path set to value.
func withField(t *testing.T, data []byte, value any, path ...any) []byte {
	t.Helper()
	root := decodeAny(t, data)
	parent := navigateToParent(t, root, path)
	last := path[len(path)-1]
	switch key := last.(type) {
	case string:
		m, ok := parent.(map[string]any)
		if !ok {
			t.Fatalf("path %v: parent is not an object", path)
		}
		m[key] = value
	case int:
		arr, ok := parent.([]any)
		if !ok {
			t.Fatalf("path %v: parent is not an array", path)
		}
		arr[key] = value
	default:
		t.Fatalf("unsupported path segment %v (%T)", last, last)
	}
	out, err := json.Marshal(root)
	if err != nil {
		t.Fatalf("remarshal: %v", err)
	}
	return out
}

// withoutField returns data with the object key at path removed.
func withoutField(t *testing.T, data []byte, path ...any) []byte {
	t.Helper()
	root := decodeAny(t, data)
	parent := navigateToParent(t, root, path)
	key, ok := path[len(path)-1].(string)
	if !ok {
		t.Fatalf("withoutField: last path segment must be a string object key, got %v", path[len(path)-1])
	}
	m, ok := parent.(map[string]any)
	if !ok {
		t.Fatalf("path %v: parent is not an object", path)
	}
	delete(m, key)
	out, err := json.Marshal(root)
	if err != nil {
		t.Fatalf("remarshal: %v", err)
	}
	return out
}
