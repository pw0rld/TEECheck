package actions

import "testing"

func TestIsSourceFile(t *testing.T) {
	cases := map[string]bool{
		"a.rs": true, "b.c": true, "c.h": true, "d.cc": true, "e.cpp": true, "f.hpp": true,
		"Cargo.toml": false, "README.md": false, "x.txt": false, "dir/y.C": true,
	}
	for path, want := range cases {
		if got := isSourceFile(path); got != want {
			t.Errorf("isSourceFile(%q) = %v, want %v", path, got, want)
		}
	}
}

func TestFunctionSignatureLine(t *testing.T) {
	hit := map[string]string{
		"fn verify(&self) -> bool {":        "verify",
		"pub async unsafe fn go() {":        "go",
		"int foo(int x) {":                  "foo",
		"static void bar(void)":             "bar",
		"TEE_Result handle_invoke(uint32_t":  "handle_invoke",
	}
	for line, want := range hit {
		got, ok := functionSignatureLine(line)
		if !ok || got != want {
			t.Errorf("functionSignatureLine(%q) = (%q,%v), want (%q,true)", line, got, ok, want)
		}
	}
	miss := []string{
		"    return foo();", "if (x > 0) {", "while (running) {",
		"    bar();", "int x = baz(1);", "} ", "// fn comment(",
	}
	for _, line := range miss {
		if got, ok := functionSignatureLine(line); ok {
			t.Errorf("functionSignatureLine(%q) = (%q,true), want ok=false", line, got)
		}
	}
}

func TestEnclosingFunctionText(t *testing.T) {
	src := []byte(`void outer(int x)
{
    if (x) {
        target();
    }
}

void other() {
    noop();
}
`)
	// target() is on line 4, inside outer
	if got := enclosingFunctionText(src, 4); got != "outer" {
		t.Errorf("enclosing(line 4) = %q, want outer", got)
	}
	// a call between the two functions is top-level
	if got := enclosingFunctionText(src, 7); got != "<top-level>" {
		t.Errorf("enclosing(line 7) = %q, want <top-level>", got)
	}
}

func TestTextOutline(t *testing.T) {
	src := []byte("struct Foo {\n    int a;\n};\n\nint compute(int x) {\n    return x;\n}\n")
	out := textOutline(src)
	if !contains(out, "compute") || !contains(out, "line 5") {
		t.Errorf("outline missing compute@line5:\n%s", out)
	}
	if !contains(out, "Foo") || !contains(out, "line 1") {
		t.Errorf("outline missing Foo@line1:\n%s", out)
	}
}

func contains(s, sub string) bool { return len(s) >= len(sub) && (func() bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub { return true }
	}
	return false
})() }
