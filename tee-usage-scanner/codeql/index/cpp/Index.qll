/**
 * Shared identity for the program index queries.
 *
 * Every query here binds ONE FunctionDeclarationEntry per row. A CodeQL
 * `Function` is one entity even when the tree defines it several times — a
 * weak stub plus per-backend implementations is the normal OP-TEE shape —
 * and `getFile()` and `getLocation()` then each have several results. A
 * select that mentions both pairs them independently and emits a cross
 * product: on OP-TEE@a9386bf that turned 12,098 real definitions into 16,014
 * rows, so `crypto_acipher_sm2_kep_derive` acquired an id naming
 * core/crypto/crypto.c:403 — a file and a line from two different
 * definitions, describing nothing. A planner opening that location finds a
 * different function.
 *
 * Binding the entry is what makes file, line and module come from one
 * definition.
 */

import cpp

/**
 * The module a file belongs to: the directory containing it, truncated to
 * two path components.
 *
 * MUST agree with ModuleOf in internal/projectmap/cards.go. The index
 * assigns capsules to modules and that function counts files into them; if
 * they disagree, a module's two numbers describe different sets and the
 * ratio a reader uses to tell first-party code from vendored code means
 * nothing.
 *
 * Two levels distinguishes core/crypto from core/kernel on OP-TEE while
 * keeping lib/libmbedtls whole. Deeper fragments a module into its
 * subdirectories; shallower puts all 2216 files of core/ in one bucket.
 */
string moduleOf(File f) {
  result = f.getRelativePath().regexpCapture("^([^/]+/[^/]+)/.*$", 1)
  or
  result = f.getRelativePath().regexpCapture("^([^/]+)/[^/]+$", 1)
  or
  not f.getRelativePath().matches("%/%") and result = "."
}

/** Every definition of `f` that lives in the extracted tree. */
FunctionDeclarationEntry definitionOf(Function f) {
  result = f.getDefinition() and
  exists(result.getFile().getRelativePath())
}

/**
 * The definition a call site sits inside.
 *
 * Pinned by file: a call in core/crypto/crypto.c belongs to the definition
 * in core/crypto/crypto.c, not to the same function's implementation in
 * lib/libmbedtls. Without this the enclosing id is drawn from the same cross
 * product the module doc comment describes.
 */
FunctionDeclarationEntry enclosingDefinition(Call c) {
  result = definitionOf(c.getEnclosingFunction()) and
  result.getFile() = c.getFile()
}

/** The parameter list, in the parenthesised form SymbolID carries. */
string signatureOf(FunctionDeclarationEntry d) { result = "(" + d.getFunction().getParameterString() + ")" }
