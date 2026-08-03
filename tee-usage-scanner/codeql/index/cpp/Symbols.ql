/**
 * @name Symbols
 * @description Every function definition, with the parts that make its
 *              identity stable. Two files can each define a static function
 *              of the same name and one translation unit can hold overloads,
 *              so name alone is not an identity: file, line and signature
 *              are what separate them.
 * @kind table
 * @id teecheck/index/symbols
 *
 * Columns: name, file, start_line, signature, module
 */

import cpp

/**
 * The module a file belongs to: the directory containing it, truncated to
 * two path components.
 *
 * Two levels is what distinguishes core/crypto from core/kernel on OP-TEE
 * while keeping lib/libmbedtls whole. Deeper would fragment a module into
 * its subdirectories; shallower would put all 2216 files of core/ in one
 * bucket and lose the distinction the Planner navigates by.
 */
string moduleOf(File f) {
  result = f.getRelativePath().regexpCapture("^([^/]+/[^/]+)/.*$", 1)
  or
  result = f.getRelativePath().regexpCapture("^([^/]+)/[^/]+$", 1)
  or
  not f.getRelativePath().matches("%/%") and result = "."
}

from Function f
where f.hasDefinition() and exists(f.getFile().getRelativePath())
select f.getName(), f.getFile().getRelativePath(), f.getLocation().getStartLine(),
  f.getParameterString(), moduleOf(f.getFile())
