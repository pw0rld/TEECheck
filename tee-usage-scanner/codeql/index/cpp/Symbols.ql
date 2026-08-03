/**
 * @name Symbols
 * @description One row per function DEFINITION, with the parts that make its
 *              identity stable: two files can each define a static function
 *              of the same name, one translation unit can hold overloads,
 *              and one function can be defined several times across
 *              backends.
 *
 *              The row is bound to a single FunctionDeclarationEntry — see
 *              Index.qll for what happens when file and line are drawn from
 *              the Function instead.
 * @kind table
 * @id teecheck/index/symbols
 *
 * Columns: name, file, start_line, signature, module
 */

import cpp
import Index

from FunctionDeclarationEntry d
where d = definitionOf(d.getFunction())
select d.getFunction().getName(), d.getFile().getRelativePath(),
  d.getLocation().getStartLine(), d.getFunction().getParameterString(), moduleOf(d.getFile())
