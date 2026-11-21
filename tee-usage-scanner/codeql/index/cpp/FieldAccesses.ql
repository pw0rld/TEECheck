/**
 * @name Field accesses and direct field writes
 * @description Per function DEFINITION: every struct field touched inside
 *              that definition, and the subset provable as the target of a
 *              direct assignment.
 *
 *              Scoped to the definition's own file, not to the Function. A
 *              function defined in three backends has three sets of field
 *              accesses, and attributing the union to each would tell a
 *              reader that the core/crypto producer writes a field only the
 *              vendored implementation writes — a fact about someone else's
 *              code, in the field the CVE-2026-44362 shape is expressed in.
 *
 *              Two columns because CodeQL's FieldAccess matches an
 *              assignment's left-hand side too. A single "reads" column
 *              would silently contain writes, and a consumer comparing a
 *              producer's reads against a consumer's reads would be
 *              comparing the wrong sets without being able to tell.
 *
 *              direct_writes misses a field filled by memcpy, through a
 *              pointer alias, or by a designated initializer. Its absence is
 *              never proof that a field is unwritten.
 * @kind table
 * @id cpp/teecheck-index-field-accesses
 *
 * Columns: function_name, function_file, function_line, function_sig,
 *          accesses, direct_writes   (the last two comma-joined)
 */

import cpp
import Index

string qualified(Field fl) { result = fl.getDeclaringType().getName() + "." + fl.getName() }

/** Field accesses lexically inside one definition. */
predicate accessIn(FunctionDeclarationEntry d, Field fl) {
  exists(FieldAccess fa |
    fa.getEnclosingFunction() = d.getFunction() and
    fa.getFile() = d.getFile() and
    fa.getTarget() = fl
  )
}

/** Direct assignments to a field inside one definition. */
predicate writeIn(FunctionDeclarationEntry d, Field fl) {
  exists(Assignment a, FieldAccess fa |
    a.getEnclosingFunction() = d.getFunction() and
    a.getFile() = d.getFile() and
    a.getLValue() = fa and
    fa.getTarget() = fl
  )
}

from FunctionDeclarationEntry d, string accesses, string writes
where
  d = definitionOf(d.getFunction()) and
  accesses = concat(Field fl | accessIn(d, fl) | qualified(fl), ",") and
  writes = concat(Field fl | writeIn(d, fl) | qualified(fl), ",")
select d.getFunction().getName(), d.getFile().getRelativePath(),
  d.getLocation().getStartLine(), d.getFunction().getParameterString(), accesses, writes
