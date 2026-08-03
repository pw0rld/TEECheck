/**
 * @name Field accesses and direct field writes
 * @description Per function: every struct field it touches, and the subset
 *              provable as the target of a direct assignment.
 *
 *              Two columns rather than one because CodeQL's FieldAccess
 *              matches an assignment's left-hand side too. A single "reads"
 *              column would silently contain writes, and a consumer
 *              comparing a producer's reads against a consumer's reads would
 *              be comparing the wrong sets without being able to tell.
 *
 *              direct_writes misses a field filled by memcpy, through a
 *              pointer alias, or by a designated initializer. Its absence is
 *              never proof that a field is unwritten — see the fixture's
 *              fill_version, which copies into a field with no assignment
 *              expression anywhere.
 * @kind table
 * @id teecheck/index/field-accesses
 *
 * Columns: function_name, function_file, function_line, function_sig,
 *          accesses, direct_writes   (the last two comma-joined)
 */

import cpp

string qualified(Field fl) { result = fl.getDeclaringType().getName() + "." + fl.getName() }

from Function f, string accesses, string writes
where
  f.hasDefinition() and
  exists(f.getFile().getRelativePath()) and
  accesses =
    concat(Field fl |
      exists(FieldAccess fa | fa.getEnclosingFunction() = f and fa.getTarget() = fl)
    | qualified(fl), ",") and
  writes =
    concat(Field fl |
      exists(Assignment a, FieldAccess fa |
        a.getEnclosingFunction() = f and a.getLValue() = fa and fa.getTarget() = fl)
    | qualified(fl), ",")
select f.getName(), f.getFile().getRelativePath(), f.getLocation().getStartLine(),
  f.getParameterString(), accesses, writes
