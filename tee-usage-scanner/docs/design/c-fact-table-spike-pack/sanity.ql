import cpp
import GeneratedTrustFacts
predicate writesOutputField(Function producer, string field) {
  exists(Assignment a, FieldAccess fa |
    a.getLValue() = fa and fa.getTarget().getName() = field and
    fa.getEnclosingFunction() = producer)
}
from Function producer, string field
where GeneratedTrustFacts::isClaimProducer(producer, _) and
      GeneratedTrustFacts::rollbackVersionField(field) and
      writesOutputField(producer, field)
select producer, "writes rollback field '" + field + "'"
