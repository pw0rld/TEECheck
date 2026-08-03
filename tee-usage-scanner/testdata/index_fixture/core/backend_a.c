#include "../include/shdr.h"

/* One function, two definitions — the OP-TEE weak-stub-plus-backend shape.
 * Under --build-mode=none each file is extracted independently, so CodeQL
 * holds ONE Function entity whose getFile() and getLocation() each have two
 * results. A query that mentions both without binding a single definition
 * entry pairs them independently and emits a row for
 * core/backend_a.c at core/backend_b.c's line — a location describing
 * nothing, which a planner would open and find a different function. */
int backend_init(struct pub_key *key)
{
	key->max_depth = 1;
	return 0;
}
