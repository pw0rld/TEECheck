#include "../include/shdr.h"

/* The second definition of backend_init. It writes a DIFFERENT field from
 * core/backend_a.c on purpose: a query scoped to the Function rather than to
 * the definition merges the two sets, and each definition then appears to
 * write a field only the other one writes. */
int backend_init(struct pub_key *key)
{
	key->version = 2;
	return 0;
}
