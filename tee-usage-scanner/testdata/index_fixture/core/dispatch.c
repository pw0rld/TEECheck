#include "../include/shdr.h"

int check_version(const struct pub_key *key)
{
	return key->version == 0;
}

/* Both fields are touched, neither is written by an assignment expression.
 * They must appear in field_accesses and NOT in direct_field_writes, so a
 * consumer cannot read the absence of a write as "never written". */
void fill_version(struct pub_key *key, const struct subkey *sub)
{
	memcpy(&key->version, &sub->subkey_version, sizeof(key->version));
}

/* No resolvable target. */
int dispatch(struct ops *o, struct pub_key *key)
{
	return o->load(key);
}
