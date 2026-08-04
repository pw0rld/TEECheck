#include "../include/shdr.h"

/* File-local. core/other.c defines a helper with the same name, and the two
 * must not collapse into one symbol — that collapse is what SymbolID
 * exists to prevent. */
static int helper(int v)
{
	return v + 1;
}

/* max_depth is written by direct assignment; version is deliberately never
 * written at all. Showing that difference without calling it a finding is
 * the whole job of the index. */
int load_pub_key(struct pub_key *key, const struct subkey *sub)
{
	key->max_depth = sub->max_depth;
	return helper(0);
}
