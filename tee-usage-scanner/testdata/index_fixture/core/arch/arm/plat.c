#include "../../../include/shdr.h"

/* Three levels deep on purpose: this is the only file that exercises the
 * moduleOf branch producing a two-component module (core/arch). Without it
 * the branch that yields core/crypto and lib/libmbedtls on a real repository
 * is tested by nothing. */
int plat_init(struct pub_key *key)
{
	key->max_depth = 0;
	return 0;
}
