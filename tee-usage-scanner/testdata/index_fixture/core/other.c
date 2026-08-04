#include "../include/shdr.h"

/* Same name as core/loader.c's helper, different definition. */
static int helper(int v)
{
	return v - 1;
}

int other_entry(void)
{
	return helper(2);
}
