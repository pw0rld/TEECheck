/* A miniature of the shapes the program index has to represent correctly.
 * Kept tiny on purpose: this is the fixture that proves the queries match
 * what they claim, and a large one would make a failure hard to read. */
#ifndef SHDR_H
#define SHDR_H

typedef unsigned long size_t;
void *memcpy(void *dest, const void *src, size_t n);

struct pub_key {
	unsigned int version;
	unsigned int max_depth;
};

struct subkey {
	unsigned int subkey_version;
	unsigned int max_depth;
};

/* Dispatch through a function pointer: the call site the extractor cannot
 * resolve to a definition. */
struct ops {
	int (*load)(struct pub_key *key);
};

#endif
