/*
 * OSB tokenizer
 */

#include <sys/types.h>
#include "tokenizers.h"


/* Coefficients that are used for OSB tokenizer */
static const int primes[] = {
	1, 7,
	3, 13,
	5, 29,
	11, 51,
	23, 101,
	47, 203,
	97, 407,
	197, 817,
	397, 1637,
	797, 3277,
};

GTree *
osb_tokenize_text (struct tokenizer *tokenizer, memory_pool_t *pool, f_str_t *input)
{
	token_node_t *new = NULL;
	GTree *tree;
	f_str_t token = { NULL, 0, 0 };
	uint32_t hashpipe[FEATURE_WINDOW_SIZE], h1, h2;
	int i;

	/* First set all bytes of hashpipe to some common value */
	for (i = 0; i < FEATURE_WINDOW_SIZE; i ++) {
		hashpipe[i] = 0xABCDEF;
	}

	tree = g_tree_new (token_node_compare_func);
	memory_pool_add_destructor (pool, (pool_destruct_func)g_tree_destroy, tree);

	while (tokenizer->get_next_word (input, &token)) {
		/* Shift hashpipe */
		for (i = FEATURE_WINDOW_SIZE - 1; i > 0; i --) {
			hashpipe[i] = hashpipe[i - 1];
		}
		hashpipe[0] = fstrhash (&token);
		msg_debug ("osb_tokenize_text: text token %s, hash: %d", fstrcstr (&token, pool), hashpipe[0]);
		
		for (i = 1; i < FEATURE_WINDOW_SIZE; i ++) {
			h1 = hashpipe[0]* primes[0] + hashpipe[i] * primes[i<<1];
		    h2 = hashpipe[0] * primes[1] + hashpipe[i] * primes[(i<<1)-1];
			new = memory_pool_alloc (pool, sizeof (token_node_t));
			new->h1 = h1;
			new->h2 = h2;

			if (g_tree_lookup (tree, new) == NULL) {
				msg_debug ("osb_tokenize_text: append new token, h1=%u, h2=%u", h1, h2);
				g_tree_insert (tree, new, new);
			}
		}
	}

	return tree;
}

/*
 * vi:ts=4
 */
