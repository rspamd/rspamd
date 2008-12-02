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

token_list_t *
osb_tokenize_text (struct tokenizer *tokenizer, memory_pool_t *pool, f_str_t *input)
{
	token_list_t *new = NULL, *head = NULL, *last = NULL;
	f_str_t token = { NULL, 0, 0 };
	uint32_t hashpipe[FEATURE_WINDOW_SIZE], h1, h2;
	int i;

	/* First set all bytes of hashpipe to some common value */
	for (i = 0; i < FEATURE_WINDOW_SIZE; i ++) {
		hashpipe[i] = 0xABCDEF;
	}

	while (tokenizer->get_next_word (input, &token)) {
		/* Shift hashpipe */
		for (i = FEATURE_WINDOW_SIZE - 1; i > 0; i --) {
			hashpipe[i] = hashpipe[i - 1];
		}
		hashpipe[0] = fstrhash (&token);
		
		for (i = 0; i < FEATURE_WINDOW_SIZE - 2; i ++) {
			h1 = hashpipe[0]* primes[0] + hashpipe[i] * primes[i<<1];
		    h2 = hashpipe[0] * primes[1] + hashpipe[i] * primes[(i<<1)-1];
			new = memory_pool_alloc (pool, sizeof (token_list_t));
			new->h1 = h1;
			new->h2 = h2;
			if (last) {
				last->next = new;
			}
			else {
				head = new;
			}
			last = new;

			msg_debug ("osb_tokenize_text: append new token, h1=%u, h2=%u", h1, h2);
		}
	}
	if (last) {
		last->next = NULL;
	}

	return head;
}

/*
 * vi:ts=4
 */
