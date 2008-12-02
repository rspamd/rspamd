/*
 * Common tokenization functions
 */

#include <sys/types.h>
#include "tokenizers.h"

struct tokenizer tokenizers[] = {
	{"osb-text", osb_tokenize_text, get_next_word },
};

struct tokenizer*
get_tokenizer (char *name)
{
	int i;

	for (i = 0; i < sizeof (tokenizers) / sizeof (tokenizers[0]); i ++) {
		if (strcmp (tokenizers[i].name, name) == 0) {
			return &tokenizers[i];
		}
	}

	return NULL;
}

/* Get next word from specified f_str_t buf */
f_str_t *
get_next_word (f_str_t *buf, f_str_t *token)
{
	size_t remain;
	char *pos;
	
	if (buf == NULL) {
		return NULL;
	}

	if (token->begin == NULL) {
		token->begin = buf->begin;
	}

	remain = buf->len - (token->begin - buf->begin);
	if (remain <= 0) {
		return NULL;
	}

	token->begin = token->begin + token->len;
	token->len = 0;
	
	pos = token->begin;
	/* Skip non graph symbols */
	while (remain-- && !g_ascii_isgraph (*pos ++)) {
		token->begin ++;
	}
	while (remain-- && g_ascii_isgraph (*pos ++)) {
		token->len ++;
	}
	
	return token;
}

/*
 * vi:ts=4
 */
