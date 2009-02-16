/*
 * Copyright (c) 2009, Rambler media
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY Rambler media ''AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL <copyright holder> BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

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

int 
token_node_compare_func (gconstpointer a, gconstpointer b)
{
	const token_node_t *aa = a, *bb = b;
	
	if (aa->h1 == bb->h1) {
		return aa->h2 - bb->h2;
	}

	return aa->h1 - bb->h1;
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

	token->begin = token->begin + token->len;
	token->len = 0;
	
	remain = buf->len - (token->begin - buf->begin);
	if (remain <= 0) {
		return NULL;
	}

	pos = token->begin;
	/* Skip non graph symbols */
	while (remain > 0 && !g_ascii_isgraph (*pos)) {
		token->begin ++;
		pos ++;
		remain --;
	}
	while (remain > 0 && g_ascii_isgraph (*pos)) {
		token->len ++;
		pos ++;
		remain --;
	}

	if (token->len == 0) {
		return NULL;
	}
	
	return token;
}

/*
 * vi:ts=4
 */
