#ifndef TOKENIZERS_H
#define TOKENIZERS_H

#include <sys/types.h>
#include "../config.h"

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif
#include "../mem_pool.h"
#include "../fstring.h"
#include "../main.h"

/* Size for features pipe */
#define FEATURE_WINDOW_SIZE 5

typedef struct token_list_s {
	uint32_t h1;
	uint32_t h2;
	struct token_list_s *next;
} token_list_t;

/* Get next word from specified f_str_t buf */
f_str_t *get_next_word (f_str_t *buf, f_str_t *token);

#endif
/*
 * vi:ts=4
 */
