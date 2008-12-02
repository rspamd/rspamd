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


/* Common tokenizer structure */
struct tokenizer {
	char *name;
	token_list_t* (*tokenize_func)(struct tokenizer *tokenizer, memory_pool_t *pool, f_str_t *input);
	f_str_t* (*get_next_word)(f_str_t *buf, f_str_t *token);
};

/* Get tokenizer structure by name or return NULL if this name is not found */
struct tokenizer* get_tokenizer (char *name);
/* Get next word from specified f_str_t buf */
f_str_t *get_next_word (f_str_t *buf, f_str_t *token);
/* OSB tokenize function */
token_list_t* osb_tokenize_text (struct tokenizer *tokenizer, memory_pool_t *pool, f_str_t *input);

/* Array of all defined tokenizers */
extern struct tokenizer tokenizers[];

#endif
/*
 * vi:ts=4
 */
