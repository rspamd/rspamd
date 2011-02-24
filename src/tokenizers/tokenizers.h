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

typedef struct token_node_s {
	uint32_t h1;
	uint32_t h2;
	float value;
	uintptr_t extra;
} token_node_t;

/* Common tokenizer structure */
struct tokenizer {
	char *name;
	int (*tokenize_func)(struct tokenizer *tokenizer, memory_pool_t *pool, f_str_t *input, GTree **cur);
	f_str_t* (*get_next_word)(f_str_t *buf, f_str_t *token);
};

/* Compare two token nodes */
int token_node_compare_func (gconstpointer a, gconstpointer b);
/* Get tokenizer structure by name or return NULL if this name is not found */
struct tokenizer* get_tokenizer (char *name);
/* Get next word from specified f_str_t buf */
f_str_t *get_next_word (f_str_t *buf, f_str_t *token);
/* OSB tokenize function */
int osb_tokenize_text (struct tokenizer *tokenizer, memory_pool_t *pool, f_str_t *input, GTree **cur);
/* Common tokenizer for headers */
int tokenize_headers (memory_pool_t *pool, struct worker_task *task, GTree **cur);
/* Make tokens for a subject */
void tokenize_subject (struct worker_task *task, GTree ** tree);

/* Array of all defined tokenizers */
extern struct tokenizer tokenizers[];

#endif
/*
 * vi:ts=4
 */
