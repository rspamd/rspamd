#ifndef CLASSIFIERS_H
#define CLASSIFIERS_H

#include <sys/types.h>
#include "../config.h"

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif
#include "../mem_pool.h"
#include "../statfile.h"
#include "../tokenizers/tokenizers.h"

struct classifier_ctx {
	memory_pool_t *pool;
	GHashTable *results;
};
/* Common classifier structure */
struct classifier {
	char *name;
	struct classifier_ctx* (*init_func)(memory_pool_t *pool);
	void (*classify_func)(struct classifier_ctx* ctx, statfile_pool_t *pool, 
							char *statfile, GTree *input, double scale);
	void (*learn_func)(struct classifier_ctx* ctx, statfile_pool_t *pool, 
							char *statfile, GTree *input, int in_class);
	char* (*result_file_func)(struct classifier_ctx *ctx, double *probability);
};

/* Get classifier structure by name or return NULL if this name is not found */
struct classifier* get_classifier (char *name);

/* Winnow algorithm */
struct classifier_ctx* winnow_init (memory_pool_t *pool);
void winnow_classify (struct classifier_ctx* ctx, statfile_pool_t *pool, char *statfile, GTree *input, double scale);
void winnow_learn (struct classifier_ctx* ctx, statfile_pool_t *pool, char *statfile, GTree *input, int in_class);
char* winnow_result_file (struct classifier_ctx* ctx, double *probability);

/* Array of all defined classifiers */
extern struct classifier classifiers[];

#endif
/*
 * vi:ts=4
 */
