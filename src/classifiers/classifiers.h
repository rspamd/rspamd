#ifndef CLASSIFIERS_H
#define CLASSIFIERS_H

#include "../config.h"
#include "../mem_pool.h"
#include "../statfile.h"
#include "../tokenizers/tokenizers.h"

struct classifier_config;
struct worker_task;

struct classifier_ctx {
	memory_pool_t *pool;
	GHashTable *results;
	struct classifier_config *cfg;
};
/* Common classifier structure */
struct classifier {
	char *name;
	struct classifier_ctx* (*init_func)(memory_pool_t *pool, struct classifier_config *cf);
	void (*classify_func)(struct classifier_ctx* ctx, statfile_pool_t *pool, GTree *input, struct worker_task *task);
	void (*learn_func)(struct classifier_ctx* ctx, statfile_pool_t *pool, 
							char *symbol, GTree *input, gboolean in_class);
};

/* Get classifier structure by name or return NULL if this name is not found */
struct classifier* get_classifier (char *name);

/* Winnow algorithm */
struct classifier_ctx* winnow_init (memory_pool_t *pool, struct classifier_config *cf);
void winnow_classify (struct classifier_ctx* ctx, statfile_pool_t *pool, GTree *input, struct worker_task *task);
void winnow_learn (struct classifier_ctx* ctx, statfile_pool_t *pool, char *symbol, GTree *input, gboolean in_class);

/* Array of all defined classifiers */
extern struct classifier classifiers[];

#endif
/*
 * vi:ts=4
 */
