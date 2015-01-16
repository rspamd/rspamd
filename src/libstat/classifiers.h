#ifndef CLASSIFIERS_H
#define CLASSIFIERS_H

#include "config.h"
#include "mem_pool.h"
#include "statfile.h"
#include "tokenizers.h"
#include <lua.h>

/* Consider this value as 0 */
#define ALPHA 0.0001

struct rspamd_classifier_config;
struct rspamd_task;

struct classifier_ctx {
	rspamd_mempool_t *pool;
	GHashTable *results;
	gboolean debug;
	struct rspamd_classifier_config *cfg;
};

struct classify_weight {
	const char *name;
	long double weight;
};

/* Common classifier structure */
struct classifier {
	char *name;
	struct classifier_ctx * (*init_func)(rspamd_mempool_t *pool,
		struct rspamd_classifier_config *cf);
	gboolean (*classify_func)(struct classifier_ctx * ctx,
		statfile_pool_t *pool, GTree *input, struct rspamd_task *task,
		lua_State *L);
	gboolean (*learn_func)(struct classifier_ctx * ctx, statfile_pool_t *pool,
		const char *symbol, GTree *input, gboolean in_class,
		double *sum, double multiplier, GError **err);
	gboolean (*learn_spam_func)(struct classifier_ctx * ctx,
		statfile_pool_t *pool,
		GTree *input, struct rspamd_task *task, gboolean is_spam, lua_State *L,
		GError **err);
	GList * (*weights_func)(struct classifier_ctx * ctx, statfile_pool_t *pool,
		GTree *input, struct rspamd_task *task);
};

/* Get classifier structure by name or return NULL if this name is not found */
struct classifier * get_classifier (const char *name);

/* Winnow algorithm */
struct classifier_ctx * winnow_init (rspamd_mempool_t *pool,
	struct rspamd_classifier_config *cf);
gboolean winnow_classify (struct classifier_ctx * ctx,
	statfile_pool_t *pool,
	GTree *input,
	struct rspamd_task *task,
	lua_State *L);
gboolean winnow_learn (struct classifier_ctx * ctx,
	statfile_pool_t *pool,
	const char *symbol,
	GTree *input,
	gboolean in_class,
	double *sum,
	double multiplier,
	GError **err);
gboolean winnow_learn_spam (struct classifier_ctx * ctx,
	statfile_pool_t *pool,
	GTree *input,
	struct rspamd_task *task,
	gboolean is_spam,
	lua_State *L,
	GError **err);
GList * winnow_weights (struct classifier_ctx * ctx,
	statfile_pool_t *pool,
	GTree *input,
	struct rspamd_task *task);

/* Bayes algorithm */
struct classifier_ctx * bayes_init (rspamd_mempool_t *pool,
	struct rspamd_classifier_config *cf);
gboolean bayes_classify (struct classifier_ctx * ctx,
	statfile_pool_t *pool,
	GTree *input,
	struct rspamd_task *task,
	lua_State *L);
gboolean bayes_learn (struct classifier_ctx * ctx,
	statfile_pool_t *pool,
	const char *symbol,
	GTree *input,
	gboolean in_class,
	double *sum,
	double multiplier,
	GError **err);
gboolean bayes_learn_spam (struct classifier_ctx * ctx,
	statfile_pool_t *pool,
	GTree *input,
	struct rspamd_task *task,
	gboolean is_spam,
	lua_State *L,
	GError **err);
GList * bayes_weights (struct classifier_ctx * ctx,
	statfile_pool_t *pool,
	GTree *input,
	struct rspamd_task *task);
/* Array of all defined classifiers */
extern struct classifier classifiers[];

#endif
/*
 * vi:ts=4
 */
