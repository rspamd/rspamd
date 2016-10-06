#ifndef CLASSIFIERS_H
#define CLASSIFIERS_H

#include "config.h"
#include "mem_pool.h"

#define RSPAMD_DEFAULT_CLASSIFIER "bayes"
/* Consider this value as 0 */
#define ALPHA 0.0001

struct rspamd_classifier_config;
struct rspamd_task;
struct rspamd_classifier;

struct token_node_s;

struct rspamd_stat_classifier {
	char *name;
	gboolean (*init_func)(rspamd_mempool_t *pool,
			struct rspamd_classifier *cl);
	gboolean (*classify_func)(struct rspamd_classifier * ctx,
			GPtrArray *tokens,
			struct rspamd_task *task);
	gboolean (*learn_spam_func)(struct rspamd_classifier * ctx,
			GPtrArray *input,
			struct rspamd_task *task,
			gboolean is_spam,
			gboolean unlearn,
			GError **err);
};

/* Bayes algorithm */
gboolean bayes_init (rspamd_mempool_t *pool,
		struct rspamd_classifier *);
gboolean bayes_classify (struct rspamd_classifier *ctx,
		GPtrArray *tokens,
		struct rspamd_task *task);
gboolean bayes_learn_spam (struct rspamd_classifier *ctx,
		GPtrArray *tokens,
		struct rspamd_task *task,
		gboolean is_spam,
		gboolean unlearn,
		GError **err);

/* Generic lua classifier */
gboolean lua_classifier_init (rspamd_mempool_t *pool,
		struct rspamd_classifier *);
gboolean lua_classifier_classify (struct rspamd_classifier *ctx,
		GPtrArray *tokens,
		struct rspamd_task *task);
gboolean lua_classifier_learn_spam (struct rspamd_classifier *ctx,
		GPtrArray *tokens,
		struct rspamd_task *task,
		gboolean is_spam,
		gboolean unlearn,
		GError **err);


#endif
/*
 * vi:ts=4
 */
