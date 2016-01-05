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
	void (*init_func)(rspamd_mempool_t *pool,
			struct rspamd_classifier *cl);
	gboolean (*classify_func)(struct rspamd_classifier * ctx,
			GPtrArray *tokens,
			struct rspamd_task *task);
	gboolean (*learn_spam_func)(struct rspamd_classifier * ctx,
			GPtrArray *input,
			struct rspamd_task *task, gboolean is_spam,
			GError **err);
};

/* Bayes algorithm */
void bayes_init (rspamd_mempool_t *pool,
		struct rspamd_classifier *);
gboolean bayes_classify (struct rspamd_classifier *ctx,
		GPtrArray *tokens,
		struct rspamd_task *task);
gboolean bayes_learn_spam (struct rspamd_classifier *ctx,
		GPtrArray *tokens,
		struct rspamd_task *task,
		gboolean is_spam,
		GError **err);

#endif
/*
 * vi:ts=4
 */
