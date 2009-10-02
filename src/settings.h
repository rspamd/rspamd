#ifndef RSPAMD_SETTINGS_H
#define RSPAMD_SETTINGS_H

#include "config.h"
#include "main.h"

struct rspamd_settings {
	GHashTable *metric_scores;			/**< hash table of metric require scores for this setting		*/
	GHashTable *reject_scores;			/**< hash table of metric reject scores for this setting		*/
	GHashTable *factors;				/**< hash table of new factors for this setting			*/
	char *statfile_alias;				/**< alias for statfile used							*/
	gboolean want_spam;					/**< if true disable rspamd checks						*/
};


gboolean read_settings (const char *path, struct config_file *cfg, GHashTable *table);
void init_settings (struct config_file *cfg);
gboolean check_metric_settings (struct worker_task *task, struct metric *metric, double *score, double *rscore);
gboolean check_factor_settings (struct worker_task *task, const char *symbol, double *factor);
gboolean check_want_spam (struct worker_task *task);

#endif
