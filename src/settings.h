#ifndef RSPAMD_SETTINGS_H
#define RSPAMD_SETTINGS_H

#include "config.h"
#include "main.h"

struct rspamd_settings {
	GHashTable *metric_scores;			/**< hash table of metric require scores for this setting		*/
	GHashTable *reject_scores;			/**< hash table of metric reject scores for this setting		*/
	GHashTable *metric_actions;			/**< hash table of metric actions for this setting				*/
	GHashTable *factors;				/**< hash table of new factors for this setting			*/
	GHashTable *whitelist;				/**< hash table of whitelist for this setting			*/
	GHashTable *blacklist;				/**< hash table of whitelist for this setting			*/
	gchar *statfile_alias;				/**< alias for statfile used							*/
	gboolean want_spam;					/**< if true disable rspamd checks						*/
	gint ref_count;						/**< reference counter									*/
};


/*
 * Read settings from specified path
 */
gboolean read_settings (const gchar *path, const gchar *description, struct config_file *cfg, GHashTable *table);

/*
 * Init configuration structures for settings
 */
void init_settings (struct config_file *cfg);

/*
 * Check scores settings
 */
gboolean check_metric_settings (struct metric_result *res, double *score, double *rscore);

/*
 * Check actions settings
 */
gboolean check_metric_action_settings (struct rspamd_task *task, struct metric_result *res, double score, enum rspamd_metric_action *result);

/*
 * Check individual weights for settings
 */
gboolean check_factor_settings (struct metric_result *res, const gchar *symbol, double *factor);

/*
 * Check want_spam flag
 */
gboolean check_want_spam (struct rspamd_task *task);

/*
 * Search settings for metric and store pointers to settings into metric_result structure
 */
gboolean apply_metric_settings (struct rspamd_task *task, struct metric *metric, struct metric_result *res);

#endif
