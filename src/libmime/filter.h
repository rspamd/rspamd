/**
 * @file filter.h
 * Filters logic implemetation
 */

#ifndef RSPAMD_FILTER_H
#define RSPAMD_FILTER_H

#include "config.h"
#include "symbols_cache.h"
#include "task.h"

struct rspamd_task;
struct rspamd_settings;
struct rspamd_classifier_config;

/**
 * Rspamd symbol
 */
struct symbol {
	double score;                                   /**< symbol's score							*/
	GList *options;                                 /**< list of symbol's options				*/
	const gchar *name;
	struct rspamd_symbol_def *def;					/**< symbol configuration					*/
};

/**
 * Result of metric processing
 */
struct metric_result {
	struct metric *metric;                          /**< pointer to metric structure			*/
	double score;                                   /**< total score							*/
	double grow_factor;								/**< current grow factor					*/
	GHashTable *symbols;                            /**< symbols of metric						*/
	GHashTable *sym_groups;							/**< groups of symbols						*/
	gdouble actions_limits[METRIC_ACTION_MAX];		/**< set of actions for this metric			*/
	enum rspamd_metric_action action;               /**< the current action						*/
};

/**
 * Create or return existing result for the specified metric name
 * @param task task object
 * @param name name of metric
 * @return metric result or NULL if metric `name` has not been found
 */
struct metric_result * rspamd_create_metric_result (struct rspamd_task *task,
		const gchar *name);

/**
 * Insert a result to task
 * @param task worker's task that present message from user
 * @param metric_name metric's name to which we need to insert result
 * @param symbol symbol to insert
 * @param flag numeric weight for symbol
 * @param opts list of symbol's options
 */
void rspamd_task_insert_result (struct rspamd_task *task,
	const gchar *symbol,
	double flag,
	GList *opts);

/**
 * Insert a single result to task
 * @param task worker's task that present message from user
 * @param metric_name metric's name to which we need to insert result
 * @param symbol symbol to insert
 * @param flag numeric weight for symbol
 * @param opts list of symbol's options
 */
void rspamd_task_insert_result_single (struct rspamd_task *task,
	const gchar *symbol,
	double flag,
	GList *opts);

/**
 * Default consolidation function for metric, it get all symbols and multiply symbol
 * weight by some factor that is specified in config. Default factor is 1.
 * @param task worker's task that present message from user
 * @param metric_name name of metric
 * @return result metric weight
 */
double rspamd_factor_consolidation_func (struct rspamd_task *task,
	const gchar *metric_name,
	const gchar *unused);


/*
 * Get action from a string
 */
gboolean rspamd_action_from_str (const gchar *data, gint *result);

/*
 * Return textual representation of action enumeration
 */
const gchar * rspamd_action_to_str (enum rspamd_metric_action action);
const gchar * rspamd_action_to_str_alt (enum rspamd_metric_action action);

/*
 * Get action for specific metric
 */
enum rspamd_metric_action rspamd_check_action_metric (struct rspamd_task *task,
	struct metric_result *mres);

#endif
