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

typedef double (*metric_cons_func)(struct rspamd_task *task,
	const gchar *metric_name, const gchar *func_name);
typedef void (*filter_func)(struct rspamd_task *task);

enum filter_type { C_FILTER, PERL_FILTER };

/**
 * Filter structure
 */
struct filter {
	gchar *func_name;                               /**< function name							*/
	enum filter_type type;                          /**< filter type (c or perl)				*/
	module_t *module;
};

/**
 * Rspamd symbol
 */
struct symbol {
	double score;                                   /**< symbol's score							*/
	GList *options;                                 /**< list of symbol's options				*/
	const gchar *name;
	struct rspamd_symbol_def *def;					/**< symbol configuration					*/
};

struct metric_action {
	enum rspamd_metric_action action;
	gdouble score;
};

/**
 * Common definition of metric
 */
struct metric {
	const gchar *name;                              /**< name of metric									*/
	gchar *func_name;                               /**< name of consolidation function					*/
	metric_cons_func func;                          /**< c consolidation function						*/
	gboolean accept_unknown_symbols;                /**< if true unknown symbols are registered here	*/
	gdouble unknown_weight;                         /**< weight of unknown symbols						*/
	gdouble grow_factor;                            /**< grow factor for metric							*/
	GHashTable *symbols;                            /**< weights of symbols in metric					*/
	GHashTable *descriptions;                       /**< descriptions of symbols in metric				*/
	struct metric_action actions[METRIC_ACTION_MAX]; /**< all actions of the metric					*/
	gchar *subject;                                 /**< subject rewrite string							*/
};

/**
 * Result of metric processing
 */
struct metric_result {
	struct metric *metric;                          /**< pointer to metric structure			*/
	double score;                                   /**< total score							*/
	enum rspamd_metric_action action;				/**< the current action						*/
	GHashTable *symbols;                            /**< symbols of metric						*/
	GHashTable *sym_groups;							/**< groups of symbols						*/
	gboolean checked;                               /**< whether metric result is consolidated  */
	double grow_factor;                             /**< current grow factor					*/
};


/**
 * Subr for composite expressions
 */
extern const struct rspamd_atom_subr composite_expr_subr;
/**
 * Composite structure
 */
struct rspamd_composite {
	struct rspamd_expression *expr;
	gint id;
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
 * Process all filters
 * @param task worker's task that present message from user
 * @return 0 - if there is non-finished tasks and 1 if processing is completed
 */
gint rspamd_process_filters (struct rspamd_task *task);

/**
 * Process message with statfiles
 * @param task worker's task that present message from user
 */
void rspamd_process_statistics (struct rspamd_task *task);

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
 * Process all results and form composite metrics from existent metrics as it is defined in config
 * @param task worker's task that present message from user
 */
void rspamd_make_composites (struct rspamd_task *task);

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


/**
 * Learn specified statfile with message in a task
 * @param statfile symbol of statfile
 * @param task worker's task object
 * @param err pointer to GError
 * @return true if learn succeed
 */
gboolean rspamd_learn_task_spam (struct rspamd_classifier_config *cl,
	struct rspamd_task *task,
	gboolean is_spam,
	GError **err);

/*
 * Get action from a string
 */
gboolean rspamd_action_from_str (const gchar *data, gint *result);

/*
 * Return textual representation of action enumeration
 */
const gchar * rspamd_action_to_str (enum rspamd_metric_action action);

/*
 * Get action for specific metric
 */
gint rspamd_check_action_metric (struct rspamd_task *task,
	double score,
	double *rscore,
	struct metric *metric);

#endif
