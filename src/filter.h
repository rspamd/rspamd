/**
 * @file filter.h
 * Filters logic implemetation
 */

#ifndef RSPAMD_FILTER_H
#define RSPAMD_FILTER_H

#include "config.h"
#include "symbols_cache.h"

struct worker_task;

typedef double (*metric_cons_func)(struct worker_task *task, const gchar *metric_name, const gchar *func_name);
typedef void (*filter_func)(struct worker_task *task);

enum filter_type { C_FILTER, PERL_FILTER };

/**
 * Filter structure
 */
struct filter {
	gchar *func_name;								/**< function name							*/
	enum filter_type type;							/**< filter type (c or perl)				*/
    module_t *module;
};

/**
 * Rspamd symbol
 */
struct symbol {
	double score;									/**< symbol's score							*/
	GList *options;									/**< list of symbol's options				*/
	const gchar *name;
};

enum rspamd_metric_action {
	METRIC_ACTION_REJECT = 0,
	METRIC_ACTION_SOFT_REJECT,
	METRIC_ACTION_REWRITE_SUBJECT,
	METRIC_ACTION_ADD_HEADER,
	METRIC_ACTION_GREYLIST,
	METRIC_ACTION_NOACTION
};

struct metric_action {
	enum rspamd_metric_action action;
	gdouble score;
};

/**
 * Common definition of metric
 */
struct metric {
	gchar *name;									/**< name of metric									*/
	gchar *func_name;								/**< name of consolidation function					*/
	metric_cons_func func;							/**< c consolidation function						*/
	double grow_factor;								/**< grow factor for metric							*/
	double required_score;							/**< required score for this metric					*/
	double reject_score;							/**< reject score for this metric					*/
	GHashTable *symbols;							/**< weights of symbols in metric					*/
	GHashTable *descriptions;						/**< descriptions of symbols in metric				*/
	enum rspamd_metric_action action;				/**< action to do by this metric by default		  	*/
	GList *actions;									/**< actions that can be performed by this metric 	*/
};

/**
 * Result of metric processing
 */
struct metric_result {
	struct metric *metric;							/**< pointer to metric structure			*/
	double score;									/**< total score							*/
	GHashTable *symbols;							/**< symbols of metric						*/
	gboolean checked;								/**< whether metric result is consolidated  */
	double grow_factor;								/**< current grow factor					*/
};

/**
 * Process all filters
 * @param task worker's task that present message from user
 * @return 0 - if there is non-finished tasks and 1 if processing is completed
 */
gint process_filters (struct worker_task *task);

/**
 * Process message with statfiles
 * @param task worker's task that present message from user
 */
void process_statfiles (struct worker_task *task);

/**
 * Insert a result to task
 * @param task worker's task that present message from user
 * @param metric_name metric's name to which we need to insert result
 * @param symbol symbol to insert
 * @param flag numeric weight for symbol
 * @param opts list of symbol's options
 */
void insert_result (struct worker_task *task, const gchar *symbol, double flag, GList *opts);

/**
 * Insert a single result to task
 * @param task worker's task that present message from user
 * @param metric_name metric's name to which we need to insert result
 * @param symbol symbol to insert
 * @param flag numeric weight for symbol
 * @param opts list of symbol's options
 */
void insert_result_single (struct worker_task *task, const gchar *symbol, double flag, GList *opts);

/**
 * Process all results and form composite metrics from existent metrics as it is defined in config
 * @param task worker's task that present message from user
 */
void make_composites (struct worker_task *task);

/**
 * Default consolidation function for metric, it get all symbols and multiply symbol 
 * weight by some factor that is specified in config. Default factor is 1.
 * @param task worker's task that present message from user
 * @param metric_name name of metric
 * @return result metric weight
 */
double factor_consolidation_func (struct worker_task *task, const gchar *metric_name, const gchar *unused);

/*
 * Learn specified statfile with message in a task
 * @param statfile symbol of statfile
 * @param task worker's task object
 * @param err pointer to GError
 * @return true if learn succeed
 */
gboolean learn_task (const gchar *statfile, struct worker_task *task, GError **err);

gboolean check_action_str (const gchar *data, gint *result);
const gchar *str_action_metric (enum rspamd_metric_action action);
gint check_metric_action (double score, double required_score, struct metric *metric);

#endif
