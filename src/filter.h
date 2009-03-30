/**
 * @file filter.h
 * Filters logic implemetation
 */

#ifndef RSPAMD_FILTER_H
#define RSPAMD_FILTER_H

#include "config.h"

struct worker_task;

typedef double (*metric_cons_func)(struct worker_task *task, const char *metric_name, const char *func_name);
typedef void (*filter_func)(struct worker_task *task);

enum filter_type { C_FILTER, PERL_FILTER };

/**
 * Filter structure
 */
struct filter {
	char *func_name;								/**< function name					*/
	enum filter_type type;							/**< filter type (c or perl)		*/
	LIST_ENTRY (filter) next;						/**< chain link						*/
};

/**
 * Rspamd symbol
 */
struct symbol {
	double score;									/**< symbol's score					*/
	GList *options;									/**< list of symbol's options		*/
};

/**
 * Common definition of metric
 */
struct metric {
	char *name;										/**< name of metric							*/
	char *func_name;								/**< name of consolidation function			*/
	metric_cons_func func;							/**< c consolidation function				*/
	double required_score;							/**< required score for this metric			*/
	struct classifier *classifier;					/**< classifier that is used for metric		*/
};

/**
 * Result of metric processing
 */
struct metric_result {
	struct metric *metric;							/**< pointer to metric structure			*/
	double score;									/**< total score							*/
	GHashTable *symbols;							/**< symbols of metric						*/
};

/**
 * Process all filters
 * @param task worker's task that present message from user
 * @return 0 - if there is non-finished tasks and 1 if processing is completed
 */
int process_filters (struct worker_task *task);

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
void insert_result (struct worker_task *task, const char *metric_name, const char *symbol, double flag, GList *opts);

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
double factor_consolidation_func (struct worker_task *task, const char *metric_name, const char *unused);

#endif
