/**
 * @file scan_result.h
 * Scan result holder
 */

#ifndef RSPAMD_SCAN_RESULT_H
#define RSPAMD_SCAN_RESULT_H

#include "config.h"
#include "rspamd_symcache.h"
#include "task.h"

#ifdef  __cplusplus
extern "C" {
#endif

struct rspamd_task;
struct rspamd_settings;
struct rspamd_classifier_config;

struct rspamd_symbol_option {
	gchar *option;
	gsize optlen;
	struct rspamd_symbol_option *prev, *next;
};

enum rspamd_symbol_result_flags {
	RSPAMD_SYMBOL_RESULT_NORMAL = 0,
	RSPAMD_SYMBOL_RESULT_IGNORED = (1 << 0)
};

struct kh_rspamd_options_hash_s;

/**
 * Rspamd symbol
 */
struct rspamd_symbol_result {
	double score;                                  /**< symbol's score							*/
	struct kh_rspamd_options_hash_s *options;         /**< list of symbol's options				*/
	struct rspamd_symbol_option *opts_head;        /**< head of linked list of options			*/
	const gchar *name;
	struct rspamd_symbol *sym;                     /**< symbol configuration					*/
	gssize opts_len; /**< total size of all options (negative if truncated option is added) */
	guint nshots;
	enum rspamd_symbol_result_flags flags;
};


#define RSPAMD_PASSTHROUGH_NORMAL 1
#define RSPAMD_PASSTHROUGH_LOW 0
#define RSPAMD_PASSTHROUGH_HIGH 2
#define RSPAMD_PASSTHROUGH_CRITICAL 3

#define RSPAMD_PASSTHROUGH_LEAST (1u << 0u)
#define RSPAMD_PASSTHROUGH_NO_SMTP_MESSAGE (1u << 0u)

struct rspamd_passthrough_result {
	struct rspamd_action *action;
	guint priority;
	guint flags;
	double target_score;
	const gchar *message;
	const gchar *module;
	struct rspamd_passthrough_result *prev, *next;
};

struct rspamd_action_result {
	gdouble cur_limit;
	struct rspamd_action *action;
};

struct kh_rspamd_symbols_hash_s;
struct kh_rspamd_symbols_group_hash_s;


struct rspamd_scan_result {
	double score;                                    /**< total score							*/
	double grow_factor;                                /**< current grow factor					*/
	struct rspamd_passthrough_result *passthrough_result;
	guint npositive;
	guint nnegative;
	double positive_score;
	double negative_score;
	struct kh_rspamd_symbols_hash_s *symbols;            /**< symbols of metric						*/
	struct kh_rspamd_symbols_group_hash_s *sym_groups; /**< groups of symbols						*/
	struct rspamd_action_result *actions_limits;
	guint nactions;
};

/**
 * Create or return existing result for the specified metric name
 * @param task task object
 * @return metric result or NULL if metric `name` has not been found
 */
struct rspamd_scan_result *rspamd_create_metric_result (struct rspamd_task *task);

/**
 * Adds a new passthrough result to a task
 * @param task
 * @param action
 * @param priority
 * @param target_score
 * @param message
 * @param module
 */
void rspamd_add_passthrough_result (struct rspamd_task *task,
									struct rspamd_action *action,
									guint priority,
									double target_score,
									const gchar *message,
									const gchar *module,
									guint flags);

enum rspamd_symbol_insert_flags {
	RSPAMD_SYMBOL_INSERT_DEFAULT = 0,
	RSPAMD_SYMBOL_INSERT_SINGLE = (1 << 0),
	RSPAMD_SYMBOL_INSERT_ENFORCE = (1 << 1),
};

/**
 * Insert a result to task
 * @param task worker's task that present message from user
 * @param metric_name metric's name to which we need to insert result
 * @param symbol symbol to insert
 * @param weight numeric weight for symbol
 * @param opts list of symbol's options
 */
struct rspamd_symbol_result *rspamd_task_insert_result_full (struct rspamd_task *task,
															 const gchar *symbol,
															 double weight,
															 const gchar *opts,
															 enum rspamd_symbol_insert_flags flags);

#define rspamd_task_insert_result_single(task, symbol, flag, opts) \
    rspamd_task_insert_result_full (task, symbol, flag, opts, RSPAMD_SYMBOL_INSERT_SINGLE)
#define rspamd_task_insert_result(task, symbol, flag, opts) \
    rspamd_task_insert_result_full (task, symbol, flag, opts, RSPAMD_SYMBOL_INSERT_DEFAULT)


/**
 * Adds new option to symbol
 * @param task
 * @param s
 * @param opt
 */
gboolean rspamd_task_add_result_option (struct rspamd_task *task,
										struct rspamd_symbol_result *s,
										const gchar *opt,
										gsize vlen);

/**
 * Finds symbol result
 * @param task
 * @param sym
 * @return
 */
struct rspamd_symbol_result *rspamd_task_find_symbol_result (
		struct rspamd_task *task, const char *sym);

/**
 * Compatibility function to iterate on symbols hash
 * @param task
 * @param func
 * @param ud
 */
void rspamd_task_symbol_result_foreach (struct rspamd_task *task,
										GHFunc func,
										gpointer ud);

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
 * Check thresholds and return action for a task
 * @param task
 * @return
 */
struct rspamd_action *rspamd_check_action_metric (struct rspamd_task *task,
												  struct rspamd_passthrough_result **ppr);

#ifdef  __cplusplus
}
#endif

#endif
