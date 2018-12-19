/**
 * @file filter.h
 * Filters logic implementation
 */

#ifndef RSPAMD_FILTER_H
#define RSPAMD_FILTER_H

#include "config.h"
#include "rspamd_symcache.h"
#include "task.h"
#include "khash.h"

struct rspamd_task;
struct rspamd_settings;
struct rspamd_classifier_config;

struct rspamd_symbol_option {
	gchar *option;
	struct rspamd_symbol_option *prev, *next;
};

enum rspamd_symbol_result_flags {
	RSPAMD_SYMBOL_RESULT_NORMAL = 0,
	RSPAMD_SYMBOL_RESULT_IGNORED = (1 << 0)
};

/**
 * Rspamd symbol
 */

KHASH_MAP_INIT_STR (rspamd_options_hash, struct rspamd_symbol_option *);
struct rspamd_symbol_result {
	double score;                                  /**< symbol's score							*/
	khash_t(rspamd_options_hash) *options;         /**< list of symbol's options				*/
	struct rspamd_symbol_option *opts_head;        /**< head of linked list of options			*/
	const gchar *name;
	struct rspamd_symbol *sym;                     /**< symbol configuration					*/
	guint nshots;
	enum rspamd_symbol_result_flags flags;
};

/**
 * Result of metric processing
 */
KHASH_MAP_INIT_STR (rspamd_symbols_hash, struct rspamd_symbol_result);
#if UINTPTR_MAX <= UINT_MAX
/* 32 bit */
#define rspamd_ptr_hash_func(key) (khint32_t)(((uintptr_t)(key))>>1)
#else
/* likely 64 bit */
#define rspamd_ptr_hash_func(key) (khint32_t)(((uintptr_t)(key))>>3)
#endif
#define rspamd_ptr_equal_func(a, b) ((a) == (b))
KHASH_INIT (rspamd_symbols_group_hash,
		void *,
		double,
		1,
		rspamd_ptr_hash_func,
		rspamd_ptr_equal_func);

#define RSPAMD_PASSTHROUGH_NORMAL 1
#define RSPAMD_PASSTHROUGH_LOW 0
#define RSPAMD_PASSTHROUGH_HIGH 2
#define RSPAMD_PASSTHROUGH_CRITICAL 3

struct rspamd_passthrough_result {
	enum rspamd_action_type action;
	guint priority;
	double target_score;
	const gchar *message;
	const gchar *module;
	struct rspamd_passthrough_result *prev, *next;
};

struct rspamd_metric_result {
	double score;									/**< total score							*/
	double grow_factor;								/**< current grow factor					*/
	struct rspamd_passthrough_result *passthrough_result;
	guint npositive;
	guint nnegative;
	double positive_score;
	double negative_score;
	khash_t(rspamd_symbols_hash) *symbols;			/**< symbols of metric						*/
	khash_t(rspamd_symbols_group_hash) *sym_groups; /**< groups of symbols						*/
	gdouble actions_limits[METRIC_ACTION_MAX];		/**< set of actions for this metric			*/
};

/**
 * Create or return existing result for the specified metric name
 * @param task task object
 * @return metric result or NULL if metric `name` has not been found
 */
struct rspamd_metric_result * rspamd_create_metric_result (struct rspamd_task *task);

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
									enum rspamd_action_type action,
									guint priority,
									double target_score,
									const gchar *message,
									const gchar *module);

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
struct rspamd_symbol_result* rspamd_task_insert_result_full (struct rspamd_task *task,
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
		struct rspamd_symbol_result *s, const gchar *opt);

/**
 * Finds symbol result
 * @param task
 * @param sym
 * @return
 */
struct rspamd_symbol_result* rspamd_task_find_symbol_result (
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


/*
 * Get action for specific metric
 */
enum rspamd_action_type rspamd_check_action_metric (struct rspamd_task *task,
	struct rspamd_metric_result *mres);

#endif
