/*
 * Copyright 2024 Vsevolod Stakhov
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * @file scan_result.h
 * Scan result holder
 */

#ifndef RSPAMD_SCAN_RESULT_H
#define RSPAMD_SCAN_RESULT_H

#include "config.h"
#include "rspamd_symcache.h"
#include "task.h"

#ifdef __cplusplus
extern "C" {
#endif

struct rspamd_task;
struct rspamd_settings;
struct rspamd_classifier_config;

struct rspamd_symbol_option {
	char *option;
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
	double score;                             /**< symbol's score							*/
	struct kh_rspamd_options_hash_s *options; /**< list of symbol's options				*/
	struct rspamd_symbol_option *opts_head;   /**< head of linked list of options			*/
	const char *name;
	struct rspamd_symbol *sym; /**< symbol configuration					*/
	gssize opts_len;           /**< total size of all options (negative if truncated option is added) */
	unsigned int nshots;
	int flags;
	struct rspamd_symbol_result *next; /**< for shadow results */
};


#define RSPAMD_PASSTHROUGH_NORMAL 1
#define RSPAMD_PASSTHROUGH_LOW 0
#define RSPAMD_PASSTHROUGH_HIGH 2
#define RSPAMD_PASSTHROUGH_CRITICAL 3

#define RSPAMD_PASSTHROUGH_LEAST (1u << 0u)
#define RSPAMD_PASSTHROUGH_NO_SMTP_MESSAGE (1u << 1u)
#define RSPAMD_PASSTHROUGH_PROCESS_ALL (1u << 2u)

struct rspamd_passthrough_result {
	struct rspamd_action *action;
	unsigned int priority;
	unsigned int flags;
	double target_score;
	const char *message;
	const char *module;
	struct rspamd_passthrough_result *prev, *next;
};


enum rspamd_action_config_flags {
	RSPAMD_ACTION_RESULT_DEFAULT = 0,
	RSPAMD_ACTION_RESULT_NO_THRESHOLD = (1u << 0u),
	RSPAMD_ACTION_RESULT_DISABLED = (1u << 1u),
};
struct rspamd_action_config {
	double cur_limit;
	int flags;
	struct rspamd_action *action;
};

struct kh_rspamd_symbols_hash_s;
struct kh_rspamd_symbols_group_hash_s;


struct rspamd_scan_result {
	double score; /**< total score							*/
	struct rspamd_passthrough_result *passthrough_result;
	double positive_score;
	double negative_score;
	struct kh_rspamd_symbols_hash_s *symbols;          /**< symbols of metric						*/
	struct kh_rspamd_symbols_group_hash_s *sym_groups; /**< groups of symbols						*/
	struct rspamd_action_config *actions_config;
	const char *name;         /**< for named results, NULL is the default result */
	struct rspamd_task *task; /**< back reference */
	int symbol_cbref;         /**< lua function that defines if a symbol can be inserted, -1 if unused */
	unsigned int nactions;
	unsigned int npositive;
	unsigned int nnegative;
	unsigned int nresults;                  /**< all results: positive, negative, passthrough etc */
	unsigned int nresults_postfilters;      /**< how many results are there before postfilters stage */
	struct rspamd_scan_result *prev, *next; /**< double linked list of results */
};

/**
 * Create or return existing result for the specified metric name
 * @param task task object
 * @return metric result or NULL if metric `name` has not been found
 */
struct rspamd_scan_result *rspamd_create_metric_result(struct rspamd_task *task,
													   const char *name, int lua_sym_cbref);

/**
 * Find result with a specific name (NULL means the default result)
 * @param task
 * @param name
 * @return
 */
struct rspamd_scan_result *rspamd_find_metric_result(struct rspamd_task *task,
													 const char *name);

/**
 * Adds a new passthrough result to a task
 * @param task
 * @param action
 * @param priority
 * @param target_score
 * @param message
 * @param module
 */
bool rspamd_add_passthrough_result(struct rspamd_task *task,
								   struct rspamd_action *action, unsigned int priority,
								   double target_score, const char *message,
								   const char *module, unsigned int flags,
								   struct rspamd_scan_result *scan_result);

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
struct rspamd_symbol_result *rspamd_task_insert_result_full(struct rspamd_task *task,
															const char *symbol,
															double weight,
															const char *opts,
															enum rspamd_symbol_insert_flags flags,
															struct rspamd_scan_result *result);

#define rspamd_task_insert_result_single(task, symbol, weight, opts) \
	rspamd_task_insert_result_full((task), (symbol), (weight), (opts), RSPAMD_SYMBOL_INSERT_SINGLE, NULL)
#define rspamd_task_insert_result(task, symbol, weight, opts) \
	rspamd_task_insert_result_full((task), (symbol), (weight), (opts), RSPAMD_SYMBOL_INSERT_DEFAULT, NULL)

/**
 * Removes a symbol from a specific symbol result
 * @param task
 * @param symbol
 * @param result
 * @return
 */
struct rspamd_symbol_result *rspamd_task_remove_symbol_result(
	struct rspamd_task *task,
	const char *symbol,
	struct rspamd_scan_result *result);
/**
 * Adds new option to symbol
 * @param task
 * @param s
 * @param opt
 */
gboolean rspamd_task_add_result_option(struct rspamd_task *task,
									   struct rspamd_symbol_result *s,
									   const char *opt,
									   gsize vlen);

/**
 * Finds symbol result
 * @param task
 * @param sym
 * @return
 */
struct rspamd_symbol_result *
rspamd_task_find_symbol_result(struct rspamd_task *task, const char *sym,
							   struct rspamd_scan_result *result);

/**
 * Compatibility function to iterate on symbols hash
 * @param task
 * @param func
 * @param ud
 */
void rspamd_task_symbol_result_foreach(struct rspamd_task *task,
									   struct rspamd_scan_result *result,
									   GHFunc func,
									   gpointer ud);

/**
 * Adjust symbol results to the grow factor for a specific task; should be called after postfilters
 */
void rspamd_task_result_adjust_grow_factor(struct rspamd_task *task,
										   struct rspamd_scan_result *result,
										   double grow_factor);

/**
 * Check thresholds and return action for a task
 * @param task
 * @return
 */
struct rspamd_action *rspamd_check_action_metric(struct rspamd_task *task,
												 struct rspamd_passthrough_result **ppr,
												 struct rspamd_scan_result *scan_result);

struct rspamd_action_config *rspamd_find_action_config_for_action(struct rspamd_scan_result *scan_result,
																  struct rspamd_action *act);

#ifdef __cplusplus
}
#endif

#endif
