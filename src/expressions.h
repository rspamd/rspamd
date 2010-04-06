/**
 * @file expressions.h
 * Rspamd expressions API
 */

#ifndef RSPAMD_EXPRESSIONS_H
#define RSPAMD_EXPRESSIONS_H

#include "config.h"

struct worker_task;

/**
 * Rspamd expression function
 */
struct expression_function {
	char *name;													/**< name of function								*/
	GList *args;												/**< its args										*/
};

/**
 * Function's argument
 */
struct expression_argument {
	enum {
		EXPRESSION_ARGUMENT_NORMAL,
		EXPRESSION_ARGUMENT_BOOL,
		EXPRESSION_ARGUMENT_EXPR,
	} type;														/**< type of argument (text or other function)		*/
	void *data;													/**< pointer to its data							*/
};

/** 
 * Logic expression 
 */
struct expression {
	enum { 
		EXPR_REGEXP,
		EXPR_OPERATION, 
		EXPR_FUNCTION, 
		EXPR_STR, 
		EXPR_REGEXP_PARSED,
	} type;														/**< expression type								*/
	union {
		void *operand;
		char operation;
	} content;													/**< union for storing operand or operation code 	*/
	const gchar *orig;											/**< original line									*/
	struct expression *next;									/**< chain link										*/
};

typedef gboolean (*rspamd_internal_func_t)(struct worker_task *, GList *args, void *user_data);

/**
 * Parse regexp line to regexp structure
 * @param pool memory pool to use
 * @param line incoming line
 * @return regexp structure or NULL in case of error
 */
struct rspamd_regexp* parse_regexp (memory_pool_t *pool, char *line, gboolean raw_mode);

/**
 * Parse composites line to composites structure (eg. "SYMBOL1&SYMBOL2|!SYMBOL3")
 * @param pool memory pool to use
 * @param line incoming line
 * @return expression structure or NULL in case of error
 */
struct expression* parse_expression (memory_pool_t *pool, char *line);

/**
 * Call specified fucntion and return boolean result
 * @param func function to call
 * @param task task object
 * @return TRUE or FALSE depending on function result
 */
gboolean call_expression_function (struct expression_function *func, struct worker_task *task);

/**
 * Register specified function to rspamd internal functions list
 * @param name name of function
 * @param func pointer to function
 */
void register_expression_function (const char *name, rspamd_internal_func_t func, void *user_data);

/**
 * Add regexp to regexp cache
 * @param line symbolic representation
 * @param pointer regexp data
 */
void re_cache_add (char *line, void *pointer);

/**
 * Check regexp in cache
 * @param line symbolic representation
 * @return pointer to regexp data or NULL if regexp is not found
 */
void * re_cache_check (const char *line);

/**
 * Add regexp to regexp task cache
 * @param task task object
 * @param pointer regexp data
 * @param result numeric result of this regexp
 */
void task_cache_add (struct worker_task *task, struct rspamd_regexp *re, int32_t result);

/**
 * Check regexp in cache
 * @param task task object
 * @param pointer regexp data
 * @return numeric result if value exists or -1 if not
 */
int32_t task_cache_check (struct worker_task *task, struct rspamd_regexp *re);

/**
 * Parse and return a single function argument for a function (may recurse)
 * @param expr expression structure that represents function's argument
 * @param task task object
 * @param want_string return NULL if argument is not a string
 * @return expression argument structure or NULL if failed
 */
struct expression_argument *get_function_arg (struct expression *expr, struct worker_task *task, gboolean want_string);

#endif
