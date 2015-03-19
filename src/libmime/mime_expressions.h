/**
 * @file expressions.h
 * Rspamd expressions API
 */

#ifndef RSPAMD_EXPRESSIONS_H
#define RSPAMD_EXPRESSIONS_H

#include "config.h"
#include "expression.h"

struct rspamd_task;

extern const struct rspamd_atom_subr mime_expr_subr;

/**
 * Function's argument
 */
struct expression_argument {
	enum {
		EXPRESSION_ARGUMENT_NORMAL = 0,
		EXPRESSION_ARGUMENT_BOOL,
		EXPRESSION_ARGUMENT_REGEXP
	} type;                                                     /**< type of argument (text or other function)		*/
	void *data;                                                 /**< pointer to its data							*/
};


typedef gboolean (*rspamd_internal_func_t)(struct rspamd_task *, GList *args,
	void *user_data);


/**
 * Register specified function to rspamd internal functions list
 * @param name name of function
 * @param func pointer to function
 */
void register_expression_function (const gchar *name,
	rspamd_internal_func_t func,
	void *user_data);

/**
 * Add regexp to regexp task cache
 * @param task task object
 * @param pointer regexp data
 * @param result numeric result of this regexp
 */
void task_cache_add (struct rspamd_task *task,
	struct rspamd_regexp_element *re,
	gint32 result);

/**
 * Check regexp in cache
 * @param task task object
 * @param pointer regexp data
 * @return numeric result if value exists or -1 if not
 */
gint32 task_cache_check (struct rspamd_task *task, struct rspamd_regexp_element *re);

/**
 * Set global limit of regexp data size to be processed
 * @param limit new limit in bytes
 * @return old limit value
 */
guint rspamd_mime_expression_set_re_limit (guint limit);

#endif
