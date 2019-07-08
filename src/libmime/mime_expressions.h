/**
 * @file expressions.h
 * Rspamd expressions API
 */

#ifndef RSPAMD_EXPRESSIONS_H
#define RSPAMD_EXPRESSIONS_H

#include "config.h"
#include "expression.h"
#include "contrib/libucl/ucl.h"

#ifdef  __cplusplus
extern "C" {
#endif

struct rspamd_task;
struct rspamd_config;

struct rspamd_mime_expr_ud {
	struct rspamd_config *cfg;
	const ucl_object_t *conf_obj;
};

extern const struct rspamd_atom_subr mime_expr_subr;

/**
 * Function's argument
 */
enum rspamd_expression_type {
	EXPRESSION_ARGUMENT_NORMAL = 0,
	EXPRESSION_ARGUMENT_BOOL,
	EXPRESSION_ARGUMENT_REGEXP
};
struct expression_argument {
	enum rspamd_expression_type type;                           /**< type of argument (text or other function)		*/
	void *data;                                                 /**< pointer to its data							*/
};


typedef gboolean (*rspamd_internal_func_t) (struct rspamd_task *,
											GArray *args, void *user_data);


/**
 * Register specified function to rspamd internal functions list
 * @param name name of function
 * @param func pointer to function
 */
void register_expression_function (const gchar *name,
								   rspamd_internal_func_t func,
								   void *user_data);

/**
 * Set global limit of regexp data size to be processed
 * @param limit new limit in bytes
 * @return old limit value
 */
guint rspamd_mime_expression_set_re_limit (guint limit);

#ifdef  __cplusplus
}
#endif

#endif
