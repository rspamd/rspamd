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
		EXPRESSION_ARGUMENT_FUNCTION
	} type;														/**< type of argument (text or other function)		*/
	void *data;													/**< pointer to its data							*/
};

/** 
 * Logic expression 
 */
struct expression {
	enum { EXPR_REGEXP, EXPR_OPERATION, EXPR_FUNCTION, EXPR_STR } type;	/**< expression type								*/
	union {
		void *operand;
		char operation;
	} content;													/**< union for storing operand or operation code 	*/
	struct expression *next;									/**< chain link										*/
};

/**
 * Parse regexp line to regexp structure
 * @param pool memory pool to use
 * @param line incoming line
 * @return regexp structure or NULL in case of error
 */
struct rspamd_regexp* parse_regexp (memory_pool_t *pool, char *line);

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


#endif
