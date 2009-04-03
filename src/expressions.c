/*
 * Copyright (c) 2009, Rambler media
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY Rambler media ''AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL Rambler BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "config.h"
#include "util.h"
#include "cfg_file.h"
#include "main.h"
#include "message.h"
#include "fuzzy.h"
#include "expressions.h"

gboolean rspamd_compare_encoding (struct worker_task *task, GList *args);
gboolean rspamd_header_exists (struct worker_task *task, GList *args);
gboolean rspamd_content_type_compare_param (struct worker_task *task, GList *args);
gboolean rspamd_content_type_has_param (struct worker_task *task, GList *args);
gboolean rspamd_content_type_is_subtype (struct worker_task *task, GList *args);
gboolean rspamd_content_type_is_type (struct worker_task *task, GList *args);
gboolean rspamd_parts_distance (struct worker_task *task, GList *args);
gboolean rspamd_recipients_distance (struct worker_task *task, GList *args);
gboolean rspamd_has_content_part (struct worker_task *task, GList *args);
gboolean rspamd_has_content_part_len (struct worker_task *task, GList *args);
gboolean rspamd_has_only_html_part (struct worker_task *task, GList *args);
gboolean rspamd_is_recipients_sorted (struct worker_task *task, GList *args);

/*
 * List of internal functions of rspamd
 * Sorted by name to use bsearch
 */
static struct _fl {
	const char *name;
	rspamd_internal_func_t func;
} rspamd_functions_list[] = {
	{ "compare_encoding", rspamd_compare_encoding },
	{ "compare_parts_distance", rspamd_parts_distance },
	{ "compare_recipients_distance", rspamd_recipients_distance },
	{ "content_type_compare_param", rspamd_content_type_compare_param },
	{ "content_type_has_param", rspamd_content_type_has_param },
	{ "content_type_is_subtype", rspamd_content_type_is_subtype },
	{ "content_type_is_type", rspamd_content_type_is_type },
	{ "has_content_part", rspamd_has_content_part },
	{ "has_content_part_len", rspamd_has_content_part_len },
	{ "has_only_html_part", rspamd_has_only_html_part },
	{ "header_exists", rspamd_header_exists },
	{ "is_recipients_sorted", rspamd_is_recipients_sorted },
};

static struct _fl *list_ptr = &rspamd_functions_list[0];
static uint32_t functions_number = sizeof (rspamd_functions_list) / sizeof (struct _fl);
static gboolean list_allocated = FALSE;

/* Bsearch routine */
static int
fl_cmp (const void *s1, const void *s2)
{
	struct _fl *fl1 = (struct _fl *)s1;
	struct _fl *fl2 = (struct _fl *)s2;
	return strcmp (fl1->name, fl2->name);
}

/* Cache for regular expressions that are used in functions */
static GHashTable *re_cache = NULL;

void *
re_cache_check (const char *line)
{
	if (re_cache == NULL) {
		re_cache = g_hash_table_new (g_str_hash, g_str_equal);
		return NULL;
	}
	return g_hash_table_lookup (re_cache, line);
}

void
re_cache_add (char *line, void *pointer)
{
	if (re_cache == NULL) {
		re_cache = g_hash_table_new (g_str_hash, g_str_equal);
	}
	
	g_hash_table_insert (re_cache, line, pointer);
}

/*
 * Functions for parsing expressions
 */
struct expression_stack {
	char op;
	struct expression_stack *next;
};

/*
 * Push operand or operator to stack  
 */
static struct expression_stack*
push_expression_stack (memory_pool_t *pool, struct expression_stack *head, char op)
{
	struct expression_stack *new;
	new = memory_pool_alloc (pool, sizeof (struct expression_stack));
	new->op = op;
  	new->next = head;
	return new;                               
}

/*
 * Delete symbol from stack, return pointer to operand or operator (casted to void* )
 */
static char
delete_expression_stack (struct expression_stack **head)
{
	struct expression_stack *cur;
	char res;

 	if(*head == NULL) return 0;

	cur = *head;
	res = cur->op;
	
	*head = cur->next;
	return res;
}

/*
 * Return operation priority
 */
static int
logic_priority (char a)
{
	switch (a) {
		case '!':
			return 3;
		case '|':
		case '&':
			return 2;
		case '(':
			return 1;
		default:
			return 0;
	}
}

/*
 * Return FALSE if symbol is not operation symbol (operand)
 * Return TRUE if symbol is operation symbol
 */
static gboolean
is_operation_symbol (char a)
{
	switch (a) {
		case '!':
		case '&':
		case '|':
		case '(':
		case ')':
			return TRUE;
		default:
			return FALSE;
	}
}

/*
 * Return TRUE if symbol can be regexp flag
 */
static gboolean
is_regexp_flag (char a)
{
	switch (a) {
		case 'i':
		case 'm':
		case 'x':
		case 's':
		case 'u':
		case 'o':
		case 'H':
		case 'M':
		case 'P':
		case 'U':
		case 'X':
			return TRUE;
		default:
			return FALSE;
	}
}

static void
insert_expression (memory_pool_t *pool, struct expression **head, int type, char op, void *operand)
{
	struct expression *new, *cur;
	
	new = memory_pool_alloc (pool, sizeof (struct expression));
	new->type = type;
	if (new->type != EXPR_OPERATION) {
		new->content.operand = operand;
	}
	else {
		new->content.operation = op;
	}
	new->next = NULL;

	if (!*head) {
		*head = new;
	}
	else {
		cur = *head;
		while (cur->next) {
			cur = cur->next;
		}
		cur->next = new;
	}
}

/*
 * Make inverse polish record for specified expression
 * Memory is allocated from given pool
 */
struct expression* 
parse_expression (memory_pool_t *pool, char *line)
{
	struct expression *expr = NULL;
	struct expression_stack *stack = NULL;
	struct expression_function *func = NULL, *old;
	struct expression_argument *arg;
	GQueue *function_stack;
	char *p, *c, *str, op;
	gboolean in_regexp = FALSE;

	enum {
		SKIP_SPACES,
		READ_OPERATOR,
		READ_REGEXP,
		READ_REGEXP_FLAGS,
		READ_FUNCTION,
		READ_FUNCTION_ARGUMENT,
	} state = SKIP_SPACES;

	if (line == NULL || pool == NULL) {
		return NULL;
	} 
	
	function_stack = g_queue_new ();
	p = line;
	c = p;
	while (*p) {
		switch (state) {
			case SKIP_SPACES:
				if (!g_ascii_isspace (*p)) {
					if (is_operation_symbol (*p)) {
						state = READ_OPERATOR;
					} else if (*p == '/') {
						c = ++p;
						state = READ_REGEXP;
					} else {
						c = p;
						state = READ_FUNCTION;
					}
				}
				else {
					p ++;
				}
				break;
			case READ_OPERATOR:
				if (*p == ')') {
					if (stack == NULL) {
						return NULL;
					}
					/* Pop all operators from stack to nearest '(' or to head */
					while (stack->op != '(') {
						op = delete_expression_stack (&stack);
						if (op != '(') {
							insert_expression (pool, &expr, EXPR_OPERATION, op, NULL);
						}
					}
					if (stack) {
						op = delete_expression_stack (&stack);
					}
				}
				else if (*p == '(') {
					/* Push it to stack */
					stack = push_expression_stack (pool, stack, *p);
				}
				else {
					if (stack == NULL) {
						stack = push_expression_stack (pool, stack, *p);
					}
					/* Check priority of logic operation */
					else {
						if (logic_priority (stack->op) < logic_priority (*p)) {
							stack = push_expression_stack (pool, stack, *p);
						}
						else {
							/* Pop all operations that have higher priority than this one */
							while((stack != NULL) && (logic_priority (stack->op) >= logic_priority (*p))) {
								op = delete_expression_stack (&stack);
								if (op != '(') {
									insert_expression (pool, &expr, EXPR_OPERATION, op, NULL);
								}
							}
							stack = push_expression_stack (pool, stack, *p);
						}
					}
				}
				p ++;
				state = SKIP_SPACES;
				break;

			case READ_REGEXP:
				if (*p == '/' && *(p - 1) != '\\') {
					if (*(p + 1)) {
						p ++;
					}
					state = READ_REGEXP_FLAGS;
				}
				else {
					p ++;
				}
				break;

			case READ_REGEXP_FLAGS:
				if (!is_regexp_flag (*p) || *(p + 1) == '\0') {
					if (c != p) {
						/* Copy operand */
						if (*(p + 1) == '\0') {
							p++;
						}
						str = memory_pool_alloc (pool, p - c + 2);
						g_strlcpy (str, c - 1, (p - c + 2));
						g_strstrip (str);
						if (strlen (str) > 0) {
							insert_expression (pool, &expr, EXPR_REGEXP, 0, str);
						}
					}
					c = p;
					state = SKIP_SPACES;
				}
				else {
					p ++;
				}
				break;

			case READ_FUNCTION:
				if (*p == '/') {
					/* In fact it is regexp */
					state = READ_REGEXP;
					c ++;
					p ++;
				} else if (*p == '(') {
					func = memory_pool_alloc (pool, sizeof (struct expression_function));
					func->name = memory_pool_alloc (pool, p - c + 1);
					func->args = NULL;
					g_strlcpy (func->name, c, (p - c + 1));
					g_strstrip (func->name);
					state = READ_FUNCTION_ARGUMENT;
					g_queue_push_tail (function_stack, func);
					insert_expression (pool, &expr, EXPR_FUNCTION, 0, func);
					c = ++p;
				} else if (is_operation_symbol (*p)) {
					/* In fact it is not function, but symbol */
					if (c != p) {
						str = memory_pool_alloc (pool, p - c + 1);
						g_strlcpy (str, c, (p - c + 1));
						g_strstrip (str);
						if (strlen (str) > 0) {
							insert_expression (pool, &expr, EXPR_STR, 0, str);
						}
					}
					state = READ_OPERATOR;
				}
				else {
					p ++;
				}
				break;
			
			case READ_FUNCTION_ARGUMENT:
				if (*p == '/' && !in_regexp) {
					in_regexp = TRUE;
					p ++;
				}
				if (!in_regexp) {
					/* Append argument to list */
					if (*p == ',' || *p == ')') {
						arg = memory_pool_alloc (pool, sizeof (struct expression_argument));
						if (*(p - 1) != ')') {
							/* Not a function argument */
							str = memory_pool_alloc (pool, p - c + 1);
							g_strlcpy (str, c, (p - c + 1));
							g_strstrip (str);
							arg->type = EXPRESSION_ARGUMENT_NORMAL;
							arg->data = str;
							func->args = g_list_append (func->args, arg);
						}
						else {
							arg->type = EXPRESSION_ARGUMENT_FUNCTION;
							arg->data = old;
							func->args = g_list_append (func->args, arg);
						}
						/* Pop function */
						if (*p == ')') {
							/* Last function in chain, goto skipping spaces state */
							old = func;
							func = g_queue_pop_tail (function_stack);
							if (g_queue_get_length (function_stack) == 0) {
								state = SKIP_SPACES;
							}
						}
						c = p + 1;
					}
					if (*p == '(') {
						/* Push current function to stack */
						g_queue_push_tail (function_stack, func);
						func = memory_pool_alloc (pool, sizeof (struct expression_function));
						func->name = memory_pool_alloc (pool, p - c + 1);
						func->args = NULL;
						g_strlcpy (func->name, c, (p - c + 1));
						g_strstrip (func->name);
						state = READ_FUNCTION_ARGUMENT;
						c = p + 1;
					}
				}
				else if (*p == '/' && *(p - 1) != '\\') {
					in_regexp = FALSE;
				}
				p ++;
				break;
		}
	}

	g_queue_free (function_stack);
	if (state != SKIP_SPACES) {
		/* In fact we got bad expression */
		msg_warn ("parse_expression: expression \"%s\" is invalid", line);
		return NULL;
	}
	/* Pop everything from stack */
	while(stack != NULL) {
		op = delete_expression_stack (&stack);
		if (op != '(') {
			insert_expression (pool, &expr, EXPR_OPERATION, op, NULL);
		}
	}

	return expr;
}

/*
 * Rspamd regexp utility functions
 */
struct rspamd_regexp*
parse_regexp (memory_pool_t *pool, char *line)
{
	char *begin, *end, *p, *src;
	struct rspamd_regexp *result;
	int regexp_flags = 0;
	GError *err = NULL;
	
	src = line;
	result = memory_pool_alloc0 (pool, sizeof (struct rspamd_regexp));
	/* Skip whitespaces */
	while (g_ascii_isspace (*line)) {
		line ++;
	}
	if (line == '\0') {
		msg_warn ("parse_regexp: got empty regexp");
		return NULL;
	}
	/* First try to find header name */
	begin = strchr (line, '/');
	if (begin != NULL) {
		*begin = '\0';
		end = strchr (line, '=');
		*begin = '/';
		if (end) {
			*end = '\0';
			result->header = memory_pool_strdup (pool, line);
			result->type = REGEXP_HEADER;
			*end = '=';
			line = end;
		}
	}
	else {
		*begin = '\0';
		result->header = memory_pool_strdup (pool, line);
		result->type = REGEXP_HEADER;
		*begin = '=';
		line = begin;
	}
	/* Find begin of regexp */
	while (*line && *line != '/') {
		line ++;
	}
	if (*line != '\0') {
		begin = line + 1;
	}
	else if (result->header == NULL) {
		/* Assume that line without // is just a header name */
		result->header = memory_pool_strdup (pool, line);
		result->type = REGEXP_HEADER;
		return result;
	}
	else {
		/* We got header name earlier but have not found // expression, so it is invalid regexp */
		msg_warn ("parse_regexp: got no header name (eg. header=) but without corresponding regexp, %s", src);
		return NULL;
	}
	/* Find end */
	end = begin;
	while (*end && (*end != '/' || *(end - 1) == '\\')) {
		end ++;
	}
	if (end == begin || *end != '/') {
		msg_warn ("parse_regexp: no trailing / in regexp %s", src);
		return NULL;
	}
	/* Parse flags */
	p = end + 1;
	while (p != NULL) {
		switch (*p) {
			case 'i':
				regexp_flags |= G_REGEX_CASELESS;
				p ++;
				break;
			case 'm':
				regexp_flags |= G_REGEX_MULTILINE;
				p ++;
				break;
			case 's':
				regexp_flags |= G_REGEX_DOTALL;
				p ++;
				break;
			case 'x':
				regexp_flags |= G_REGEX_EXTENDED;
				p ++;
				break;
			case 'u':
				regexp_flags |= G_REGEX_UNGREEDY;
				p ++;
				break;
			case 'o':
				regexp_flags |= G_REGEX_OPTIMIZE;
				p ++;
				break;
			/* Type flags */
			case 'H':
				if (result->type == REGEXP_NONE) {
					result->type = REGEXP_HEADER;
				}
				p ++;
				break;
			case 'M':
				if (result->type == REGEXP_NONE) {
					result->type = REGEXP_MESSAGE;
				}
				p ++;
				break;
			case 'P':
				if (result->type == REGEXP_NONE) {
					result->type = REGEXP_MIME;
				}
				p ++;
				break;
			case 'U':
				if (result->type == REGEXP_NONE) {
					result->type = REGEXP_URL;
				}
				p ++;
				break;
			case 'X':
				if (result->type == REGEXP_NONE || result->type == REGEXP_HEADER) {
					result->type = REGEXP_RAW_HEADER;
				}
				p ++;
				break;
			/* Stop flags parsing */
			default:
				p = NULL;
				break;
		}
	}

	*end = '\0';
	result->regexp = g_regex_new (begin, regexp_flags, 0, &err);
	result->regexp_text = memory_pool_strdup (pool, begin);
	memory_pool_add_destructor (pool, (pool_destruct_func)g_regex_unref, (void *)result->regexp);
	*end = '/';

	if (result->regexp == NULL || err != NULL) {
		msg_warn ("parse_regexp: could not read regexp: %s while reading regexp %s", err->message, src);
		return NULL;
	}

	return result;
}

gboolean 
call_expression_function (struct expression_function *func, struct worker_task *task)
{
	struct _fl *selected, key;

	key.name = func->name;

	selected = bsearch (&key, list_ptr, functions_number,
						sizeof (struct _fl), fl_cmp);
	if (selected == NULL) {
		msg_warn ("call_expression_function: call to undefined function %s", key.name);
		return FALSE;
	}
	
	return selected->func (task, func->args);
}

void
register_expression_function (const char *name, rspamd_internal_func_t func)
{
	static struct _fl *new;

	functions_number ++;
	
	new = g_new (struct _fl, functions_number);
	memcpy (new, rspamd_functions_list, (functions_number - 1) * sizeof (struct _fl));
	if (list_allocated) {
		g_free (list_ptr);
	}

	list_allocated = TRUE;
	new[functions_number - 1].name = name;
	new[functions_number - 1].func = func;
	qsort (new, functions_number, sizeof (struct _fl), fl_cmp);
	list_ptr = new;
}

gboolean
rspamd_compare_encoding (struct worker_task *task, GList *args)
{
	struct expression_argument *arg;

	if (args == NULL || task == NULL) {
		return FALSE;
	}

	arg = args->data;
	if (arg->type == EXPRESSION_ARGUMENT_FUNCTION) {
		msg_warn ("rspamd_compare_encoding: invalid argument to function is passed");
		return FALSE;
	}

	/* XXX: really write this function */
	return TRUE;
}

gboolean 
rspamd_header_exists (struct worker_task *task, GList *args)
{
	struct expression_argument *arg;
	GList *headerlist;

	if (args == NULL || task == NULL) {
		return FALSE;
	}

	arg = args->data;
	if (arg->type == EXPRESSION_ARGUMENT_FUNCTION) {
		msg_warn ("rspamd_header_exists: invalid argument to function is passed");
		return FALSE;
	}

	headerlist = message_get_header (task->task_pool, task->message, (char *)arg->data);
	if (headerlist) {
		g_list_free (headerlist);
		return TRUE;
	}
	return FALSE;
}

/*
 * This function is designed to find difference between text/html and text/plain parts
 * It takes one argument: difference threshold, if we have two text parts, compare 
 * its hashes and check for threshold, if value is greater than threshold, return TRUE
 * and return FALSE otherwise.
 */
gboolean 
rspamd_parts_distance (struct worker_task *task, GList *args)
{	
	int threshold;
	struct mime_text_part *p1, *p2;
	GList *cur;
	struct expression_argument *arg;
	
	if (args == NULL) {
		msg_debug ("rspamd_parts_distance: no threshold is specified, assume it 100");
		threshold = 100;
	}
	else {
		errno = 0;
		arg = args->data;
		threshold = strtoul ((char *)arg->data, NULL, 10);
		if (errno != 0) {
			msg_info ("rspamd_parts_distance: bad numeric value for threshold \"%s\", assume it 100", (char *)args->data);
			threshold = 100;
		}
	}

	if (g_list_length (task->text_parts) == 2) {
		cur = g_list_first (task->text_parts);
		p1 = cur->data;
		cur = g_list_next (cur);
		if (cur == NULL) {
			msg_info ("rspamd_parts_distance: bad parts list");
			return FALSE;
		}
		p2 = cur->data;
		if (fuzzy_compare_hashes (p1->fuzzy, p2->fuzzy) >= threshold) {
			return TRUE;
		}
	}
	else {
		msg_debug ("rspamd_parts_distance: message has too many text parts, so do not try to compare them with each other");
		return FALSE;
	}

	return FALSE;
}

gboolean 
rspamd_content_type_compare_param (struct worker_task *task, GList *args)
{
	char *param_name, *param_pattern;
	const char *param_data;
	struct rspamd_regexp *re;
	struct expression_argument *arg;
	GMimeObject *part;
	const GMimeContentType *ct;
	
	if (args == NULL) {
		msg_warn ("rspamd_content_type_compare_param: no parameters to function");
		return FALSE;
	}
	arg = args->data;
	param_name = arg->data;
	args = g_list_next (args);
	if (args == NULL) {
		msg_warn ("rspamd_content_type_compare_param: too few params to function");
		return FALSE;
	}
	arg = args->data;
	param_pattern = arg->data;
	
	part = g_mime_message_get_mime_part (task->message);
	if (part) {
		ct = g_mime_object_get_content_type (part);
		g_object_unref (part);

		if ((param_data = g_mime_content_type_get_parameter (ct, param_name)) == NULL) {
			return FALSE;
		}
		if (*param_pattern == '/') {
			/* This is regexp, so compile and create g_regexp object */
			if ((re = re_cache_check (param_pattern)) == NULL) {
				re = parse_regexp (task->task_pool, param_pattern);
				if (re == NULL) {
					msg_warn ("rspamd_content_type_compare_param: cannot compile regexp for function");
					return FALSE;
				}
				re_cache_add (param_pattern, re);
			}
			if (g_regex_match (re->regexp, param_data, 0, NULL) == TRUE) {
				return TRUE;
			}
		}
		else {
			/* Just do strcasecmp */
			if (g_ascii_strcasecmp (param_data, param_pattern) == 0) {
				return TRUE;
			}
		}
	}
	

	return FALSE;
}	

gboolean 
rspamd_content_type_has_param (struct worker_task *task, GList *args)
{
	char *param_name;
	const char *param_data;
	struct expression_argument *arg;
	GMimeObject *part;
	const GMimeContentType *ct;
	
	if (args == NULL) {
		msg_warn ("rspamd_content_type_compare_param: no parameters to function");
		return FALSE;
	}
	arg = args->data;
	param_name = arg->data;
	part = g_mime_message_get_mime_part (task->message);
	if (part) {
		ct = g_mime_object_get_content_type (part);
		g_object_unref (part);

		if ((param_data = g_mime_content_type_get_parameter (ct, param_name)) == NULL) {
			return FALSE;
		}
	}
	
	return TRUE;
}

/* In gmime24 this function is opaque, so define it here to avoid errors when compiling with gmime24 */
typedef struct {
	char *type;
	char *subtype;
	
	GMimeParam *params;
	GHashTable *param_hash;
} localContentType;

gboolean 
rspamd_content_type_is_subtype (struct worker_task *task, GList *args)
{
	char *param_pattern;
	struct rspamd_regexp *re;
	struct expression_argument *arg;
	GMimeObject *part;
	const localContentType *ct;
	
	if (args == NULL) {
		msg_warn ("rspamd_content_type_compare_param: no parameters to function");
		return FALSE;
	}
	
	arg = args->data;
	param_pattern = arg->data;
	part = g_mime_message_get_mime_part (task->message);
	if (part) {
		ct = (const localContentType *)g_mime_object_get_content_type (part);
		g_object_unref (part);

		if (ct == NULL) {
			return FALSE;
		}
		
		if (*param_pattern == '/') {
			/* This is regexp, so compile and create g_regexp object */
			if ((re = re_cache_check (param_pattern)) == NULL) {
				re = parse_regexp (task->task_pool, param_pattern);
				if (re == NULL) {
					msg_warn ("rspamd_content_type_compare_param: cannot compile regexp for function");
					return FALSE;
				}
				re_cache_add (param_pattern, re);
			}
			if (g_regex_match (re->regexp, ct->subtype, 0, NULL) == TRUE) {
				return TRUE;
			}
		}
		else {
			/* Just do strcasecmp */
			if (g_ascii_strcasecmp (ct->subtype, param_pattern) == 0) {
				return TRUE;
			}
		}
	}

	return FALSE;
}

gboolean 
rspamd_content_type_is_type (struct worker_task *task, GList *args)
{
	char *param_pattern;
	struct rspamd_regexp *re;
	GMimeObject *part;
	const localContentType *ct;
	struct expression_argument *arg;
	
	if (args == NULL) {
		msg_warn ("rspamd_content_type_compare_param: no parameters to function");
		return FALSE;
	}
	
	arg = args->data;
	param_pattern = arg->data;

	part = g_mime_message_get_mime_part (task->message);
	if (part) {
		ct = (const localContentType *)g_mime_object_get_content_type (part);
		g_object_unref (part);

		if (ct == NULL) {
			return FALSE;
		}
		
		if (*param_pattern == '/') {
			/* This is regexp, so compile and create g_regexp object */
			if ((re = re_cache_check (param_pattern)) == NULL) {
				re = parse_regexp (task->task_pool, param_pattern);
				if (re == NULL) {
					msg_warn ("rspamd_content_type_compare_param: cannot compile regexp for function");
					return FALSE;
				}
				re_cache_add (param_pattern, re);
			}
			if (g_regex_match (re->regexp, ct->type, 0, NULL) == TRUE) {
				return TRUE;
			}
		}
		else {
			/* Just do strcasecmp */
			if (g_ascii_strcasecmp (ct->type, param_pattern) == 0) {
				return TRUE;
			}
		}
	}

	return FALSE;
}

struct addr_list {
	const char *name;
	const char *addr;
};

#define COMPARE_RCPT_LEN 3
#define MIN_RCPT_TO_COMPARE 5

gboolean 
rspamd_recipients_distance (struct worker_task *task, GList *args)
{
	struct expression_argument *arg;
	InternetAddressList *cur;
	InternetAddress *addr;
	double threshold;
	struct addr_list *ar;
	char *c;
	int num, i, j, hits = 0, total = 0;
	
	if (args == NULL) {
		msg_warn ("rspamd_content_type_compare_param: no parameters to function");
		return FALSE;
	}
	
	arg = args->data;
	errno = 0;
	threshold = strtod ((char *)arg->data, NULL);
	if (errno != 0) {
		msg_warn ("rspamd_recipients_distance: invalid numeric value '%s': %s", (char *)arg->data, strerror (errno));
		return FALSE;
	}

	num = internet_address_list_length (task->rcpts);
	if (num < MIN_RCPT_TO_COMPARE) {
		return FALSE;
	}
	ar = memory_pool_alloc (task->task_pool, num * sizeof (struct addr_list));

	/* Fill array */
	cur = task->rcpts;
	i = 0;
	while (cur) {
		addr = internet_address_list_get_address (cur);
		ar[i].name = memory_pool_strdup (task->task_pool, internet_address_get_addr (addr));
		if ((c = strchr (ar[i].name, '@')) != NULL) {
			*c = '\0';
			ar[i].addr = c + 1;
		}
		else {
			ar[i].addr = NULL;
		}
		cur = internet_address_list_next (cur);
	}

	/* Cycle all elements in array */
	for (i = 0; i < num; i ++) {
		for (j = i + 1; j < num; j ++) {
			if (ar[i].name && ar[j].name && g_ascii_strncasecmp (ar[i].name, ar[j].name, COMPARE_RCPT_LEN) == 0) {
				/* Common name part */
				hits ++;
			}
			else if (ar[i].addr && ar[j].addr && g_ascii_strcasecmp (ar[i].addr, ar[j].addr) == 0) {
				/* Common address part, but different name */
				hits ++;
			}
			total ++;
		}
	}

	if ((double)total / (double)hits >= threshold) {
		return TRUE;
	}

	return FALSE;
}

gboolean 
rspamd_has_only_html_part (struct worker_task *task, GList *args)
{
	struct mime_text_part *p;
	GList *cur;
	gboolean res = FALSE;

	cur = g_list_first (task->text_parts);
	while (cur) {
		p = cur->data;
		if (p->is_html) {
			res = TRUE;
		}
		else {
			res = FALSE;
			break;
		}
		cur = g_list_next (cur);
	}

	return res;
}

static gboolean
is_recipient_list_sorted (const InternetAddressList *ia)
{
	const InternetAddressList *cur;
	InternetAddress *addr;
	gboolean res = TRUE;
	struct addr_list current = {NULL, NULL}, previous = {NULL, NULL};
	
	/* Do not check to short address lists */
	if (internet_address_list_length (ia) < MIN_RCPT_TO_COMPARE) {
		return FALSE;
	}

	cur = ia;
	while (cur) {
		addr = internet_address_list_get_address (cur);
		current.addr = internet_address_get_addr (addr);
		if (previous.addr != NULL) {
			if (g_ascii_strcasecmp (current.addr, previous.addr) < 0) {
				res = FALSE;
				break;
			}
		}
		previous.addr = current.addr;
		cur = internet_address_list_next (cur);
	}

	return res;
}

gboolean
rspamd_is_recipients_sorted (struct worker_task *task, GList *args)
{
	/* Check all types of addresses */
	if (is_recipient_list_sorted (g_mime_message_get_recipients (task->message, GMIME_RECIPIENT_TYPE_TO)) == TRUE) {
		return TRUE;
	}
	if (is_recipient_list_sorted (g_mime_message_get_recipients (task->message, GMIME_RECIPIENT_TYPE_BCC)) == TRUE) {
		return TRUE;
	}
	if (is_recipient_list_sorted (g_mime_message_get_recipients (task->message, GMIME_RECIPIENT_TYPE_CC)) == TRUE) {
		return TRUE;
	}

	return FALSE;
}

static inline gboolean
compare_subtype (struct worker_task *task, const localContentType *ct, char *subtype)
{
	struct rspamd_regexp *re;

	if (*subtype == '/') {
		/* This is regexp, so compile and create g_regexp object */
		if ((re = re_cache_check (subtype)) == NULL) {
			re = parse_regexp (task->task_pool, subtype);
			if (re == NULL) {
				msg_warn ("compare_subtype: cannot compile regexp for function");
				return FALSE;
			}
			re_cache_add (subtype, re);
		}
		if (g_regex_match (re->regexp, ct->subtype , 0, NULL) == TRUE) {
			return TRUE;
		}
	}
	else {
		/* Just do strcasecmp */
		if (g_ascii_strcasecmp (ct->subtype, subtype) == 0) {
			return TRUE;
		}
	}

	return FALSE;
}

static inline gboolean
compare_len (struct mime_part *part, int min, int max)
{
	if (min == 0 && max == 0) {
		return TRUE;
	}

	if (min == 0) {
		return part->content->len <= max;
	}
	else if (max == 0) {
		return part->content->len >= min;
	}
	else {
		return part->content->len >= min && part->content->len <= max;
	}
}

gboolean 
common_has_content_part (struct worker_task *task, char *param_type, char *param_subtype, int min_len, int max_len)
{
	struct rspamd_regexp *re;
	struct mime_part *part;
	GList *cur;
	const localContentType *ct;
	
	
	cur = g_list_first (task->parts);
	while (cur) {
		part = cur->data;
		ct = (localContentType *)part->type;
		if (ct == NULL) {
			cur = g_list_next (cur);
			continue;
		}
		
		if (*param_type == '/') {
			/* This is regexp, so compile and create g_regexp object */
			if ((re = re_cache_check (param_type)) == NULL) {
				re = parse_regexp (task->task_pool, param_type);
				if (re == NULL) {
					msg_warn ("rspamd_has_content_part: cannot compile regexp for function");
					cur = g_list_next (cur);
					continue;
				}
				re_cache_add (param_type, re);
			}
			if (g_regex_match (re->regexp, ct->type, 0, NULL) == TRUE) {
				if (param_subtype) {
					if (compare_subtype (task, ct, param_subtype)) {
						if (compare_len (part, min_len, max_len)) {
							return TRUE;
						}
					}
				}
				else {
					if (compare_len (part, min_len, max_len)) {
						return TRUE;
					}
				}
			}
		}
		else {
			/* Just do strcasecmp */
			if (g_ascii_strcasecmp (ct->type, param_type) == 0) {
				if (param_subtype) {
					if (compare_subtype (task, ct, param_subtype)) {
						if (compare_len (part, min_len, max_len)) {
							return TRUE;
						}
					}
				}
				else {
					if (compare_len (part, min_len, max_len)) {
						return TRUE;
					}
				}
			}
		}
		cur = g_list_next (cur);
	}

	return FALSE;
}

gboolean
rspamd_has_content_part (struct worker_task *task, GList *args)
{
	char *param_type = NULL, *param_subtype = NULL;
	struct expression_argument *arg;

	if (args == NULL) {
		msg_warn ("rspamd_has_content_part: no parameters to function");
		return FALSE;
	}
	
	arg = args->data;
	param_type = arg->data;
	args = args->next;
	if (args) {
		arg = args->data;
		param_subtype = arg->data;
	}

	return common_has_content_part (task, param_type, param_subtype, 0, 0);
}

gboolean
rspamd_has_content_part_len (struct worker_task *task, GList *args)
{
	char *param_type = NULL, *param_subtype = NULL;
	int min = 0, max = 0;
	struct expression_argument *arg;

	if (args == NULL) {
		msg_warn ("rspamd_has_content_part_len: no parameters to function");
		return FALSE;
	}
	
	arg = args->data;
	param_type = arg->data;
	args = args->next;
	if (args) {
		arg = args->data;
		param_subtype = arg->data;
		args = args->next;
		if (args) {
			arg = args->data;
			errno = 0;
			min = strtoul (arg->data, NULL, 10);
			if (errno != 0) {
				msg_warn ("rspamd_has_content_part_len: invalid numeric value '%s': %s", (char *)arg->data, strerror (errno));
				return FALSE;
			}
			args = args->next;
			if (args) {
				arg = args->data;
				max = strtoul (arg->data, NULL, 10);
				if (errno != 0) {
					msg_warn ("rspamd_has_content_part_len: invalid numeric value '%s': %s", (char *)arg->data, strerror (errno));
					return FALSE;
				}
			}
		}
	}

	return common_has_content_part (task, param_type, param_subtype, min, max);
}

/*
 * vi:ts=4
 */
