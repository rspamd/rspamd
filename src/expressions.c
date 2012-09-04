/*
 * Copyright (c) 2012, Vsevolod Stakhov
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
 * THIS SOFTWARE IS PROVIDED BY AUTHOR ''AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL AUTHOR BE LIABLE FOR ANY
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
#include "html.h"
#include "lua/lua_common.h"
#include "diff.h"

gboolean                        rspamd_compare_encoding (struct worker_task *task, GList * args, void *unused);
gboolean                        rspamd_header_exists (struct worker_task *task, GList * args, void *unused);
gboolean                        rspamd_parts_distance (struct worker_task *task, GList * args, void *unused);
gboolean                        rspamd_recipients_distance (struct worker_task *task, GList * args, void *unused);
gboolean                        rspamd_has_only_html_part (struct worker_task *task, GList * args, void *unused);
gboolean                        rspamd_is_recipients_sorted (struct worker_task *task, GList * args, void *unused);
gboolean                        rspamd_compare_transfer_encoding (struct worker_task *task, GList * args, void *unused);
gboolean                        rspamd_is_html_balanced (struct worker_task *task, GList * args, void *unused);
gboolean                        rspamd_has_html_tag (struct worker_task *task, GList * args, void *unused);
gboolean                        rspamd_has_fake_html (struct worker_task *task, GList * args, void *unused);

/*
 * List of internal functions of rspamd
 * Sorted by name to use bsearch
 */
static struct _fl {
	const gchar                     *name;
	rspamd_internal_func_t          func;
	void                           *user_data;
} rspamd_functions_list[] = {
	{"compare_encoding", rspamd_compare_encoding, NULL},
	{"compare_parts_distance", rspamd_parts_distance, NULL},
	{"compare_recipients_distance", rspamd_recipients_distance, NULL},
	{"compare_transfer_encoding", rspamd_compare_transfer_encoding, NULL},
	{"has_fake_html", rspamd_has_fake_html, NULL},
	{"has_html_tag", rspamd_has_html_tag, NULL},
	{"has_only_html_part", rspamd_has_only_html_part, NULL},
	{"header_exists", rspamd_header_exists, NULL},
	{"is_html_balanced", rspamd_is_html_balanced, NULL},
	{"is_recipients_sorted", rspamd_is_recipients_sorted, NULL}
};

static struct _fl              *list_ptr = &rspamd_functions_list[0];
static guint32                  functions_number = sizeof (rspamd_functions_list) / sizeof (struct _fl);
static gboolean                 list_allocated = FALSE;

/* Bsearch routine */
static gint
fl_cmp (const void *s1, const void *s2)
{
	struct _fl                     *fl1 = (struct _fl *)s1;
	struct _fl                     *fl2 = (struct _fl *)s2;
	return strcmp (fl1->name, fl2->name);
}

/* Cache for regular expressions that are used in functions */
void                           *
re_cache_check (const gchar *line, memory_pool_t *pool)
{
	GHashTable              *re_cache;
	
	re_cache = memory_pool_get_variable (pool, "re_cache");

	if (re_cache == NULL) {
		re_cache = g_hash_table_new (g_str_hash, g_str_equal);
		memory_pool_set_variable (pool, "re_cache", re_cache, (pool_destruct_func)g_hash_table_destroy);
		return NULL;
	}
	return g_hash_table_lookup (re_cache, line);
}

void
re_cache_add (const gchar *line, void *pointer, memory_pool_t *pool)
{
	GHashTable              *re_cache;
	
	re_cache = memory_pool_get_variable (pool, "re_cache");

	if (re_cache == NULL) {
		re_cache = g_hash_table_new (g_str_hash, g_str_equal);
		memory_pool_set_variable (pool, "re_cache", re_cache, (pool_destruct_func)g_hash_table_destroy);
	}

	g_hash_table_insert (re_cache, (gpointer)line, pointer);
}

void
re_cache_del (const gchar *line, memory_pool_t *pool)
{
	GHashTable              *re_cache;

	re_cache = memory_pool_get_variable (pool, "re_cache");

	if (re_cache != NULL) {
		g_hash_table_remove (re_cache, line);
	}

}

/*
 * Functions for parsing expressions
 */
struct expression_stack {
	gchar                           op;
	struct expression_stack        *next;
};

/*
 * Push operand or operator to stack  
 */
static struct expression_stack *
push_expression_stack (memory_pool_t * pool, struct expression_stack *head, gchar op)
{
	struct expression_stack        *new;
	new = memory_pool_alloc (pool, sizeof (struct expression_stack));
	new->op = op;
	new->next = head;
	return new;
}

/*
 * Delete symbol from stack, return pointer to operand or operator (casted to void* )
 */
static gchar
delete_expression_stack (struct expression_stack **head)
{
	struct expression_stack        *cur;
	gchar                           res;

	if (*head == NULL)
		return 0;

	cur = *head;
	res = cur->op;

	*head = cur->next;
	return res;
}

/*
 * Return operation priority
 */
static gint
logic_priority (gchar a)
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
static                          gboolean
is_operation_symbol (gchar *a)
{
	switch (*a) {
	case '!':
	case '&':
	case '|':
	case '(':
	case ')':
		return TRUE;
	case 'O':
	case 'o':
		if (g_ascii_strncasecmp (a, "or", sizeof ("or") - 1) == 0&& g_ascii_isspace (a[2])) {
			return TRUE;
		}
		break;
	case 'A':
	case 'a':
		if (g_ascii_strncasecmp (a, "and", sizeof ("and") - 1) == 0&& g_ascii_isspace (a[3])) {
			return TRUE;
		}
		break;
	case 'N':
	case 'n':
		if (g_ascii_strncasecmp (a, "not", sizeof ("not") - 1) == 0 && g_ascii_isspace (a[3])) {
			return TRUE;
		}
		break;
	}

	return FALSE;
}

/* Return character representation of operation */
static gchar
op_to_char (gchar *a, gchar **next)
{
	switch (*a) {
	case '!':
	case '&':
	case '|':
	case '(':
	case ')':
		*next = a + 1;
		return *a;
	case 'O':
	case 'o':
		if (g_ascii_strncasecmp (a, "or", sizeof ("or") - 1) == 0) {
			*next = a + sizeof ("or") - 1;
			return '|';
		}
		break;
	case 'A':
	case 'a':
		if (g_ascii_strncasecmp (a, "and", sizeof ("and") - 1) == 0) {
			*next = a + sizeof ("and") - 1;
			return '&';
		}
		break;
	case 'N':
	case 'n':
		if (g_ascii_strncasecmp (a, "not", sizeof ("not") - 1) == 0) {
			*next = a + sizeof ("not") - 1;
			return '!';
		}
		break;
	}

	return '\0';
}

/*
 * Return TRUE if symbol can be regexp flag
 */
static                          gboolean
is_regexp_flag (gchar a)
{
	switch (a) {
	case 'i':
	case 'm':
	case 'x':
	case 's':
	case 'u':
	case 'o':
	case 'r':
	case 'H':
	case 'M':
	case 'P':
	case 'U':
	case 'X':
	case 'T':
	case 'S':
		return TRUE;
	default:
		return FALSE;
	}
}

static void
insert_expression (memory_pool_t * pool, struct expression **head, gint type, gchar op, void *operand, const gchar *orig)
{
	struct expression              *new, *cur;

	new = memory_pool_alloc (pool, sizeof (struct expression));
	new->type = type;
	new->orig = orig;
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

static struct expression       *
maybe_parse_expression (memory_pool_t * pool, gchar *line)
{
	struct expression              *expr;
	gchar                           *p = line;

	while (*p) {
		if (is_operation_symbol (p)) {
			return parse_expression (pool, line);
		}
		p++;
	}

	expr = memory_pool_alloc (pool, sizeof (struct expression));
	expr->type = EXPR_STR;
	expr->content.operand = memory_pool_strdup (pool, line);
	expr->next = NULL;

	return expr;
}

/*
 * Make inverse polish record for specified expression
 * Memory is allocated from given pool
 */
struct expression              *
parse_expression (memory_pool_t * pool, gchar *line)
{
	struct expression              *expr = NULL;
	struct expression_stack        *stack = NULL;
	struct expression_function     *func = NULL;
	struct expression              *arg;
	GQueue                         *function_stack;
	gchar                           *p, *c, *str, op, newop, *copy, *next;
	gboolean                        in_regexp = FALSE;
	gint                            brackets = 0;

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

	msg_debug ("parsing expression {{ %s }}", line);

	function_stack = g_queue_new ();
	copy = memory_pool_strdup (pool, line);
	p = line;
	c = p;
	while (*p) {
		switch (state) {
		case SKIP_SPACES:
			if (!g_ascii_isspace (*p)) {
				if (is_operation_symbol (p)) {
					state = READ_OPERATOR;
				}
				else if (*p == '/') {
					c = ++p;
					state = READ_REGEXP;
				}
				else {
					c = p;
					state = READ_FUNCTION;
				}
			}
			else {
				p++;
			}
			break;
		case READ_OPERATOR:
			if (*p == ')') {
				if (stack == NULL) {
					return NULL;
				}
				/* Pop all operators from stack to nearest '(' or to head */
				while (stack && stack->op != '(') {
					op = delete_expression_stack (&stack);
					if (op != '(') {
						insert_expression (pool, &expr, EXPR_OPERATION, op, NULL, copy);
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
					newop = op_to_char (p, &next);
					if (newop != '\0') {
						stack = push_expression_stack (pool, stack, newop);
						p = next;
						state = SKIP_SPACES;
						continue;
					}
				}
				/* Check priority of logic operation */
				else {
					newop = op_to_char (p, &next);
					if (newop != '\0') {
						if (logic_priority (stack->op) < logic_priority (newop)) {
							stack = push_expression_stack (pool, stack, newop);
						}
						else {
							/* Pop all operations that have higher priority than this one */
							while ((stack != NULL) && (logic_priority (stack->op) >= logic_priority (newop))) {
								op = delete_expression_stack (&stack);
								if (op != '(') {
									insert_expression (pool, &expr, EXPR_OPERATION, op, NULL, copy);
								}
							}
							stack = push_expression_stack (pool, stack, newop);
						}
					}
					p = next;
					state = SKIP_SPACES;
					continue;
				}
			}
			p++;
			state = SKIP_SPACES;
			break;

		case READ_REGEXP:
			if (*p == '/' && *(p - 1) != '\\') {
				if (*(p + 1)) {
					p++;
				}
				state = READ_REGEXP_FLAGS;
			}
			else {
				p++;
			}
			break;

		case READ_REGEXP_FLAGS:
			if (!is_regexp_flag (*p) || *(p + 1) == '\0') {
				if (c != p) {
					if ((is_regexp_flag (*p) || *p == '/') && *(p + 1) == '\0') {
						p++;
					}
					str = memory_pool_alloc (pool, p - c + 2);
					rspamd_strlcpy (str, c - 1, (p - c + 2));
					g_strstrip (str);
					msg_debug ("found regexp: %s", str);
					if (strlen (str) > 0) {
						insert_expression (pool, &expr, EXPR_REGEXP, 0, str, copy);
					}
				}
				c = p;
				state = SKIP_SPACES;
			}
			else {
				p++;
			}
			break;

		case READ_FUNCTION:
			if (*p == '/') {
				/* In fact it is regexp */
				state = READ_REGEXP;
				c++;
				p++;
			}
			else if (*p == '(') {
				func = memory_pool_alloc (pool, sizeof (struct expression_function));
				func->name = memory_pool_alloc (pool, p - c + 1);
				func->args = NULL;
				rspamd_strlcpy (func->name, c, (p - c + 1));
				g_strstrip (func->name);
				state = READ_FUNCTION_ARGUMENT;
				g_queue_push_tail (function_stack, func);
				insert_expression (pool, &expr, EXPR_FUNCTION, 0, func, copy);
				c = ++p;
			}
			else if (is_operation_symbol (p)) {
				/* In fact it is not function, but symbol */
				if (c != p) {
					str = memory_pool_alloc (pool, p - c + 1);
					rspamd_strlcpy (str, c, (p - c + 1));
					g_strstrip (str);
					if (strlen (str) > 0) {
						insert_expression (pool, &expr, EXPR_STR, 0, str, copy);
					}
				}
				state = READ_OPERATOR;
			}
			else if (*(p + 1) == '\0') {
				/* In fact it is not function, but symbol */
				p++;
				if (c != p) {
					str = memory_pool_alloc (pool, p - c + 1);
					rspamd_strlcpy (str, c, (p - c + 1));
					g_strstrip (str);
					if (strlen (str) > 0) {
						insert_expression (pool, &expr, EXPR_STR, 0, str, copy);
					}
				}
				state = SKIP_SPACES;
			}
			else {
				p++;
			}
			break;

		case READ_FUNCTION_ARGUMENT:
			if (*p == '/' && !in_regexp) {
				in_regexp = TRUE;
				p++;
			}
			if (!in_regexp) {
				/* Append argument to list */
				if (*p == ',' || (*p == ')' && brackets == 0)) {
					arg = NULL;
					str = memory_pool_alloc (pool, p - c + 1);
					rspamd_strlcpy (str, c, (p - c + 1));
					g_strstrip (str);
					/* Recursive call */
					arg = maybe_parse_expression (pool, str);
					func->args = g_list_append (func->args, arg);
					/* Pop function */
					if (*p == ')') {
						/* Last function in chain, goto skipping spaces state */
						func = g_queue_pop_tail (function_stack);
						if (g_queue_get_length (function_stack) == 0) {
							state = SKIP_SPACES;
						}
					}
					c = p + 1;
				}
				else if (*p == '(') {
					brackets++;
				}
				else if (*p == ')') {
					brackets--;
				}
			}
			else if (*p == '/' && *(p - 1) != '\\') {
				in_regexp = FALSE;
			}
			p++;
			break;
		}
	}

	g_queue_free (function_stack);
	if (state != SKIP_SPACES) {
		/* In fact we got bad expression */
		msg_warn ("expression \"%s\" is invalid", line);
		return NULL;
	}
	/* Pop everything from stack */
	while (stack != NULL) {
		op = delete_expression_stack (&stack);
		if (op != '(') {
			insert_expression (pool, &expr, EXPR_OPERATION, op, NULL, copy);
		}
	}

	return expr;
}

/*
 * Rspamd regexp utility functions
 */
struct rspamd_regexp           *
parse_regexp (memory_pool_t * pool, gchar *line, gboolean raw_mode)
{
	gchar                           *begin, *end, *p, *src, *start;
	struct rspamd_regexp           *result, *check;
	gint                            regexp_flags = G_REGEX_OPTIMIZE | G_REGEX_NO_AUTO_CAPTURE;
	GError                         *err = NULL;

	if (line == NULL) {
		msg_err ("cannot parse NULL line");
		return NULL;
	}

	src = line;
	result = memory_pool_alloc0 (pool, sizeof (struct rspamd_regexp));
	/* Skip whitespaces */
	while (g_ascii_isspace (*line)) {
		line++;
	}
	if (line == '\0') {
		msg_warn ("got empty regexp");
		return NULL;
	}
	start = line;
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
		result->header = memory_pool_strdup (pool, line);
		result->type = REGEXP_HEADER;
		line = start;
	}
	/* Find begin of regexp */
	while (*line && *line != '/') {
		line++;
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
		msg_warn ("got no header name (eg. header=) but without corresponding regexp, %s", src);
		return NULL;
	}
	/* Find end */
	end = begin;
	while (*end && (*end != '/' || *(end - 1) == '\\')) {
		end++;
	}
	if (end == begin || *end != '/') {
		msg_warn ("no trailing / in regexp %s", src);
		return NULL;
	}
	/* Parse flags */
	p = end + 1;
	while (p != NULL) {
		switch (*p) {
		case 'i':
			regexp_flags |= G_REGEX_CASELESS;
			p++;
			break;
		case 'm':
			regexp_flags |= G_REGEX_MULTILINE;
			p++;
			break;
		case 's':
			regexp_flags |= G_REGEX_DOTALL;
			p++;
			break;
		case 'x':
			regexp_flags |= G_REGEX_EXTENDED;
			p++;
			break;
		case 'u':
			regexp_flags |= G_REGEX_UNGREEDY;
			p++;
			break;
		case 'o':
			regexp_flags |= G_REGEX_OPTIMIZE;
			p++;
			break;
		case 'r':
			regexp_flags |= G_REGEX_RAW;
			result->is_raw = TRUE;
			p++;
			break;
			/* Type flags */
		case 'H':
			if (result->type == REGEXP_NONE) {
				result->type = REGEXP_HEADER;
			}
			p++;
			break;
		case 'M':
			if (result->type == REGEXP_NONE) {
				result->type = REGEXP_MESSAGE;
			}
			p++;
			break;
		case 'P':
			if (result->type == REGEXP_NONE) {
				result->type = REGEXP_MIME;
			}
			p++;
			break;
		case 'U':
			if (result->type == REGEXP_NONE) {
				result->type = REGEXP_URL;
			}
			p++;
			break;
		case 'X':
			if (result->type == REGEXP_NONE || result->type == REGEXP_HEADER) {
				result->type = REGEXP_RAW_HEADER;
			}
			p++;
			break;
		case 'T':
			result->is_test = TRUE;
			p ++;
			break;
		case 'S':
			result->is_strong = TRUE;
			p ++;
			break;
			/* Stop flags parsing */
		default:
			p = NULL;
			break;
		}
	}

	*end = '\0';

	if (raw_mode) {
		regexp_flags |= G_REGEX_RAW;
	}

	/* Avoid multiply regexp structures for similar regexps */
	if ((check = (struct rspamd_regexp *)re_cache_check (begin, pool)) != NULL) {
		/* Additional check for headers */
		if (result->type == REGEXP_HEADER || result->type == REGEXP_RAW_HEADER) {
			if (result->header && check->header) {
				if (strcmp (result->header, check->header) == 0) {
					return check;
				}
			}
		}
		else {
			return check;
		}
	}
	result->regexp = g_regex_new (begin, regexp_flags, 0, &err);
	if ((regexp_flags & G_REGEX_RAW) != 0) {
		result->raw_regexp = result->regexp;
	}
	else {
		result->raw_regexp = g_regex_new (begin, regexp_flags | G_REGEX_RAW, 0, &err);
		memory_pool_add_destructor (pool, (pool_destruct_func) g_regex_unref, (void *)result->raw_regexp);
	}
	*end = '/';
	result->regexp_text = memory_pool_strdup (pool, start);
	memory_pool_add_destructor (pool, (pool_destruct_func) g_regex_unref, (void *)result->regexp);

	if (result->regexp == NULL || err != NULL) {
		*end = '/';
		msg_warn ("could not read regexp: %s while reading regexp %s", err->message, src);
		return NULL;
	}


	if (result->raw_regexp == NULL || err != NULL) {
		msg_warn ("could not read raw regexp: %s while reading regexp %s", err->message, src);
		return NULL;
	}

	/* Add to cache for further usage */
	re_cache_add (result->regexp_text, result, pool);
	return result;
}

gboolean
call_expression_function (struct expression_function * func, struct worker_task * task, lua_State *L)
{
	struct _fl                     *selected, key;

	key.name = func->name;

	selected = bsearch (&key, list_ptr, functions_number, sizeof (struct _fl), fl_cmp);
	if (selected == NULL) {
		/* Try to check lua function */
		return FALSE;
	}

	return selected->func (task, func->args, selected->user_data);
}

struct expression_argument     *
get_function_arg (struct expression *expr, struct worker_task *task, gboolean want_string)
{
	GQueue                         *stack;
	gsize                           cur, op1, op2;
	struct expression_argument     *res;
	struct expression              *it;

	if (expr == NULL) {
		msg_warn ("NULL expression passed");
		return NULL;
	}
	if (expr->next == NULL) {
		res = memory_pool_alloc (task->task_pool, sizeof (struct expression_argument));
		if (expr->type == EXPR_REGEXP || expr->type == EXPR_STR || expr->type == EXPR_REGEXP_PARSED) {
			res->type = EXPRESSION_ARGUMENT_NORMAL;
			res->data = expr->content.operand;
		}
		else if (expr->type == EXPR_FUNCTION && !want_string) {
			res->type = EXPRESSION_ARGUMENT_BOOL;
			cur = call_expression_function (expr->content.operand, task, NULL);
			res->data = GSIZE_TO_POINTER (cur);
		}
		else {
			msg_warn ("cannot parse argument: it contains operator or bool expression that is not wanted");
			return NULL;
		}
		return res;
	}
	else if (!want_string) {
		res = memory_pool_alloc (task->task_pool, sizeof (struct expression_argument));
		res->type = EXPRESSION_ARGUMENT_BOOL;
		stack = g_queue_new ();
		it = expr;

		while (it) {
			if (it->type == EXPR_REGEXP || it->type == EXPR_REGEXP_PARSED || it->type == EXPR_STR) {
				g_queue_free (stack);
				res->type = EXPRESSION_ARGUMENT_EXPR;
				res->data = expr;
				return res;
			}
			else if (it->type == EXPR_FUNCTION) {
				cur = (gsize) call_expression_function ((struct expression_function *)it->content.operand, task, NULL);
				debug_task ("function %s returned %s", ((struct expression_function *)it->content.operand)->name, cur ? "true" : "false");
			}
			else if (it->type == EXPR_OPERATION) {
				if (g_queue_is_empty (stack)) {
					/* Queue has no operands for operation, exiting */
					debug_task ("invalid expression");
					g_queue_free (stack);
					return NULL;
				}
				switch (it->content.operation) {
				case '!':
					op1 = GPOINTER_TO_SIZE (g_queue_pop_head (stack));
					op1 = !op1;
					g_queue_push_head (stack, GSIZE_TO_POINTER (op1));
					break;
				case '&':
					op1 = GPOINTER_TO_SIZE (g_queue_pop_head (stack));
					op2 = GPOINTER_TO_SIZE (g_queue_pop_head (stack));
					g_queue_push_head (stack, GSIZE_TO_POINTER (op1 && op2));
					break;
				case '|':
					op1 = GPOINTER_TO_SIZE (g_queue_pop_head (stack));
					op2 = GPOINTER_TO_SIZE (g_queue_pop_head (stack));
					g_queue_push_head (stack, GSIZE_TO_POINTER (op1 || op2));
					break;
				default:
					it = it->next;
					continue;
				}
			}
			if (it) {
				it = it->next;
			}
		}
		if (!g_queue_is_empty (stack)) {
			res->data = g_queue_pop_head (stack);
		}
		else {
			res->data = GSIZE_TO_POINTER (FALSE);
		}

		return res;
	}

	msg_warn ("invalid expression argument");

	return NULL;
}

void
register_expression_function (const gchar *name, rspamd_internal_func_t func, void *user_data)
{
	static struct _fl              *new;

	functions_number++;

	new = g_new (struct _fl, functions_number);
	memcpy (new, list_ptr, (functions_number - 1) * sizeof (struct _fl));
	if (list_allocated) {
		g_free (list_ptr);
	}

	list_allocated = TRUE;
	new[functions_number - 1].name = name;
	new[functions_number - 1].func = func;
	new[functions_number - 1].user_data = user_data;
	qsort (new, functions_number, sizeof (struct _fl), fl_cmp);
	list_ptr = new;
}

gboolean
rspamd_compare_encoding (struct worker_task *task, GList * args, void *unused)
{
	struct expression_argument     *arg;

	if (args == NULL || task == NULL) {
		return FALSE;
	}

	arg = get_function_arg (args->data, task, TRUE);
	if (arg->type == EXPRESSION_ARGUMENT_BOOL) {
		msg_warn ("invalid argument to function is passed");
		return FALSE;
	}

	/* XXX: really write this function */
	return TRUE;
}

gboolean
rspamd_header_exists (struct worker_task * task, GList * args, void *unused)
{
	struct expression_argument     *arg;
	GList                          *headerlist;

	if (args == NULL || task == NULL) {
		return FALSE;
	}

	arg = get_function_arg (args->data, task, TRUE);
	if (!arg || arg->type == EXPRESSION_ARGUMENT_BOOL) {
		msg_warn ("invalid argument to function is passed");
		return FALSE;
	}

	debug_task ("try to get header %s", (gchar *)arg->data);
	headerlist = message_get_header (task->task_pool, task->message, (gchar *)arg->data, FALSE);
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
rspamd_parts_distance (struct worker_task * task, GList * args, void *unused)
{
	gint                            threshold, threshold2 = -1, diff;
	struct mime_text_part          *p1, *p2;
	GList                          *cur;
	struct expression_argument     *arg;
	GMimeObject                    *parent;
	const GMimeContentType         *ct;
	gint                           *pdiff;

	if (args == NULL) {
		debug_task ("no threshold is specified, assume it 100");
		threshold = 100;
	}
	else {
		errno = 0;
		arg = get_function_arg (args->data, task, TRUE);
		threshold = strtoul ((gchar *)arg->data, NULL, 10);
		if (errno != 0) {
			msg_info ("bad numeric value for threshold \"%s\", assume it 100", (gchar *)args->data);
			threshold = 100;
		}
		if (args->next) {
			arg = get_function_arg (args->next->data, task, TRUE);
			errno = 0;
			threshold2 = strtoul ((gchar *)arg->data, NULL, 10);
			if (errno != 0) {
				msg_info ("bad numeric value for threshold \"%s\", ignore it", (gchar *)arg->data);
				threshold2 = -1;
			}
		}
	}

	if ((pdiff = memory_pool_get_variable (task->task_pool, "parts_distance")) != NULL) {
		diff = *pdiff;
		if (diff != -1) {
			if (threshold2 > 0) {
				if (diff >= MIN (threshold, threshold2) && diff < MAX (threshold, threshold2)) {
					return TRUE;
				}
			}
			else {
				if (diff <= threshold) {
					return TRUE;
				}
			}
			return FALSE;
		}
		else {
			return FALSE;
		}
	}

	if (g_list_length (task->text_parts) == 2) {
		cur = g_list_first (task->text_parts);
		p1 = cur->data;
		cur = g_list_next (cur);
		pdiff = memory_pool_alloc (task->task_pool, sizeof (gint));
		*pdiff = -1;

		if (cur == NULL) {
			msg_info ("bad parts list");
			return FALSE;
		}
		p2 = cur->data;
		/* First of all check parent object */
		if (p1->parent && p1->parent == p2->parent) {
			parent = p1->parent;
			ct = g_mime_object_get_content_type (parent);
#ifndef GMIME24
			if (ct == NULL || ! g_mime_content_type_is_type (ct, "multipart", "alternative")) {
#else
			if (ct == NULL || ! g_mime_content_type_is_type ((GMimeContentType *)ct, "multipart", "alternative")) {
#endif
				debug_task ("two parts are not belong to multipart/alternative container, skip check");
				memory_pool_set_variable (task->task_pool, "parts_distance", pdiff, NULL);
				return FALSE;
			}
		}
		else {
			debug_task ("message contains two parts but they are in different multi-parts");
			memory_pool_set_variable (task->task_pool, "parts_distance", pdiff, NULL);
			return FALSE;
		}
		if (!p1->is_empty && !p2->is_empty) {
			if (p1->diff_str != NULL && p2->diff_str != NULL) {
				diff = compare_diff_distance (p1->diff_str, p2->diff_str);
			}
			else {
				diff = fuzzy_compare_parts (p1, p2);
			}
			debug_task ("got likeliness between parts of %d%%, threshold is %d%%", diff, threshold);
			*pdiff = diff;
			memory_pool_set_variable (task->task_pool, "parts_distance", pdiff, NULL);
			if (threshold2 > 0) {
				if (diff >= MIN (threshold, threshold2) && diff < MAX (threshold, threshold2)) {
					return TRUE;
				}
			}
			else {
				if (diff <= threshold) {
					return TRUE;
				}
			}
		}
		else if ((p1->is_empty && !p2->is_empty) || (!p1->is_empty && p2->is_empty)) {
			/* Empty and non empty parts are different */
			*pdiff = 0;
			memory_pool_set_variable (task->task_pool, "parts_distance", pdiff, NULL);
			return TRUE;
		}
	}
	else {
		debug_task ("message has too many text parts, so do not try to compare them with each other");
		memory_pool_set_variable (task->task_pool, "parts_distance", pdiff, NULL);
		return FALSE;
	}

	memory_pool_set_variable (task->task_pool, "parts_distance", pdiff, NULL);
	return FALSE;
}

struct addr_list {
	const gchar                     *name;
	const gchar                     *addr;
};

#define COMPARE_RCPT_LEN 3
#define MIN_RCPT_TO_COMPARE 7

gboolean
rspamd_recipients_distance (struct worker_task *task, GList * args, void *unused)
{
	struct expression_argument     *arg;
	InternetAddressList            *cur;
	InternetAddress                *addr;
	double                          threshold;
	struct addr_list               *ar;
	gchar                           *c;
	gint                            num, i, j, hits = 0, total = 0;

	if (args == NULL) {
		msg_warn ("no parameters to function");
		return FALSE;
	}

	arg = get_function_arg (args->data, task, TRUE);
	errno = 0;
	threshold = strtod ((gchar *)arg->data, NULL);
	if (errno != 0) {
		msg_warn ("invalid numeric value '%s': %s", (gchar *)arg->data, strerror (errno));
		return FALSE;
	}

	if (!task->rcpts) {
		return FALSE;
	}
	num = internet_address_list_length (task->rcpts);
	if (num < MIN_RCPT_TO_COMPARE) {
		return FALSE;
	}
	ar = memory_pool_alloc0 (task->task_pool, num * sizeof (struct addr_list));

	/* Fill array */
	cur = task->rcpts;
#ifdef GMIME24
	for (i = 0; i < num; i ++) {
		addr = internet_address_list_get_address (cur, i);
		ar[i].name = memory_pool_strdup (task->task_pool, internet_address_get_name (addr));
		if (ar[i].name != NULL && (c = strchr (ar[i].name, '@')) != NULL) {
			*c = '\0';
			ar[i].addr = c + 1;
		}
	}
#else
	i = 0;
	while (cur) {
		addr = internet_address_list_get_address (cur);
		if (addr && internet_address_get_type (addr) == INTERNET_ADDRESS_NAME) {
			ar[i].name = memory_pool_strdup (task->task_pool, internet_address_get_addr (addr));
			if (ar[i].name != NULL && (c = strchr (ar[i].name, '@')) != NULL) {
				*c = '\0';
				ar[i].addr = c + 1;
			}
			cur = internet_address_list_next (cur);
			i++;
		}
		else {
			cur = internet_address_list_next (cur);
		}
	}
#endif

	/* Cycle all elements in array */
	for (i = 0; i < num; i++) {
		for (j = i + 1; j < num; j++) {
			if (ar[i].name && ar[j].name && g_ascii_strncasecmp (ar[i].name, ar[j].name, COMPARE_RCPT_LEN) == 0) {
				/* Common name part */
				hits++;
			}
			else if (ar[i].addr && ar[j].addr && g_ascii_strcasecmp (ar[i].addr, ar[j].addr) == 0) {
				/* Common address part, but different name */
				hits++;
			}
			total++;
		}
	}

	if ((double)(hits * num / 2.) / (double)total >= threshold) {
		return TRUE;
	}

	return FALSE;
}

gboolean
rspamd_has_only_html_part (struct worker_task * task, GList * args, void *unused)
{
	struct mime_text_part          *p;
	GList                          *cur;
	gboolean                        res = FALSE;

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

static                          gboolean
is_recipient_list_sorted (const InternetAddressList * ia)
{
	const InternetAddressList      *cur;
	InternetAddress                *addr;
	gboolean                        res = TRUE;
	struct addr_list                current = { NULL, NULL }, previous = {
	NULL, NULL};
#ifdef GMIME24
	gint                            num, i;
#endif

	/* Do not check to short address lists */
	if (internet_address_list_length ((InternetAddressList *)ia) < MIN_RCPT_TO_COMPARE) {
		return FALSE;
	}
#ifdef GMIME24
	num = internet_address_list_length ((InternetAddressList *)ia);
	cur = ia;
	for (i = 0; i < num; i ++) {
		addr = internet_address_list_get_address ((InternetAddressList *)cur, i);
		current.addr = (gchar *)internet_address_get_name (addr);
		if (previous.addr != NULL) {
			if (current.addr && g_ascii_strcasecmp (current.addr, previous.addr) < 0) {
				res = FALSE;
				break;
			}
		}
		previous.addr = current.addr;
	}
#else
	cur = ia;
	while (cur) {
		addr = internet_address_list_get_address (cur);
		if (internet_address_get_type (addr) == INTERNET_ADDRESS_NAME) {
			current.addr = internet_address_get_addr (addr);
			if (previous.addr != NULL) {
				if (current.addr && g_ascii_strcasecmp (current.addr, previous.addr) < 0) {
					res = FALSE;
					break;
				}
			}
			previous.addr = current.addr;
		}
		cur = internet_address_list_next (cur);
	}
#endif

	return res;
}

gboolean
rspamd_is_recipients_sorted (struct worker_task * task, GList * args, void *unused)
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

gboolean
rspamd_compare_transfer_encoding (struct worker_task * task, GList * args, void *unused)
{
	GMimeObject                    *part;
#ifndef GMIME24
	GMimePartEncodingType           enc_req, part_enc;
#else
	GMimeContentEncoding            enc_req, part_enc;
#endif
	struct expression_argument     *arg;

	if (args == NULL) {
		msg_warn ("no parameters to function");
		return FALSE;
	}

	arg = get_function_arg (args->data, task, TRUE);
#ifndef GMIME24
	enc_req = g_mime_part_encoding_from_string (arg->data);
	if (enc_req == GMIME_PART_ENCODING_DEFAULT) {
#else
	enc_req = g_mime_content_encoding_from_string (arg->data);
	if (enc_req == GMIME_CONTENT_ENCODING_DEFAULT) {
#endif
		msg_warn ("bad encoding type: %s", (gchar *)arg->data);
		return FALSE;
	}

	part = g_mime_message_get_mime_part (task->message);
	if (part) {
		if (GMIME_IS_PART (part)) {
#ifndef GMIME24
			part_enc = g_mime_part_get_encoding (GMIME_PART (part));
			if (part_enc == GMIME_PART_ENCODING_DEFAULT) {
				/* Assume 7bit as default transfer encoding */
				part_enc = GMIME_PART_ENCODING_7BIT;
			}
#else
			part_enc = g_mime_part_get_content_encoding (GMIME_PART (part));
			if (part_enc == GMIME_CONTENT_ENCODING_DEFAULT) {
				/* Assume 7bit as default transfer encoding */
				part_enc = GMIME_CONTENT_ENCODING_7BIT;
			}
#endif


			debug_task ("got encoding in part: %d and compare with %d", (gint)part_enc, (gint)enc_req);
#ifndef GMIME24
			g_object_unref (part);
#endif

			return part_enc == enc_req;
		}
#ifndef GMIME24
		g_object_unref (part);
#endif
	}

	return FALSE;
}

gboolean
rspamd_is_html_balanced (struct worker_task * task, GList * args, void *unused)
{
	struct mime_text_part          *p;
	GList                          *cur;
	gboolean                        res = TRUE;

	cur = g_list_first (task->text_parts);
	while (cur) {
		p = cur->data;
		if (!p->is_empty && p->is_html) {
			if (p->is_balanced) {
				res = TRUE;
			}
			else {
				res = FALSE;
				break;
			}
		}
		cur = g_list_next (cur);
	}

	return res;

}

struct html_callback_data {
	struct html_tag                *tag;
	gboolean                       *res;
};

static                          gboolean
search_html_node_callback (GNode * node, gpointer data)
{
	struct html_callback_data      *cd = data;
	struct html_node               *nd;

	nd = node->data;
	if (nd) {
		if (nd->tag == cd->tag) {
			*cd->res = TRUE;
			return TRUE;
		}
	}

	return FALSE;
}

gboolean
rspamd_has_html_tag (struct worker_task * task, GList * args, void *unused)
{
	struct mime_text_part          *p;
	GList                          *cur;
	struct expression_argument     *arg;
	struct html_tag                *tag;
	gboolean                        res = FALSE;
	struct html_callback_data       cd;

	if (args == NULL) {
		msg_warn ("no parameters to function");
		return FALSE;
	}

	arg = get_function_arg (args->data, task, TRUE);
	tag = get_tag_by_name (arg->data);
	if (tag == NULL) {
		msg_warn ("unknown tag type passed as argument: %s", (gchar *)arg->data);
		return FALSE;
	}

	cur = g_list_first (task->text_parts);
	cd.res = &res;
	cd.tag = tag;

	while (cur && res == FALSE) {
		p = cur->data;
		if (!p->is_empty && p->is_html && p->html_nodes) {
			g_node_traverse (p->html_nodes, G_PRE_ORDER, G_TRAVERSE_ALL, -1, search_html_node_callback, &cd);
		}
		cur = g_list_next (cur);
	}

	return res;

}

gboolean
rspamd_has_fake_html (struct worker_task * task, GList * args, void *unused)
{
	struct mime_text_part          *p;
	GList                          *cur;
	gboolean                        res = FALSE;

	cur = g_list_first (task->text_parts);

	while (cur && res == FALSE) {
		p = cur->data;
		if (!p->is_empty && p->is_html && p->html_nodes == NULL) {
			res = TRUE;
		}
		cur = g_list_next (cur);
	}

	return res;

}


/*
 * vi:ts=4
 */
