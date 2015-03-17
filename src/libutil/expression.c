/*
 * Copyright (c) 2015, Vsevolod Stakhov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *	 * Redistributions of source code must retain the above copyright
 *	   notice, this list of conditions and the following disclaimer.
 *	 * Redistributions in binary form must reproduce the above copyright
 *	   notice, this list of conditions and the following disclaimer in the
 *	   documentation and/or other materials provided with the distribution.
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
#include "expression.h"
#include "printf.h"
#include "regexp.h"

#define RSPAMD_EXPR_FLAG_NEGATE (1 << 0)
#define RSPAMD_EXPR_FLAG_PROCESSED (1 << 1)

enum rspamd_expression_op {
	OP_INVALID = 0,
	OP_PLUS, /* || or + */
	OP_MULT, /* && or * */
	OP_OR, /* || or | */
	OP_AND, /* && or & */
	OP_NOT, /* ! */
	OP_LT, /* < */
	OP_GT, /* > */
	OP_LE, /* <= */
	OP_GE, /* >= */
	OP_OBRACE, /* ( */
	OP_CBRACE /* ) */
};

struct rspamd_expression_elt {
	enum {
		ELT_OP = 0,
		ELT_ATOM,
		ELT_LIMIT
	} type;

	union {
		rspamd_expression_atom_t *atom;
		enum rspamd_expression_op op;
		struct {
			gint val;
			gint op_idx;
		} lim;
	} p;
	gint flags;
	gint value;
};

struct rspamd_expression {
	const struct rspamd_atom_subr *subr;
	GArray *expressions;
	GArray *expression_stack;
};

static GQuark
rspamd_expr_quark (void)
{
	return g_quark_from_static_string ("rspamd-expression");
}

static void
rspamd_expr_stack_push (struct rspamd_expression *expr,
		gpointer elt)
{
	g_array_append_val (expr->expression_stack, elt);
}

static gpointer
rspamd_expr_stack_pop (struct rspamd_expression *expr)
{
	gpointer e;
	gint idx;

	if (expr->expression_stack->len == 0) {
		return NULL;
	}

	idx = expr->expression_stack->len - 1;
	e = g_array_index (expr->expression_stack, gpointer, idx);
	g_array_remove_index_fast (expr->expression_stack, idx);

	return e;
}

/*
 * Return operation priority
 */
static gint
rspamd_expr_logic_priority (enum rspamd_expression_op op)
{
	gint ret = 0;

	switch (op) {
	case OP_NOT:
		ret = 5;
		break;
	case OP_MULT:
	case OP_AND:
		ret = 4;
		break;
	case OP_PLUS:
	case OP_OR:
		ret = 3;
		break;
	case OP_GE:
	case OP_GT:
	case OP_LE:
	case OP_LT:
		ret = 2;
		break;
	case OP_OBRACE:
	case OP_CBRACE:
		ret = 1;
		break;
	case OP_INVALID:
		ret = -1;
		break;
	}

	return ret;
}

/*
 * Return FALSE if symbol is not operation symbol (operand)
 * Return TRUE if symbol is operation symbol
 */
static gboolean
rspamd_expr_is_operation_symbol (gchar a)
{
	switch (a) {
	case '!':
	case '&':
	case '|':
	case '(':
	case ')':
	case '>':
	case '<':
		return TRUE;
	}

	return FALSE;
}

/* Return character representation of operation */
static enum rspamd_expression_op
rspamd_expr_str_to_op (const gchar *a, const gchar *end, const gchar **next)
{
	enum rspamd_expression_op op = OP_INVALID;

	g_assert (a < end);

	switch (*a) {
	case '!':
	case '&':
	case '|':
	case '+':
	case '*':
	case '(':
	case ')': {
		if (a < end - 1) {
			if ((a[0] == '&' && a[1] == '&') ||
					(a[0] == '|' && a[1] == '|')) {
				*next = a + 2;
			}
			else {
				*next = a + 1;
			}
		}
		else {
			*next = end;
		}
		/* XXX: not especially effective */
		switch (*a) {
		case '!':
			op = OP_NOT;
			break;
		case '&':
			op = OP_AND;
			break;
		case '*':
			op = OP_MULT;
			break;
		case '|':
			op = OP_OR;
			break;
		case '+':
			op = OP_PLUS;
			break;
		case ')':
			op = OP_CBRACE;
			break;
		case '(':
			op = OP_OBRACE;
			break;
		default:
			op = OP_INVALID;
			break;
		}
		break;
	}
	case 'O':
	case 'o':
		if ((gulong)(end - a) >= sizeof ("or") &&
				g_ascii_strncasecmp (a, "or", sizeof ("or") - 1) == 0) {
			*next = a + sizeof ("or") - 1;
			op = OP_OR;
		}
		break;
	case 'A':
	case 'a':
		if ((gulong)(end - a) >= sizeof ("and") &&
				g_ascii_strncasecmp (a, "and", sizeof ("and") - 1) == 0) {
			*next = a + sizeof ("and") - 1;
			op = OP_AND;
		}
		break;
	case 'N':
	case 'n':
		if ((gulong)(end - a) >= sizeof ("not") &&
				g_ascii_strncasecmp (a, "not", sizeof ("not") - 1) == 0) {
			*next = a + sizeof ("not") - 1;
			op = OP_NOT;
		}
		break;
	case '>':
		if (a < end - 1 && a[1] == '=') {
			*next = a + 2;
			op = OP_GE;
		}
		else {
			*next = a + 1;
			op = OP_GT;
		}
		break;
	case '<':
		if (a < end - 1 && a[1] == '=') {
			*next = a + 2;
			op = OP_LE;
		}
		else {
			*next = a + 1;
			op = OP_LT;
		}
		break;
	default:
		op = OP_INVALID;
		break;
	}

	return op;
}

static void
rspamd_expression_destroy (struct rspamd_expression *expr)
{
	guint i;
	struct rspamd_expression_elt *elt;

	if (expr != NULL) {

		if (expr->subr->destroy) {
			/* Free atoms */
			for (i = 0; i < expr->expressions->len; i ++) {
				elt = &g_array_index (expr->expressions,
						struct rspamd_expression_elt, i);

				if (elt->type == ELT_ATOM) {
					expr->subr->destroy (elt->p.atom);
				}
			}
		}

		g_array_free (expr->expressions, TRUE);
		g_array_free (expr->expression_stack, TRUE);
	}
}

gboolean
rspamd_parse_expression (const gchar *line, gsize len,
		const struct rspamd_atom_subr *subr, gpointer subr_data,
		rspamd_mempool_t *pool, GError **err,
		struct rspamd_expression **target)
{
	struct rspamd_expression *e;
	struct rspamd_expression_elt elt;
	rspamd_expression_atom_t *atom;
	rspamd_regexp_t *num_re;
	enum rspamd_expression_op op, op_stack;
	const gchar *p, *c, *end;

	enum {
		PARSE_ATOM = 0,
		PARSE_OP,
		PARSE_LIM,
		SKIP_SPACES
	} state;

	g_assert (line != NULL);
	g_assert (subr != NULL && subr->parse != NULL);

	if (len == 0) {
		len = strlen (line);
	}

	num_re = rspamd_regexp_cache_create (NULL, "/^\\d+\\s*[><]/", NULL, NULL);

	p = line;
	c = line;
	end = line + len;
	e = g_slice_alloc (sizeof (*e));
	e->expressions = g_array_new (FALSE, FALSE,
			sizeof (struct rspamd_expression_elt));
	e->expression_stack = g_array_sized_new (FALSE, FALSE, sizeof (gpointer), 32);
	e->subr = subr;

	/* Shunting-yard algorithm */
	while (p < end) {
		switch (state) {
		case PARSE_ATOM:
			if (g_ascii_isspace (*p)) {
				state = SKIP_SPACES;
			}
			else if (rspamd_expr_is_operation_symbol (*p)) {
				state = PARSE_OP;
			}
			else {
				/*
				 * First of all, we check some pre-conditions:
				 * 1) if we have 'and ' or 'or ' or 'not ' strings, they are op
				 * 2) if we have full numeric string, then we check for
				 * the following expression:
				 *  ^\d+\s*[><]$
				 */
				if ((gulong)(end - p) > sizeof ("and ") &&
					(g_ascii_strncasecmp (p, "and ", sizeof ("and ") - 1) == 0 ||
					g_ascii_strncasecmp (p, "not ", sizeof ("not ") - 1) == 0 )) {
					state = PARSE_OP;
				}
				else if ((gulong)(end - p) > sizeof ("or ") &&
					g_ascii_strncasecmp (p, "or ", sizeof ("or ") - 1) == 0) {
					state = PARSE_OP;
				}
				else if (rspamd_regexp_search (num_re, p, end - p, NULL, NULL,
						FALSE)) {
					c = p;
					state = PARSE_LIM;
				}
				else {
					/* Try to parse atom */
					atom = subr->parse (p, end - p, pool, subr_data, err);
					if (atom == NULL) {
						/* We couldn't parse the atom, so go out */
						goto err;
					}
					g_assert (atom->len != 0);
					p = p + atom->len;

					/* Push to output */
					elt.type = ELT_ATOM;
					elt.p.atom = atom;
					g_array_append_val (e->expressions, elt);
				}
			}
			break;
		case PARSE_LIM:
			if (g_ascii_isdigit (*p)) {
				p ++;
			}
			else {
				if (p - c > 0) {
					elt.type = ELT_LIMIT;
					elt.p.lim.val = strtoul (c, NULL, 10);
					g_array_append_val (e->expressions, elt);
					c = p;
					state = SKIP_SPACES;
				}
				else {
					g_set_error (err, rspamd_expr_quark(), 400, "Empty number");
					goto err;
				}
			}
			break;
		case PARSE_OP:
			op = rspamd_expr_str_to_op (p, end, &p);
			if (op == OP_INVALID) {
				g_set_error (err, rspamd_expr_quark(), 500, "Bad operator %c",
						*p);
				goto err;
			}
			else if (op == OP_OBRACE) {
				/*
				 * If the token is a left parenthesis, then push it onto
				 * the stack.
				 */
				rspamd_expr_stack_push (e, GINT_TO_POINTER (op));
			}
			else if (op == OP_CBRACE) {
				/*
				 * Until the token at the top of the stack is a left
				 * parenthesis, pop operators off the stack onto the
				 * output queue.
				 *
				 * Pop the left parenthesis from the stack,
				 * but not onto the output queue.
				 *
				 * If the stack runs out without finding a left parenthesis,
				 * then there are mismatched parentheses.
				 */
				do {
					op = GPOINTER_TO_INT (rspamd_expr_stack_pop (e));

					if (op == OP_INVALID) {
						g_set_error (err, rspamd_expr_quark(), 600,
								"Braces mismatch");
						goto err;
					}

					if (op != OP_OBRACE) {
						elt.type = ELT_OP;
						elt.p.op = op;
						g_array_append_val (e->expressions, elt);
					}

				} while (op != OP_OBRACE);
			}
			else {
				/*
				 * While there is an operator token, o2, at the top of
				 * the operator stack, and either:
				 *
				 * - o1 is left-associative and its precedence is less than
				 * or equal to that of o2, or
				 * - o1 is right associative, and has precedence less than
				 * that of o2,
				 *
				 * then pop o2 off the operator stack, onto the output queue;
				 *
				 * push o1 onto the operator stack.
				 */

				for (;;) {
					op_stack = GPOINTER_TO_INT (rspamd_expr_stack_pop (e));

					if (op_stack == OP_INVALID) {
						/* Stack is empty */
						break;
					}

					/* We ignore associativity for now */
					if (op_stack != OP_OBRACE &&
							rspamd_expr_logic_priority (op) <=
							rspamd_expr_logic_priority(op_stack)) {
						elt.type = ELT_OP;
						elt.p.op = op_stack;
						g_array_append_val (e->expressions, elt);
					}
					else {
						/* Push op_stack back */
						rspamd_expr_stack_push (e, GINT_TO_POINTER (op_stack));
						break;
					}
				}

				/* Push new operator itself */
				rspamd_expr_stack_push (e, GINT_TO_POINTER (op));
			}

			state = SKIP_SPACES;
			break;
		case SKIP_SPACES:
			if (g_ascii_isspace (*p)) {
				p ++;
			}
			else if (rspamd_expr_is_operation_symbol (*p)) {
				state = PARSE_OP;
			}
			else {
				state = PARSE_ATOM;
			}
		}
	}

	/* Now we process the stack and push operators to the output */
	while ((op_stack = GPOINTER_TO_INT (rspamd_expr_stack_pop (e)))
			!= OP_INVALID) {
		if (op_stack != OP_OBRACE) {
			elt.type = ELT_OP;
			elt.p.op = op_stack;
			g_array_append_val (e->expressions, elt);
		}
		else {
			g_set_error (err, rspamd_expr_quark(), 600,
					"Braces mismatch");
			goto err;
		}
	}

	if (*target) {
		*target = e;
		rspamd_mempool_add_destructor (pool,
			(rspamd_mempool_destruct_t)rspamd_expression_destroy, e);
	}
	else {
		rspamd_expression_destroy (e);
	}

	return TRUE;

err:
	return FALSE;
}

#define CHOSE_OPERAND(e1, e2) (((e1)->p.atom->priority >= (e2)->p.atom->priority) ? \
		(e1) : (e2))
#define CHOOSE_REMAIN(e1, e2, es) ((es) == (e1) ? (e2) : (e1))
#define PROCESS_ELT(expr, e)	do {										\
		if (!((e)->flags & RSPAMD_EXPR_FLAG_PROCESSED)) {					\
			(e)->value = (expr)->subr->process (data, (e)->p.atom);			\
			(e)->flags |= RSPAMD_EXPR_FLAG_PROCESSED;						\
			if ((e)->flags & RSPAMD_EXPR_FLAG_NEGATE) {						\
				(e)->value = !(e)->value;									\
			}																\
		}																	\
	} while (0)

gint
rspamd_process_expression (struct rspamd_expression *expr, gpointer data)
{
	struct rspamd_expression_elt *elt, *st_elt[2], *ev;
	guint i;

	g_assert (expr != NULL);
	/* Ensure that stack is empty at this point */
	g_assert (expr->expression_stack->len == 0);

	/* Go through the whole expression */
	for (i = 0; i < expr->expressions->len; i ++) {
		elt = &g_array_index (expr->expressions, struct rspamd_expression_elt, i);

		if (elt->type == ELT_ATOM || elt->type == ELT_LIMIT) {
			/* Push this value to the stack without processing */
			rspamd_expr_stack_push (expr, elt);
		}
		else {
			/*
			 * Here we can process atoms on stack and apply
			 * some optimizations for them
			 */
			g_assert (expr->expression_stack->len > 0);

			switch (elt->p.op) {
			case OP_NOT:
				/* Just setup flag for the atom on top of the stack */
				st_elt[0] = rspamd_expr_stack_pop (expr);
				g_assert (st_elt[0]->type == ELT_ATOM);

				if (st_elt[0]->flags & RSPAMD_EXPR_FLAG_NEGATE) {
					st_elt[0]->flags &= ~RSPAMD_EXPR_FLAG_NEGATE;
				}
				else {
					st_elt[0]->flags |= RSPAMD_EXPR_FLAG_NEGATE;
				}

				rspamd_expr_stack_push (expr, st_elt[0]);
				break;
			case OP_OR:
				/* Evaluate first, if it evaluates to true, then push true */
				g_assert (expr->expression_stack->len > 1);
				st_elt[0] = rspamd_expr_stack_pop (expr);
				st_elt[1] = rspamd_expr_stack_pop (expr);
				PROCESS_ELT (expr, ev);

				if (ev->value) {
					rspamd_expr_stack_push (expr, ev);
				}
				else {
					ev = CHOOSE_REMAIN (st_elt[0], st_elt[1], ev);
					PROCESS_ELT (expr, ev);
					/* Push the remaining op */
					rspamd_expr_stack_push (expr, ev);
				}
				break;
			case OP_AND:
				/* Evaluate first, if it evaluates to false, then push false */
				g_assert (expr->expression_stack->len > 1);
				st_elt[0] = rspamd_expr_stack_pop (expr);
				st_elt[1] = rspamd_expr_stack_pop (expr);
				ev = CHOSE_OPERAND (st_elt[0], st_elt[1]);
				PROCESS_ELT (expr, ev);

				if (!ev->value) {
					rspamd_expr_stack_push (expr, ev);
				}
				else {
					ev = CHOOSE_REMAIN (st_elt[0], st_elt[1], ev);
					PROCESS_ELT (expr, ev);
					/* Push the remaining op */
					rspamd_expr_stack_push (expr, ev);
				}
				break;
			default:
				g_assert (0);
				break;
			}
		}
	}

	return 0;
}

GString *
rspamd_expression_tostring (struct rspamd_expression *expr)
{
	GString *res;
	struct rspamd_expression_elt *elt;
	const char *op_str = NULL;
	guint i;

	g_assert (expr != NULL);

	res = g_string_new (NULL);

	for (i = 0; i < expr->expressions->len; i ++) {
		elt = &g_array_index (expr->expressions, struct rspamd_expression_elt, i);

		if (elt->type == ELT_ATOM) {
			g_string_append_len (res, elt->p.atom->str, elt->p.atom->len);
		}
		else if (elt->type == ELT_LIMIT) {
			rspamd_printf_gstring (res, "%d", elt->p.lim.val);
		}
		else {
			switch (elt->p.op) {
			case OP_AND:
				op_str = "&";
				break;
			case OP_OR:
				op_str = "|";
				break;
			case OP_MULT:
				op_str = "*";
				break;
			case OP_PLUS:
				op_str = "+";
				break;
			case OP_NOT:
				op_str = "!";
				break;
			case OP_GE:
				op_str = ">=";
				break;
			case OP_GT:
				op_str = ">";
				break;
			case OP_LE:
				op_str = "<=";
				break;
			case OP_LT:
				op_str = ">=";
				break;
			default:
				op_str = "???";
				break;
			}
			g_string_append (res, op_str);
		}

		if (i != expr->expressions->len - 1) {
			g_string_append_c (res, ' ');
		}
	}

	return res;
}
