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
#include "util.h"
#include "utlist.h"
#include "ottery.h"

#define RSPAMD_EXPR_FLAG_NEGATE (1 << 0)
#define RSPAMD_EXPR_FLAG_PROCESSED (1 << 1)

#define MIN_RESORT_EVALS 50
#define MAX_RESORT_EVALS 150

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
	gint priority;
};

struct rspamd_expression {
	const struct rspamd_atom_subr *subr;
	GArray *expressions;
	GPtrArray *expression_stack;
	GNode *ast;
	guint next_resort;
	guint evals;
};

static GQuark
rspamd_expr_quark (void)
{
	return g_quark_from_static_string ("rspamd-expression");
}


#define G_ARRAY_LAST(ar, type) (&g_array_index((ar), type, (ar)->len - 1))

static void
rspamd_expr_stack_elt_push (GPtrArray *stack,
		gpointer elt)
{
	g_ptr_array_add (stack, elt);
}

static gpointer
rspamd_expr_stack_elt_pop (GPtrArray *stack)
{
	gpointer e;
	gint idx;

	if (stack->len == 0) {
		return NULL;
	}

	idx = stack->len - 1;
	e = g_ptr_array_index (stack, idx);
	g_ptr_array_remove_index_fast (stack, idx);

	return e;
}


static void
rspamd_expr_stack_push (struct rspamd_expression *expr,
		gpointer elt)
{
	rspamd_expr_stack_elt_push (expr->expression_stack, elt);
}

static gpointer
rspamd_expr_stack_pop (struct rspamd_expression *expr)
{
	return rspamd_expr_stack_elt_pop (expr->expression_stack);
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
		ret = 6;
		break;
	case OP_PLUS:
		ret = 5;
		break;
	case OP_GE:
	case OP_GT:
	case OP_LE:
	case OP_LT:
		ret = 4;
		break;
	case OP_MULT:
	case OP_AND:
		ret = 3;
		break;
	case OP_OR:
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
	case '+':
	case '*':
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
		g_ptr_array_free (expr->expression_stack, TRUE);
		g_node_destroy (expr->ast);
	}
}

static void
rspamd_ast_add_node (GPtrArray *operands, struct rspamd_expression_elt *op)
{

	GNode *res, *a1, *a2, *test;
	struct rspamd_expression_elt *test_elt;

	g_assert (op->type == ELT_OP);

	if (op->p.op == OP_NOT) {
		/* Unary operator */
		res = g_node_new (op);
		a1 = rspamd_expr_stack_elt_pop (operands);
		g_node_append (res, a1);
	}
	else {
		/* For binary operators we might want to examine chains */
		a2 = rspamd_expr_stack_elt_pop (operands);
		a1 = rspamd_expr_stack_elt_pop (operands);

		/* First try with a1 */
		test = a1;
		test_elt = test->data;

		if (test_elt->type == ELT_OP && test_elt->p.op == op->p.op) {
			/* Add children */
			g_node_append (test, a2);
			rspamd_expr_stack_elt_push (operands, a1);
			return;
		}
		/* Now test a2 */
		test = a2;
		test_elt = test->data;

		if (test_elt->type == ELT_OP && test_elt->p.op == op->p.op) {
			/* Add children */
			g_node_prepend (test, a1);
			rspamd_expr_stack_elt_push (operands, a2);
			return;
		}

		/* No optimizations possible, so create new level */
		res = g_node_new (op);
		g_node_append (res, a1);
		g_node_append (res, a2);
	}

	/* Push back resulting node to the stack */
	rspamd_expr_stack_elt_push (operands, res);
}

static gboolean
rspamd_ast_priority_traverse (GNode *node, gpointer d)
{
	struct rspamd_expression_elt *elt = node->data, *cur_elt;
	struct rspamd_expression *expr = d;
	gint cnt = 0;
	GNode *cur;

	if (node->children) {
		cur = node->children;
		while (cur) {
			cur_elt = cur->data;
			cnt += cur_elt->priority;
			cur = cur->next;
		}
		elt->priority = cnt;
	}
	else {
		/* It is atom or limit */
		g_assert (elt->type != ELT_OP);

		if (elt->type == ELT_LIMIT) {
			/* Always push limit first */
			elt->priority = 0;
		}
		else {
			elt->priority = RSPAMD_EXPRESSION_MAX_PRIORITY;

			if (expr->subr->priority != NULL) {
				elt->priority = RSPAMD_EXPRESSION_MAX_PRIORITY -
						expr->subr->priority (elt->p.atom);
			}
			elt->p.atom->hits = 0;
			elt->p.atom->avg_ticks = 0.0;
		}
	}

	return FALSE;
}

#define ATOM_PRIORITY(a) ((a)->p.atom->hits / ((a)->p.atom->avg_ticks > 0 ?	\
				(a)->p.atom->avg_ticks * 10000000 : 1.0))

static gint
rspamd_ast_priority_cmp (GNode *a, GNode *b)
{
	struct rspamd_expression_elt *ea = a->data, *eb = b->data;
	gdouble w1, w2;

	/* Special logic for atoms */
	if (ea->type == ELT_ATOM && eb->type == ELT_ATOM &&
			ea->priority == eb->priority) {
		w1 = ATOM_PRIORITY (ea);
		w2 = ATOM_PRIORITY (eb);

		ea->p.atom->hits = 0;
		ea->p.atom->avg_ticks = 0.0;

		return w1 - w2;
	}
	else {
		return ea->priority - eb->priority;
	}
}

static gboolean
rspamd_ast_resort_traverse (GNode *node, gpointer unused)
{
	if (node->children) {
		DL_SORT (node->children, rspamd_ast_priority_cmp);
	}

	return FALSE;
}

static struct rspamd_expression_elt *
rspamd_expr_dup_elt (rspamd_mempool_t *pool, struct rspamd_expression_elt *elt)
{
	struct rspamd_expression_elt *n;

	n = rspamd_mempool_alloc (pool, sizeof (*n));
	memcpy (n, elt, sizeof (*n));

	return n;
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
	GPtrArray *operand_stack;

	enum {
		PARSE_ATOM = 0,
		PARSE_OP,
		PARSE_LIM,
		SKIP_SPACES
	} state = PARSE_ATOM;

	g_assert (line != NULL);
	g_assert (subr != NULL && subr->parse != NULL);

	if (len == 0) {
		len = strlen (line);
	}

	memset (&elt, 0, sizeof (elt));
	num_re = rspamd_regexp_cache_create (NULL, "/^\\d+(?:\\s+|[)]|$)/", NULL, NULL);

	p = line;
	c = line;
	end = line + len;
	e = g_slice_alloc (sizeof (*e));
	e->expressions = g_array_new (FALSE, FALSE,
			sizeof (struct rspamd_expression_elt));
	operand_stack = g_ptr_array_sized_new (32);
	e->ast = NULL;
	e->expression_stack = g_ptr_array_sized_new (32);
	e->subr = subr;
	e->evals = 0;
	e->next_resort = ottery_rand_range (MAX_RESORT_EVALS) + MIN_RESORT_EVALS;

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
					rspamd_expr_stack_elt_push (operand_stack,
							g_node_new (rspamd_expr_dup_elt (pool, &elt)));
				}
			}
			break;
		case PARSE_LIM:
			if (g_ascii_isdigit (*p) && p != end - 1) {
				p ++;
			}
			else {
				if (p == end - 1 && g_ascii_isdigit (*p)) {
					p ++;
				}

				if (p - c > 0) {
					elt.type = ELT_LIMIT;
					elt.p.lim.val = strtoul (c, NULL, 10);
					g_array_append_val (e->expressions, elt);
					rspamd_expr_stack_elt_push (operand_stack,
							g_node_new (rspamd_expr_dup_elt (pool, &elt)));
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
						rspamd_ast_add_node (operand_stack,
								rspamd_expr_dup_elt (pool, &elt));
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
							rspamd_expr_logic_priority (op) <
							rspamd_expr_logic_priority (op_stack)) {
						elt.type = ELT_OP;
						elt.p.op = op_stack;
						g_array_append_val (e->expressions, elt);
						rspamd_ast_add_node (operand_stack,
								rspamd_expr_dup_elt (pool, &elt));
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
			break;
		}
	}

	/* Now we process the stack and push operators to the output */
	while ((op_stack = GPOINTER_TO_INT (rspamd_expr_stack_pop (e)))
			!= OP_INVALID) {
		if (op_stack != OP_OBRACE) {
			elt.type = ELT_OP;
			elt.p.op = op_stack;
			g_array_append_val (e->expressions, elt);
			rspamd_ast_add_node (operand_stack,
					rspamd_expr_dup_elt (pool, &elt));
		}
		else {
			g_set_error (err, rspamd_expr_quark(), 600,
					"Braces mismatch");
			goto err;
		}
	}

	g_assert (operand_stack->len == 1);
	e->ast = rspamd_expr_stack_elt_pop (operand_stack);
	g_ptr_array_free (operand_stack, TRUE);

	/* Set priorities for branches */
	g_node_traverse (e->ast, G_POST_ORDER, G_TRAVERSE_ALL, -1,
			rspamd_ast_priority_traverse, e);

	/* Now set less expensive branches to be evaluated first */
	g_node_traverse (e->ast, G_POST_ORDER, G_TRAVERSE_NON_LEAVES, -1,
			rspamd_ast_resort_traverse, NULL);

	if (target) {
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

static gboolean
rspamd_ast_node_done (struct rspamd_expression_elt *elt,
		struct rspamd_expression_elt *parelt, gint acc, gint lim)
{
	gboolean ret = FALSE;

	g_assert (elt->type == ELT_OP);

	switch (elt->p.op) {
	case OP_NOT:
		ret = TRUE;
		break;
	case OP_PLUS:
		if (parelt && lim > 0) {
			g_assert (parelt->type == ELT_OP);

			switch (parelt->p.op) {
			case OP_GE:
				ret = acc >= lim;
				break;
			case OP_GT:
				ret = acc > lim;
				break;
			case OP_LE:
				ret = acc <= lim;
				break;
			case OP_LT:
				ret = acc < lim;
				break;
			default:
				ret = FALSE;
				break;
			}
		}
		break;
	case OP_GE:
		ret = acc >= lim;
		break;
	case OP_GT:
		ret = acc > lim;
		break;
	case OP_LE:
		ret = acc <= lim;
		break;
	case OP_LT:
		ret = acc < lim;
		break;
	case OP_MULT:
	case OP_AND:
		ret = !acc;
		break;
	case OP_OR:
		ret = !!acc;
		break;
	default:
		g_assert (0);
		break;
	}

	return ret;
}

static gint
rspamd_ast_do_op (struct rspamd_expression_elt *elt, gint val, gint acc)
{
	gint ret = val;

	g_assert (elt->type == ELT_OP);

	switch (elt->p.op) {
	case OP_NOT:
		ret = !val;
		break;
	case OP_PLUS:
		ret = acc + val;
		break;
	case OP_GE:
		ret = acc >= val;
		break;
	case OP_GT:
		ret = acc > val;
		break;
	case OP_LE:
		ret = acc <= val;
		break;
	case OP_LT:
		ret = acc < val;
		break;
	case OP_MULT:
	case OP_AND:
		ret = acc && val;
		break;
	case OP_OR:
		ret = acc || val;
		break;
	default:
		g_assert (0);
		break;
	}

	return ret;
}

static gint
rspamd_ast_process_node (struct rspamd_expression *expr, gint flags, GNode *node,
		gpointer data)
{
	struct rspamd_expression_elt *elt, *celt, *parelt = NULL;
	GNode *cld;
	gint acc = G_MININT, lim = G_MININT, val;
	gdouble t1, t2;
	gboolean calc_ticks = FALSE;

	elt = node->data;

	switch (elt->type) {
	case ELT_ATOM:
		if (!(elt->flags & RSPAMD_EXPR_FLAG_PROCESSED)) {

			/*
			 * Sometimes get ticks for this expression. 'Sometimes' here means
			 * that we get lowest 5 bits of the counter `evals` and 5 bits
			 * of some shifted address to provide some sort of jittering for
			 * ticks evaluation
			 */
			if ((expr->evals & 0x1F) == (GPOINTER_TO_UINT (node) >> 4 & 0x1F)) {
				calc_ticks = TRUE;
				t1 = rspamd_get_ticks ();
			}

			elt->value = expr->subr->process (data, elt->p.atom);

			if (elt->value) {
				elt->p.atom->hits ++;
			}

			if (calc_ticks) {
				t2 = rspamd_get_ticks ();
				elt->p.atom->avg_ticks += ((t2 - t1) - elt->p.atom->avg_ticks) /
						(expr->evals);
			}

			elt->flags |= RSPAMD_EXPR_FLAG_PROCESSED;
		}

		return elt->value;
		break;
	case ELT_LIMIT:

		return elt->p.lim.val;
		break;
	case ELT_OP:
		g_assert (node->children != NULL);
		cld = node->children;

		/* Try to find limit at the parent node */
		if (node->parent) {
			parelt = node->parent->data;
			celt = node->parent->children->data;

			if (celt->type == ELT_LIMIT) {
				lim = celt->p.lim.val;
			}
		}

		DL_FOREACH (node->children, cld) {
			celt = cld->data;

			/* Save limit if we've found it */
			val = rspamd_ast_process_node (expr, flags, cld, data);

			if (acc == G_MININT) {
				acc = val;
			}

			acc = rspamd_ast_do_op (elt, val, acc);

			if (!(flags & RSPAMD_EXPRESSION_FLAG_NOOPT)) {
				if (rspamd_ast_node_done (elt, parelt, acc, lim)) {
					return acc;
				}
			}
		}
		break;
	}

	return acc;
}

static gboolean
rspamd_ast_cleanup_traverse (GNode *n, gpointer d)
{
	struct rspamd_expression_elt *elt = n->data;

	elt->value = 0;
	elt->flags = 0;

	return FALSE;
}

gint
rspamd_process_expression (struct rspamd_expression *expr, gint flags,
		gpointer data)
{
	gint ret = 0;

	g_assert (expr != NULL);
	/* Ensure that stack is empty at this point */
	g_assert (expr->expression_stack->len == 0);

	ret = rspamd_ast_process_node (expr, flags, expr->ast, data);

	/* Cleanup */
	g_node_traverse (expr->ast, G_IN_ORDER, G_TRAVERSE_ALL, -1,
			rspamd_ast_cleanup_traverse, NULL);

	expr->evals ++;

	/* Check if we need to resort */
	if (expr->evals == expr->next_resort) {
		expr->next_resort = ottery_rand_range (MAX_RESORT_EVALS) +
				MIN_RESORT_EVALS;
		/* Set priorities for branches */
		g_node_traverse (expr->ast, G_POST_ORDER, G_TRAVERSE_ALL, -1,
				rspamd_ast_priority_traverse, expr);

		/* Now set less expensive branches to be evaluated first */
		g_node_traverse (expr->ast, G_POST_ORDER, G_TRAVERSE_NON_LEAVES, -1,
				rspamd_ast_resort_traverse, NULL);
	}

	return ret;
}

static gboolean
rspamd_ast_string_traverse (GNode *n, gpointer d)
{
	GString *res = d;
	gint cnt;
	GNode *cur;
	struct rspamd_expression_elt *elt = n->data;
	const char *op_str = NULL;

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

		if (n->children) {
			LL_COUNT(n->children, cur, cnt);

			if (cnt > 2) {
				/* Print n-ary of the operator */
				g_string_append_printf (res, "(%d)", cnt);
			}
		}
	}

	g_string_append_c (res, ' ');

	return FALSE;
}

GString *
rspamd_expression_tostring (struct rspamd_expression *expr)
{
	GString *res;

	g_assert (expr != NULL);

	res = g_string_new (NULL);
	g_node_traverse (expr->ast, G_POST_ORDER, G_TRAVERSE_ALL, -1,
			rspamd_ast_string_traverse, res);

	/* Last space */
	if (res->len > 0) {
		g_string_erase (res, res->len - 1, 1);
	}

	return res;
}
