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

#include <expression.h>
#include "config.h"

enum rspamd_expression_op {
	OP_PLUS, /* || or + */
	OP_MULT, /* && or * */
	OP_NOT, /* ! */
	OP_LT, /* < */
	OP_GT, /* > */
	OP_LE, /* <= */
	OP_GE /* >= */
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
};

struct rspamd_expression {
	struct rspamd_atom_subr *subr;
	GArray *expressions;
	GPtrArray *expression_stack;
};

static void
rspamd_expr_stack_push (struct rspamd_expression *expr,
		struct rspamd_expression_elt *elt)
{
	g_ptr_array_add (expr->expression_stack, elt);
}

static struct rspamd_expression_elt *
rspamd_expr_stack_pop (struct rspamd_expression *expr)
{
	struct rspamd_expression_elt *e;
	gint idx;

	if (expr->expression_stack->len == 0) {
		return NULL;
	}

	idx = expr->expression_stack->len - 1;
	e = g_ptr_array_index (expr->expression_stack, idx);
	g_ptr_array_remove_index_fast (expr->expression_stack, idx);

	return e;
}

gboolean
rspamd_parse_expression (const gchar *line, gsize len,
		struct rspamd_atom_subr *subr, gpointer subr_data,
		rspamd_mempool_t *pool, GError **err,
		struct rspamd_expression **target)
{
	g_assert (line != NULL);
	g_assert (subr != NULL && subr->parse != NULL);

	if (len == 0) {
		len = strlen (line);
	}

	return FALSE;
}

gint
rspamd_process_expression (struct rspamd_expression *expr, gpointer data)
{
	g_assert (expr != NULL);

	return 0;
}
