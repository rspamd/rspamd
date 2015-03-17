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

#ifndef SRC_LIBUTIL_EXPRESSION_H_
#define SRC_LIBUTIL_EXPRESSION_H_

#include "config.h"
#include "mem_pool.h"

typedef struct rspamd_expression_atom_s {
	/* Opaque userdata */
	gpointer data;
	/* String representation of atom */
	const gchar *str;
	/* Length of the string representation of atom */
	gsize len;
	/* Relative priority */
	gint priority;
} rspamd_expression_atom_t;

struct rspamd_atom_subr {
	/* Parses atom from string and returns atom structure */
	rspamd_expression_atom_t * (*parse)(const gchar *line, gsize len,
			rspamd_mempool_t *pool, gpointer ud, GError **err);
	/* Process atom via the opaque pointer (e.g. struct rspamd_task *) */
	gint (*process) (gpointer input, rspamd_expression_atom_t *atom);
	/* Calculates the relative priority of the expression */
	gint (*priority) (rspamd_expression_atom_t *atom);
	void (*destroy) (rspamd_expression_atom_t *atom);
};

/* Opaque structure */
struct rspamd_expression;

/**
 * Parse symbolic expression and create the expression using the specified subroutines for atoms processing
 * @param line line to parse
 * @param len length of the line (if 0 then line should be NULL terminated)
 * @param subr subroutines for atoms parsing
 * @param subr_data opaque dat pointer
 * @param pool pool to use for memory allocations
 * @param err error pointer
 * @param target the target expression
 * @return TRUE if an expression have been parsed
 */
gboolean rspamd_parse_expression (const gchar *line, gsize len,
		struct rspamd_atom_subr *subr, gpointer subr_data,
		rspamd_mempool_t *pool, GError **err,
		struct rspamd_expression **target);

/**
 * Process the expression and return its value using atom 'process' functions with the specified data pointer
 * @param expr expression to process
 * @param data opaque data pointer for all the atoms
 * @return the value of expression
 */
gint rspamd_process_expression (struct rspamd_expression *expr, gpointer data);

#endif /* SRC_LIBUTIL_EXPRESSION_H_ */
