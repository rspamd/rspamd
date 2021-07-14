/*-
 * Copyright 2016 Vsevolod Stakhov
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef SRC_LIBUTIL_EXPRESSION_H_
#define SRC_LIBUTIL_EXPRESSION_H_

#include "config.h"
#include "mem_pool.h"
#include "fstring.h"
#include "util.h"

#ifdef  __cplusplus
extern "C" {
#endif

#define RSPAMD_EXPRESSION_MAX_PRIORITY 1024

#define RSPAMD_EXPRESSION_FLAG_NOOPT (1 << 0)

enum rspamd_expression_op {
	OP_INVALID = 0,
	OP_PLUS, /* + */
	OP_MULT, /* * */
	OP_MINUS, /* - */
	OP_DIVIDE, /* / */
	OP_OR, /* || or | */
	OP_AND, /* && or & */
	OP_NOT, /* ! */
	OP_LT, /* < */
	OP_GT, /* > */
	OP_LE, /* <= */
	OP_GE, /* >= */
	OP_EQ, /* == */
	OP_NE, /* != */
	OP_OBRACE, /* ( */
	OP_CBRACE /* ) */
};

typedef struct rspamd_expression_atom_s {
	/* Parent node */
	GNode *parent;
	/* Opaque userdata */
	gpointer data;
	/* String representation of atom */
	const gchar *str;
	/* Length of the string representation of atom */
	guint len;
	/* Relative priority */
	gint priority;
	guint hits;
	struct rspamd_counter_data exec_time;
} rspamd_expression_atom_t;

typedef gdouble (*rspamd_expression_process_cb) (gpointer runtime_data,
												 rspamd_expression_atom_t *atom);

struct rspamd_atom_subr {
	/* Parses atom from string and returns atom structure */
	rspamd_expression_atom_t *(*parse) (const gchar *line, gsize len,
										rspamd_mempool_t *pool, gpointer ud, GError **err);

	/* Process atom via the opaque pointer (e.g. struct rspamd_task *) */
	rspamd_expression_process_cb process;

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
								  const struct rspamd_atom_subr *subr, gpointer subr_data,
								  rspamd_mempool_t *pool, GError **err,
								  struct rspamd_expression **target);

/**
 * Process the expression and return its value using atom 'process' functions with the specified data pointer
 * @param expr expression to process
 * @param data opaque data pointer for all the atoms
 * @return the value of expression
 */
gdouble rspamd_process_expression (struct rspamd_expression *expr,
								   gint flags,
								   gpointer runtime_ud);

/**
 * Process the expression and return its value using atom 'process' functions with the specified data pointer.
 * This function also accepts `track` argument where it writes matched atoms (those whose value is more than 0)
 * @param expr expression to process
 * @param data opaque data pointer for all the atoms
 * @param track pointer array to atoms tracking
 * @return the value of expression
 */
gdouble rspamd_process_expression_track (struct rspamd_expression *expr,
										 gint flags,
										 gpointer runtime_ud,
										 GPtrArray **track);

/**
 * Process the expression with the custom processor
 * @param expr
 * @param cb
 * @param process_data
 * @return
 */
gdouble rspamd_process_expression_closure (struct rspamd_expression *expr,
										   rspamd_expression_process_cb cb,
										   gint flags,
										   gpointer runtime_ud,
										   GPtrArray **track);

/**
 * Shows string representation of an expression
 * @param expr expression to show
 * @return freshly allocated string with expression
 */
GString *rspamd_expression_tostring (struct rspamd_expression *expr);

/**
 * Callback that is called on @see rspamd_expression_atom_foreach, atom is ephemeral
 * and should not be modified within callback
 */
typedef void (*rspamd_expression_atom_foreach_cb) (const rspamd_ftok_t *atom,
												   gpointer ud);

/**
 * Traverse over all atoms in the expression
 * @param expr expression
 * @param cb callback to be called
 * @param ud opaque data passed to `cb`
 */
void rspamd_expression_atom_foreach (struct rspamd_expression *expr,
									 rspamd_expression_atom_foreach_cb cb, gpointer cbdata);

/**
 * Checks if a specified node in AST is the specified operation
 * @param node AST node packed in GNode container
 * @param op operation to check
 * @return TRUE if node is operation node and is exactly the specified option
 */
gboolean rspamd_expression_node_is_op (GNode *node, enum rspamd_expression_op op);

#ifdef  __cplusplus
}
#endif

#endif /* SRC_LIBUTIL_EXPRESSION_H_ */
