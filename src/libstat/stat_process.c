/* Copyright (c) 2015, Vsevolod Stakhov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *       * Redistributions of source code must retain the above copyright
 *         notice, this list of conditions and the following disclaimer.
 *       * Redistributions in binary form must reproduce the above copyright
 *         notice, this list of conditions and the following disclaimer in the
 *         documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED ''AS IS'' AND ANY
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
#include "stat_api.h"
#include "main.h"
#include "stat_internal.h"
#include "lua/lua_common.h"
#include <utlist.h>

static gboolean
rspamd_stat_preprocess (struct rspamd_stat_ctx *st_ctx, struct rspamd_stat_classifier *cls,
		struct rspamd_task *task, GError **err)
{

}

struct rspamd_tokenizer_runtime {
	GTree *tokens;
	const gchar *name;
	struct rspamd_stat_tokenizer *tokenizer;
	struct rspamd_tokenizer_runtime *next;
};

static struct rspamd_tokenizer_runtime *
rspamd_stat_get_tokenizer_runtime (const gchar *name, rspamd_mempool_t *pool,
		struct rspamd_tokenizer_runtime **ls)
{
	struct rspamd_tokenizer_runtime *tok = NULL, *cur;

	LL_FOREACH (*ls, cur) {
		if (strcmp (cur->name, name) == 0) {
			tok = cur;
			break;
		}
	}

	if (tok == NULL) {
		tok = rspamd_mempool_alloc (pool, sizeof (*tok));
		tok->tokenizer = rspamd_stat_get_tokenizer (name);

		if (tok->tokenizer == NULL) {
			return NULL;
		}

		tok->tokens = g_tree_new (token_node_compare_func);
		rspamd_mempool_add_destructor (pool,
				(rspamd_mempool_destruct_t)g_tree_destroy, tok->tokens);
		tok->name = name;
		LL_PREPEND(*ls, tok);
	}

	return tok;
}


gboolean
rspamd_stat_classify (struct rspamd_task *task, lua_State *L, GError **err)
{
	struct rspamd_stat_classifier *cls;
	struct rspamd_classifier_config *clcf;
	GList *cur;
	guint i;
	struct rspamd_stat_ctx *st_ctx;
	struct rspamd_tokenizer_runtime *tklist = NULL, *tok;


	st_ctx = rspamd_stat_get_ctx ();
	g_assert (st_ctx != NULL);

	cur = g_list_first (task->cfg->classifiers);

	while (cur) {
		clcf = (struct rspamd_classifier_config *)cur->data;
		cls = rspamd_stat_get_classifier (clcf->classifier);

		if (cls == NULL) {
			g_set_error (err, rspamd_stat_quark (), 500, "type %s is not defined"
					"for classifiers", clcf->classifier);
			return FALSE;
		}

		tok = rspamd_stat_get_tokenizer_runtime (clcf->tokenizer, task->task_pool,
				&tklist);

		if (tok == NULL) {
			g_set_error (err, rspamd_stat_quark (), 500, "type %s is not defined"
					"for tokenizers", clcf->tokenizer);
			return FALSE;
		}


		if (!rspamd_stat_preprocess (st_ctx, task, cls, err)) {
			return FALSE;
		}

		cur = g_list_next (cur);
	}

	return TRUE;
}
