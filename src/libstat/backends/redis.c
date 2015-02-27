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
#include "main.h"
#include "hiredis.h"
#include "upstream.h"

#define REDIS_CTX(p) (struct redis_stat_ctx *)(p)
#define REDIS_RUNTIME(p) (struct redis_stat_runtime *)(p)
#define REDIS_BACKEND_TYPE "redis"
#define REDIS_DEFAULT_PORT 6379
#define REDIS_DEFAULT_OBJECT "%s%l"

struct redis_stat_ctx {
	struct upstream_list *read_servers;
	struct upstream_list *write_servers;

	const gchar *redis_object;
	gdouble timeout;
};

struct redis_stat_runtime {
	struct rspamd_task *task;
	struct upstream *selected;
	GArray *results;
	gchar *redis_object_expanded;
};

gpointer
rspamd_redis_init (struct rspamd_stat_ctx *ctx, struct rspamd_config *cfg)
{
	struct redis_stat_ctx *new;
	struct rspamd_classifier_config *clf;
	struct rspamd_statfile_config *stf;
	GList *cur, *curst;
	const ucl_object_t *elt;

	new = rspamd_mempool_alloc0 (cfg->cfg_pool, sizeof (*new));

	/* Iterate over all classifiers and load matching statfiles */
	cur = cfg->classifiers;

	while (cur) {
		clf = cur->data;

		curst = clf->statfiles;
		while (curst) {
			stf = curst->data;

			/*
			 * By default, all statfiles are treated as mmaped files
			 */
			if (stf->backend != NULL && strcmp (stf->backend, REDIS_BACKEND_TYPE)) {
				/*
				 * Check configuration sanity
				 */
				elt = ucl_object_find_key (stf->opts, "read_servers");
				if (elt == NULL) {
					elt = ucl_object_find_key (stf->opts, "servers");
				}
				if (elt == NULL) {
					msg_err ("statfile %s has no redis servers", stf->symbol);
					curst = curst->next;
					continue;
				}
				else {
					new->read_servers = rspamd_upstreams_create ();
					if (!rspamd_upstreams_from_ucl (new->read_servers, elt,
							REDIS_DEFAULT_PORT, NULL)) {
						msg_err ("statfile %s cannot read servers configuration",
								stf->symbol);
						curst = curst->next;
						continue;
					}
				}

				elt = ucl_object_find_key (stf->opts, "write_servers");
				if (elt == NULL) {
					msg_err ("statfile %s has no write redis servers, "
							"so learning is impossible", stf->symbol);
					curst = curst->next;
					continue;
				}
				else {
					new->write_servers = rspamd_upstreams_create ();
					if (!rspamd_upstreams_from_ucl (new->read_servers, elt,
							REDIS_DEFAULT_PORT, NULL)) {
						msg_err ("statfile %s cannot write servers configuration",
								stf->symbol);
						rspamd_upstreams_destroy (new->write_servers);
						new->write_servers = NULL;
					}
				}

				elt = ucl_object_find_key (stf->opts, "prefix");
				if (elt == NULL || ucl_object_type (elt) != UCL_STRING) {
					new->redis_object = REDIS_DEFAULT_OBJECT;
				}
				else {
					/* XXX: sanity check */
					new->redis_object = ucl_object_tostring (elt);
				}

				ctx->statfiles ++;
			}

			curst = curst->next;
		}

		cur = g_list_next (cur);
	}

	return (gpointer)new;
}

gpointer rspamd_redis_runtime (struct rspamd_statfile_config *stcf,
		gboolean learn, gpointer ctx);
gboolean rspamd_redis_process_token (struct token_node_s *tok,
		struct rspamd_token_result *res,
		gpointer ctx);
gboolean rspamd_redis_learn_token (struct token_node_s *tok,
		struct rspamd_token_result *res,
		gpointer ctx);
void rspamd_redis_finalize_learn (struct rspamd_statfile_runtime *runtime,
		gpointer ctx);
gulong rspamd_redis_total_learns (struct rspamd_statfile_runtime *runtime,
		gpointer ctx);
gulong rspamd_redis_inc_learns (struct rspamd_statfile_runtime *runtime,
		gpointer ctx);
gulong rspamd_redis_learns (struct rspamd_statfile_runtime *runtime,
		gpointer ctx);
ucl_object_t * rspamd_redis_get_stat (struct rspamd_statfile_runtime *runtime,
		gpointer ctx);
