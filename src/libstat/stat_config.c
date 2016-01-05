/*
 * Copyright (c) 2015, Vsevolod Stakhov
 *
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
#include "stat_api.h"
#include "rspamd.h"
#include "cfg_rcl.h"
#include "stat_internal.h"

static struct rspamd_stat_ctx *stat_ctx = NULL;

static struct rspamd_stat_classifier stat_classifiers[] = {
	{
		.name = "bayes",
		.init_func = bayes_init,
		.classify_func = bayes_classify,
		.learn_spam_func = bayes_learn_spam,
	}
};

static struct rspamd_stat_tokenizer stat_tokenizers[] = {
	{
		.name = "osb-text",
		.get_config = rspamd_tokenizer_osb_get_config,
		.compatible_config = rspamd_tokenizer_osb_compatible_config,
		.tokenize_func = rspamd_tokenizer_osb,
		.load_config = rspamd_tokenizer_osb_load_config,
		.is_compat = rspamd_tokenizer_osb_is_compat
	},
	{
		.name = "osb",
		.get_config = rspamd_tokenizer_osb_get_config,
		.compatible_config = rspamd_tokenizer_osb_compatible_config,
		.tokenize_func = rspamd_tokenizer_osb,
		.load_config = rspamd_tokenizer_osb_load_config,
		.is_compat = rspamd_tokenizer_osb_is_compat
	},
};

#define RSPAMD_STAT_BACKEND_ELT(nam, eltn) { \
		.name = #nam, \
		.init = rspamd_##eltn##_init, \
		.runtime = rspamd_##eltn##_runtime, \
		.process_token = rspamd_##eltn##_process_token, \
		.finalize_process = rspamd_##eltn##_finalize_process, \
		.learn_token = rspamd_##eltn##_learn_token, \
		.finalize_learn = rspamd_##eltn##_finalize_learn, \
		.total_learns = rspamd_##eltn##_total_learns, \
		.inc_learns = rspamd_##eltn##_inc_learns, \
		.dec_learns = rspamd_##eltn##_dec_learns, \
		.get_stat = rspamd_##eltn##_get_stat, \
		.load_tokenizer_config = rspamd_##eltn##_load_tokenizer_config, \
		.close = rspamd_##eltn##_close \
	}

static struct rspamd_stat_backend stat_backends[] = {
		RSPAMD_STAT_BACKEND_ELT(mmap, mmaped_file),
		RSPAMD_STAT_BACKEND_ELT(sqlite3, sqlite3)
};

static struct rspamd_stat_cache stat_caches[] = {
	{
		.name = RSPAMD_DEFAULT_CACHE,
		.init = rspamd_stat_cache_sqlite3_init,
		.process = rspamd_stat_cache_sqlite3_process,
		.close = rspamd_stat_cache_sqlite3_close
	}
};

void
rspamd_stat_init (struct rspamd_config *cfg)
{
	guint i;
	GList *cur, *curst;
	struct rspamd_classifier_config *clf;
	struct rspamd_statfile_config *stf;
	struct rspamd_stat_backend *bk;
	struct rspamd_statfile *st;
	struct rspamd_classifier *cl;
	const ucl_object_t *cache_obj = NULL, *cache_name_obj;
	const gchar *cache_name = NULL;

	if (stat_ctx == NULL) {
		stat_ctx = g_slice_alloc0 (sizeof (*stat_ctx));
	}

	stat_ctx->backends_subrs = stat_backends;
	stat_ctx->backends_count = G_N_ELEMENTS (stat_backends);
	stat_ctx->classifiers_subrs = stat_classifiers;
	stat_ctx->classifiers_count = G_N_ELEMENTS (stat_classifiers);
	stat_ctx->tokenizers_subrs = stat_tokenizers;
	stat_ctx->tokenizers_count = G_N_ELEMENTS (stat_tokenizers);
	stat_ctx->caches_subrs = stat_caches;
	stat_ctx->caches_count = G_N_ELEMENTS (stat_caches);
	stat_ctx->cfg = cfg;
	stat_ctx->statfiles = g_ptr_array_new ();
	stat_ctx->classifiers = g_ptr_array_new ();
	REF_RETAIN (stat_ctx->cfg);

	/* Create statfiles from the classifiers */
	cur = cfg->classifiers;

	while (cur) {
		clf = cur->data;
		bk = rspamd_stat_get_backend (clf->backend);
		g_assert (bk != NULL);

		/* XXX:
		 * Here we get the first classifier tokenizer config as the only one
		 * We NO LONGER support multiple tokenizers per rspamd instance
		 */
		if (stat_ctx->tkcf == NULL) {
			stat_ctx->tokenizer = rspamd_stat_get_tokenizer (clf->tokenizer);
			g_assert (stat_ctx->tokenizer != NULL);
			stat_ctx->tkcf = stat_ctx->tokenizer->get_config (cfg->cfg_pool,
					clf->tokenizer, NULL);
		}

		cl = g_slice_alloc0 (sizeof (*cl));
		cl->cfg = clf;
		cl->statfiles_ids = g_array_new (FALSE, FALSE, sizeof (gint));

		/* Init classifier cache */
		if (clf->opts) {
			cache_obj = ucl_object_find_key (clf->opts, "cache");

			if (cache_obj) {
				cache_name_obj = ucl_object_find_key (cache_obj, "name");
			}

			if (cache_name_obj) {
				cache_name = ucl_object_tostring (cache_name_obj);
			}
		}

		cl->cache = rspamd_stat_get_cache (cache_name);
		g_assert (cl->cache != NULL);
		cl->cachecf = cl->cache->init (stat_ctx, cfg, cache_obj);

		curst = clf->statfiles;

		while (curst) {
			stf = curst->data;
			st = g_slice_alloc0 (sizeof (*st));
			st->classifier = cl;
			st->stcf = stf;
			st->bkcf = stat_ctx->backends_subrs[i].init (stat_ctx, cfg, st);
			msg_debug_config ("added backend %s",
					stat_ctx->backends_subrs[i].name);

			if (st->bkcf == NULL) {
				msg_err_config ("cannot init backend %s for statfile %s",
						clf->backend, stf->symbol);

				g_slice_free1 (sizeof (*st), st);
			}
			else {
				st->id = stat_ctx->statfiles->len;
				g_ptr_array_add (stat_ctx->statfiles, st);
				g_array_append_val (cl->statfiles_ids, st->id);
			}

			curst = curst->next;
		}

		g_ptr_array_add (stat_ctx->classifiers, cl);

		cur = cur->next;
	}
}

void
rspamd_stat_close (void)
{
	guint i;
	struct rspamd_config *cfg = stat_ctx->cfg;

	g_assert (stat_ctx != NULL);

	for (i = 0; i < stat_ctx->backends_count; i ++) {
		if (stat_ctx->backends_subrs[i].close != NULL) {
			stat_ctx->backends_subrs[i].close (stat_ctx->backends_subrs[i].ctx);
			msg_debug_config ("closed backend %s", stat_ctx->backends_subrs[i].name);
		}
	}

	REF_RELEASE (stat_ctx->cfg);
}

struct rspamd_stat_ctx *
rspamd_stat_get_ctx (void)
{
	return stat_ctx;
}

struct rspamd_stat_classifier *
rspamd_stat_get_classifier (const gchar *name)
{
	guint i;

	for (i = 0; i < stat_ctx->classifiers_count; i ++) {
		if (strcmp (name, stat_ctx->classifiers_subrs[i].name) == 0) {
			return &stat_ctx->classifiers_subrs[i];
		}
	}

	return NULL;
}

struct rspamd_stat_backend *
rspamd_stat_get_backend (const gchar *name)
{
	guint i;

	if (name == NULL || name[0] == '\0') {
		name = RSPAMD_DEFAULT_BACKEND;
	}

	for (i = 0; i < stat_ctx->backends_count; i ++) {
		if (strcmp (name, stat_ctx->backends_subrs[i].name) == 0) {
			return &stat_ctx->backends_subrs[i];
		}
	}

	return NULL;
}

struct rspamd_stat_tokenizer *
rspamd_stat_get_tokenizer (const gchar *name)
{
	guint i;

	if (name == NULL || name[0] == '\0') {
		name = RSPAMD_DEFAULT_TOKENIZER;
	}

	for (i = 0; i < stat_ctx->tokenizers_count; i ++) {
		if (strcmp (name, stat_ctx->tokenizers_subrs[i].name) == 0) {
			return &stat_ctx->tokenizers_subrs[i];
		}
	}

	return NULL;
}

struct rspamd_stat_cache *
rspamd_stat_get_cache (const gchar *name)
{
	guint i;

	if (name == NULL || name[0] == '\0') {
		name = RSPAMD_DEFAULT_CACHE;
	}

	for (i = 0; i < stat_ctx->caches_count; i++) {
		if (strcmp (name, stat_ctx->caches_subrs[i].name) == 0) {
			return &stat_ctx->caches_subrs[i];
		}
	}

	return NULL;
}
