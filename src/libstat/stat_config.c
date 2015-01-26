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
#include "main.h"
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
	{"osb-text", osb_tokenize_text},
};

struct rspamd_stat_backend stat_backends[] = {
	{
		.name = RSPAMD_DEFAULT_BACKEND,
		.init = rspamd_mmaped_file_init,
		.runtime = rspamd_mmaped_file_runtime,
		.process_token = rspamd_mmaped_file_process_token,
		.total_learns = rspamd_mmaped_file_total_learns
	}
};


void
rspamd_stat_init (struct rspamd_config *cfg)
{
	guint i;

	if (stat_ctx == NULL) {
		stat_ctx = g_slice_alloc0 (sizeof (*stat_ctx));
	}

	stat_ctx->backends = stat_backends;
	stat_ctx->backends_count = G_N_ELEMENTS (stat_backends);
	stat_ctx->classifiers = stat_classifiers;
	stat_ctx->classifiers_count = G_N_ELEMENTS (stat_classifiers);
	stat_ctx->tokenizers = stat_tokenizers;
	stat_ctx->tokenizers_count = G_N_ELEMENTS (stat_tokenizers);

	/* Init backends */
	for (i = 0; i < stat_ctx->backends_count; i ++) {
		stat_ctx->backends[i].ctx = stat_ctx->backends[i].init (stat_ctx, cfg);
	}
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
		if (strcmp (name, stat_ctx->classifiers[i].name) == 0) {
			return &stat_ctx->classifiers[i];
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
		if (strcmp (name, stat_ctx->backends[i].name) == 0) {
			return &stat_ctx->backends[i];
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
		if (strcmp (name, stat_ctx->tokenizers[i].name) == 0) {
			return &stat_ctx->tokenizers[i];
		}
	}

	return NULL;
}
