/*
 * Copyright (c) 2009, Rambler media
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
 * THIS SOFTWARE IS PROVIDED BY Rambler media ''AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL Rambler BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Winnow classifier
 */

#include "classifiers.h"

#define WINNOW_PROMOTION 1.23
#define WINNOW_DEMOTION 0.83

struct winnow_callback_data {
	statfile_pool_t *pool;
	struct classifier_ctx *ctx;
	char *filename;
	double sum;
	int count;
	int in_class;
	time_t now;
};

static gboolean
classify_callback (gpointer key, gpointer value, gpointer data) 
{
	token_node_t *node = key;
	struct winnow_callback_data *cd = data;
	float v;
	
	/* Consider that not found blocks have value 1 */
	if ((v = statfile_pool_get_block (cd->pool, cd->filename, node->h1, node->h2, cd->now)) < 0.00001) {
		cd->sum += 1;
	}
	else {
		cd->sum += v;
		cd->in_class ++;
	}

	cd->count ++;

	return FALSE;
}

static gboolean
learn_callback (gpointer key, gpointer value, gpointer data) 
{
	token_node_t *node = key;
	struct winnow_callback_data *cd = data;
	float v, c;

	c = (cd->in_class) ? WINNOW_PROMOTION : WINNOW_DEMOTION;

	/* Consider that not found blocks have value 1 */
	if ((v = statfile_pool_get_block (cd->pool, cd->filename, node->h1, node->h2, cd->now)) < 0.00001) {
		statfile_pool_set_block (cd->pool, cd->filename, node->h1, node->h2, cd->now, c);
	}
	else {
		statfile_pool_set_block (cd->pool, cd->filename, node->h1, node->h2, cd->now, v * c);
	}

	cd->count ++;
	
	return FALSE;
}

struct classifier_ctx* 
winnow_init (memory_pool_t *pool)
{
	struct classifier_ctx *ctx = memory_pool_alloc (pool, sizeof (struct classifier_ctx));

	ctx->pool = pool;
	ctx->results = g_hash_table_new (g_str_hash, g_str_equal);
	memory_pool_add_destructor (pool, (pool_destruct_func)g_hash_table_destroy, ctx->results);

	return ctx;
}
void 
winnow_classify (struct classifier_ctx *ctx, statfile_pool_t *pool, char *statfile, GTree *input, double scale)
{
	struct winnow_callback_data data;
	double *res = memory_pool_alloc (ctx->pool, sizeof (double));

	g_assert (pool != NULL);
	g_assert (ctx != NULL);

	data.pool = pool;
	data.filename = statfile;
	data.sum = 0;
	data.count = 0;
	data.now = time (NULL);
	data.ctx = ctx;

	if (!statfile_pool_is_open (pool, statfile)) {
		if (statfile_pool_open (pool, statfile) == -1) {
			return;
		}
	}

	g_tree_foreach (input, classify_callback, &data);
	
	if (data.count != 0) {
    	*res = scale * (data.sum / data.count);
	}
	else {
		*res = 0;
	}

	g_hash_table_insert (ctx->results, statfile, res);
}

void
winnow_learn (struct classifier_ctx *ctx, statfile_pool_t *pool, char *statfile, GTree *input, int in_class)
{
	struct winnow_callback_data data;
	
	g_assert (pool != NULL);
	g_assert (ctx != NULL);

	data.pool = pool;
	data.filename = statfile;
	data.sum = 0;
	data.count = 0;
	data.in_class = in_class;
	data.now = time (NULL);
	data.ctx = ctx;

	if (!statfile_pool_is_open (pool, statfile)) {
		if (statfile_pool_open (pool, statfile) == -1) {
			return;
		}
	}

	statfile_pool_lock_file (pool, statfile);
	g_tree_foreach (input, learn_callback, &data);
	statfile_pool_unlock_file (pool, statfile);
}

struct winnow_result_data {
	char *filename;
	double max_score;
	double sum;
};

static void 
result_file_callback (gpointer key, gpointer value, gpointer data)
{
	struct winnow_result_data *d = (struct winnow_result_data *)data;
	double w = *((double *)value);

	if (fabs (w) > fabs (d->max_score)) {
		d->filename = (char *)key;
		d->max_score = w;
	}
	d->sum += fabs (w);
}

char* 
winnow_result_file (struct classifier_ctx* ctx, double *probability)
{
	struct winnow_result_data data = { NULL, 0, 0 };
	g_assert (ctx != NULL);
	
	g_hash_table_foreach (ctx->results, result_file_callback, &data);
	if (data.sum != 0) {
		*probability = data.max_score / data.sum;
	}
	else {
		*probability = 1;
	}

	return data.filename;
}
