/* Copyright (c) 2010-2012, Vsevolod Stakhov
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
#include "dynamic_cfg.h"

struct dynamic_cfg {

};

struct config_json_buf {
	gchar                          *buf;
	gchar                          *pos;
	size_t                          buflen;
	struct config_file             *cfg;
};

/* Callbacks for reading json dynamic rules */
gchar                         *
json_config_read_cb (memory_pool_t * pool, gchar * chunk, gint len, struct map_cb_data *data)
{
	struct regexp_json_buf				*jb;
	gint								 free, off;

	if (data->cur_data == NULL) {
		jb = g_malloc (sizeof (struct regexp_json_buf));
		jb->cfg = ((struct regexp_json_buf *)data->prev_data)->cfg;
		jb->buf = NULL;
		jb->pos = NULL;
		data->cur_data = jb;
	}
	else {
		jb = data->cur_data;
	}

	if (jb->buf == NULL) {
		/* Allocate memory for buffer */
		jb->buflen = len * 2;
		jb->buf = g_malloc (jb->buflen);
		jb->pos = jb->buf;
	}

	off = jb->pos - jb->buf;
	free = jb->buflen - off;

	if (free < len) {
		jb->buflen = MAX (jb->buflen * 2, jb->buflen + len * 2);
		jb->buf = g_realloc (jb->buf, jb->buflen);
		jb->pos = jb->buf + off;
	}

	memcpy (jb->pos, chunk, len);
	jb->pos += len;

	/* Say not to copy any part of this buffer */
	return NULL;
}

void
json_config_fin_cb (memory_pool_t * pool, struct map_cb_data *data)
{
	struct config_json_buf				*jb;
	guint								 nelts, i, j;
	json_t								*js, *cur_elt, *cur_nm, *it_val;
	json_error_t						 je;

	if (data->prev_data) {
		jb = data->prev_data;
		/* Clean prev data */
		if (jb->buf) {
			g_free (jb->buf);
		}
		g_free (jb);
	}

	/* Now parse json */
	if (data->cur_data) {
		jb = data->cur_data;
	}
	else {
		msg_err ("no data read");
		return;
	}
	if (jb->buf == NULL) {
		msg_err ("no data read");
		return;
	}
	/* NULL terminate current buf */
	*jb->pos = '\0';

	js = json_loads (jb->buf, &je);
	if (!js) {
		msg_err ("cannot load json data: parse error %s, on line %d", je.text, je.line);
		return;
	}

	if (!json_is_array (js)) {
		json_decref (js);
		msg_err ("loaded json is not an array");
		return;
	}
}

/**
 * Init dynamic configuration using map logic and specific configuration
 * @param cfg config file
 */
void
init_dynamic_config (struct config_file *cfg)
{
	gint								 fd;
	struct stat							 st;
	struct config_json_buf				*jb, **pjb;

	if (cfg->dynamic_conf == NULL) {
		/* No dynamic conf has been specified, so do not try to load it */
		return;
	}

	if (stat (cfg->dynamic_conf, &st) == -1) {
		msg_warn ("%s is unavailable: %s", cfg->dynamic_conf, strerror (errno));
		return;
	}
	if (access (cfg->dynamic_conf, W_OK | R_OK) == -1) {
		msg_warn ("%s is inaccessible: %s", cfg->dynamic_conf, strerror (errno));
		return;
	}

	/* Now try to add map with json data */
	jb = g_malloc (sizeof (struct regexp_json_buf));
	pjb = g_malloc (sizeof (struct regexp_json_buf *));
	jb->buf = NULL;
	jb->cfg = cfg;
	*pjb = jb;
	if (!add_map (cfg->dynamic_conf, json_config_read_cb, json_config_fin_cb, (void **)pjb)) {
		msg_err ("cannot add map for configuration %s", cfg->dynamic_conf);
	}
}

