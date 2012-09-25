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
#include "map.h"
#include "filter.h"
#include "dynamic_cfg.h"
#include "json/jansson.h"

struct dynamic_cfg_symbol {
	gchar						   *name;
	gdouble						    value;
};

struct dynamic_cfg_action {
	enum rspamd_metric_action	    action;
	gdouble						    value;
};

struct dynamic_cfg_metric {
	GList 						   *symbols;
	GList						   *actions;
	gchar						   *name;
};

struct config_json_buf {
	gchar                          *buf;
	gchar                          *pos;
	size_t                          buflen;
	struct config_file             *cfg;
	GList						   *config_metrics;
};

/**
 * Free dynamic configuration
 * @param conf_metrics
 */
static void
dynamic_cfg_free (GList *conf_metrics)
{
	GList								*cur, *cur_elt;
	struct dynamic_cfg_metric			*metric;
	struct dynamic_cfg_symbol			*sym;
	struct dynamic_cfg_action			*act;

	if (conf_metrics) {
		cur = conf_metrics;
		while (cur) {
			metric = cur->data;
			if (metric->symbols) {
				cur_elt = metric->symbols;
				while (cur_elt) {
					sym = cur_elt->data;
					g_free (sym->name);
					g_slice_free1 (sizeof (struct dynamic_cfg_symbol), sym);
					cur_elt = g_list_next (cur_elt);
				}
				g_list_free (metric->symbols);
			}

			if (metric->actions) {
				cur_elt = metric->actions;
				while (cur_elt) {
					act = cur_elt->data;
					g_slice_free1 (sizeof (struct dynamic_cfg_symbol), act);
					cur_elt = g_list_next (cur_elt);
				}
				g_list_free (metric->actions);
			}
			g_slice_free1 (sizeof (struct dynamic_cfg_metric), metric);
			cur = g_list_next (cur);
		}
		g_list_free (conf_metrics);
	}
}
/**
 * Apply configuration to the specified configuration
 * @param conf_metrics
 * @param cfg
 */
static void
apply_dynamic_conf (GList *conf_metrics, struct config_file *cfg)
{
	GList								*cur, *cur_elt, *tmp;
	struct dynamic_cfg_metric			*metric;
	struct dynamic_cfg_symbol			*sym;
	struct dynamic_cfg_action			*act;
	struct metric						*real_metric;
	struct metric_action				*real_act;
	gdouble								*w;

	cur = conf_metrics;
	while (cur) {
		metric = cur->data;
		if ((real_metric = g_hash_table_lookup (cfg->metrics, metric->name)) != NULL) {
			cur_elt = metric->symbols;
			while (cur_elt) {
				sym = cur_elt->data;
				if ((w = g_hash_table_lookup (real_metric->symbols, sym->name)) != NULL) {
					*w = sym->value;
				}
				else {
					msg_info ("symbol %s is not found in the main configuration", sym->name);
				}
				cur_elt = g_list_next (cur_elt);
			}

			cur_elt = metric->actions;
			while (cur_elt) {
				act = cur_elt->data;
				tmp = real_metric->actions;
				while (tmp) {
					real_act = tmp->data;
					if (real_act->action == act->action) {
						real_act->score = act->value;
					}
					tmp = g_list_next (tmp);
				}
				cur_elt = g_list_next (cur_elt);
			}
		}
		cur = g_list_next (cur);
	}
}

/* Callbacks for reading json dynamic rules */
gchar                         *
json_config_read_cb (memory_pool_t * pool, gchar * chunk, gint len, struct map_cb_data *data)
{
	struct config_json_buf				*jb;
	gint								 free, off;

	if (data->cur_data == NULL) {
		jb = g_malloc (sizeof (struct config_json_buf));
		jb->cfg = ((struct config_json_buf *)data->prev_data)->cfg;
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
	guint								 nelts, i, j, selts;
	gint								 test_act;
	json_t								*js, *cur_elt, *cur_nm, *it_val;
	json_error_t						 je;
	struct dynamic_cfg_metric			*cur_metric;
	struct dynamic_cfg_symbol			*cur_symbol;
	struct dynamic_cfg_action			*cur_action;

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

	dynamic_cfg_free (jb->config_metrics);
	jb->config_metrics = NULL;

	/* Parse configuration */
	nelts = json_array_size (js);
	for (i = 0; i < nelts; i++) {
		cur_elt = json_array_get (js, i);
		if (!cur_elt || !json_is_object (cur_elt)) {
			msg_err ("loaded json array element is not an object");
			continue;
		}

		cur_nm = json_object_get (cur_elt, "name");
		if (!cur_nm || !json_is_string (cur_nm)) {
			msg_err ("loaded json array element has no 'name' attribute");
			continue;
		}
		cur_metric = g_slice_alloc0 (sizeof (struct dynamic_cfg_metric));
		cur_metric->name = g_strdup (json_string_value (cur_nm));
		cur_nm = json_object_get (cur_elt, "symbols");
		/* Parse symbols */
		if (cur_nm && json_is_array (cur_nm)) {
			selts = json_array_size (cur_nm);
			for (j = 0; j < selts; j ++) {
				it_val = json_array_get (cur_nm, j);
				if (it_val && json_is_object (it_val)) {
					if (json_object_get (it_val, "name") && json_object_get (it_val, "value")) {
						cur_symbol = g_slice_alloc0 (sizeof (struct dynamic_cfg_symbol));
						cur_symbol->name = g_strdup (json_string_value (json_object_get (it_val, "name")));
						cur_symbol->value = json_number_value (json_object_get (it_val, "value"));
						/* Insert symbol */
						cur_metric->symbols = g_list_prepend (cur_metric->symbols, cur_symbol);
					}
				}
			}
		}
		cur_nm = json_object_get (cur_elt, "actions");
		/* Parse actions */
		if (cur_nm && json_is_array (cur_nm)) {
			selts = json_array_size (cur_nm);
			for (j = 0; j < selts; j ++) {
				it_val = json_array_get (cur_nm, j);
				if (it_val && json_is_object (it_val)) {
					if (json_object_get (it_val, "name") && json_object_get (it_val, "value")) {

						cur_action = g_slice_alloc0 (sizeof (struct dynamic_cfg_action));
						if (!check_action_str (json_string_value (json_object_get (it_val, "name")), &test_act)) {
							msg_err ("unknown action: %s", json_string_value (json_object_get (it_val, "name")));
							g_slice_free1 (sizeof (struct dynamic_cfg_action), cur_action);
							continue;
						}
						cur_action->action = test_act;
						cur_action->value = json_number_value (json_object_get (it_val, "value"));
						/* Insert action */
						cur_metric->actions = g_list_prepend (cur_metric->actions, cur_action);
					}
				}
			}
		}
		jb->config_metrics = g_list_prepend (jb->config_metrics, cur_metric);
	}
	/*
	 * Note about thread safety: we are updating values that are gdoubles so it is not atomic in general case
	 * but on the other hand all that data is used only in the main thread, so why it is *likely* safe
	 * to do this task in this way without explicit lock.
	 */
	apply_dynamic_conf (jb->config_metrics, jb->cfg);

	json_decref (js);
}

/**
 * Init dynamic configuration using map logic and specific configuration
 * @param cfg config file
 */
void
init_dynamic_config (struct config_file *cfg)
{
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
	jb = g_malloc (sizeof (struct config_json_buf));
	pjb = g_malloc (sizeof (struct config_json_buf *));
	jb->buf = NULL;
	jb->cfg = cfg;
	*pjb = jb;
	if (!add_map (cfg, cfg->dynamic_conf, json_config_read_cb, json_config_fin_cb, (void **)pjb)) {
		msg_err ("cannot add map for configuration %s", cfg->dynamic_conf);
	}
}

