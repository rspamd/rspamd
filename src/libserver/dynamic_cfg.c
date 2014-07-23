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
#include "dynamic_cfg.h"
#include "filter.h"
#include "json/jansson.h"
#include "main.h"
#include "map.h"

struct dynamic_cfg_symbol {
	gchar *name;
	gdouble value;
};

struct dynamic_cfg_action {
	enum rspamd_metric_action action;
	gdouble value;
};

struct dynamic_cfg_metric {
	GList *symbols;
	struct dynamic_cfg_action actions[METRIC_ACTION_MAX];
	gchar *name;
};

struct config_json_buf {
	gchar *buf;
	gchar *pos;
	size_t buflen;
	struct rspamd_config *cfg;
	GList *config_metrics;
};

/**
 * Free dynamic configuration
 * @param conf_metrics
 */
static void
dynamic_cfg_free (GList *conf_metrics)
{
	GList *cur, *cur_elt;
	struct dynamic_cfg_metric *metric;
	struct dynamic_cfg_symbol *sym;

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
apply_dynamic_conf (GList *conf_metrics, struct rspamd_config *cfg)
{
	GList *cur, *cur_elt;
	struct dynamic_cfg_metric *metric;
	struct dynamic_cfg_symbol *sym;
	struct dynamic_cfg_action *act;
	struct metric *real_metric;
	struct metric_action *real_act;
	gdouble *w;
	gint i, j;

	cur = conf_metrics;
	while (cur) {
		metric = cur->data;
		if ((real_metric =
			g_hash_table_lookup (cfg->metrics, metric->name)) != NULL) {
			cur_elt = metric->symbols;
			while (cur_elt) {
				sym = cur_elt->data;
				if ((w =
					g_hash_table_lookup (real_metric->symbols,
					sym->name)) != NULL) {
					*w = sym->value;
				}
				else {
					msg_info (
						"symbol %s is not found in the main configuration",
						sym->name);
				}
				cur_elt = g_list_next (cur_elt);
			}

			for (i = METRIC_ACTION_REJECT; i < METRIC_ACTION_MAX; i++) {
				act = &metric->actions[i];
				if (act->value < 0) {
					continue;
				}
				for (j = METRIC_ACTION_REJECT; j < METRIC_ACTION_MAX; j++) {
					real_act = &real_metric->actions[j];
					if (real_act->action == act->action) {
						real_act->score = act->value;
					}
					/* Update required score accordingly to metric's action */
					if (act->action == METRIC_ACTION_REJECT) {
						real_metric->actions[METRIC_ACTION_REJECT].score =
							act->value;
					}
				}
			}
		}
		cur = g_list_next (cur);
	}
}

/* Callbacks for reading json dynamic rules */
gchar *
json_config_read_cb (rspamd_mempool_t * pool,
	gchar * chunk,
	gint len,
	struct map_cb_data *data)
{
	struct config_json_buf *jb;
	gint free, off;

	if (data->cur_data == NULL) {
		jb = g_malloc (sizeof (struct config_json_buf));
		jb->cfg = ((struct config_json_buf *)data->prev_data)->cfg;
		jb->buf = NULL;
		jb->pos = NULL;
		jb->config_metrics = NULL;
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
json_config_fin_cb (rspamd_mempool_t * pool, struct map_cb_data *data)
{
	struct config_json_buf *jb;
	guint nelts, i, j, selts;
	gint test_act;
	json_t *js, *cur_elt, *cur_nm, *it_val;
	json_error_t je;
	struct dynamic_cfg_metric *cur_metric;
	struct dynamic_cfg_symbol *cur_symbol;
	struct dynamic_cfg_action *cur_action;

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
		msg_err ("cannot load json data: parse error %s, on line %d",
			je.text,
			je.line);
		return;
	}

	if (!json_is_array (js)) {
		json_decref (js);
		msg_err ("loaded json is not an array");
		return;
	}

	jb->cfg->current_dynamic_conf = NULL;
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

		cur_nm = json_object_get (cur_elt, "metric");
		if (!cur_nm || !json_is_string (cur_nm)) {
			msg_err (
				"loaded json metric object element has no 'metric' attribute");
			continue;
		}
		cur_metric = g_slice_alloc0 (sizeof (struct dynamic_cfg_metric));
		for (i = METRIC_ACTION_REJECT; i < METRIC_ACTION_MAX; i++) {
			cur_metric->actions[i].value = -1.0;
		}
		cur_metric->name = g_strdup (json_string_value (cur_nm));
		cur_nm = json_object_get (cur_elt, "symbols");
		/* Parse symbols */
		if (cur_nm && json_is_array (cur_nm)) {
			selts = json_array_size (cur_nm);
			for (j = 0; j < selts; j++) {
				it_val = json_array_get (cur_nm, j);
				if (it_val && json_is_object (it_val)) {
					if (json_object_get (it_val,
						"name") && json_object_get (it_val, "value")) {
						cur_symbol =
							g_slice_alloc0 (sizeof (struct dynamic_cfg_symbol));
						cur_symbol->name =
							g_strdup (json_string_value (json_object_get (it_val,
								"name")));
						cur_symbol->value =
							json_number_value (json_object_get (it_val,
								"value"));
						/* Insert symbol */
						cur_metric->symbols = g_list_prepend (
							cur_metric->symbols,
							cur_symbol);
					}
					else {
						msg_info (
							"json symbol object has no mandatory 'name' and 'value' attributes");
					}
				}
			}
		}
		cur_nm = json_object_get (cur_elt, "actions");
		/* Parse actions */
		if (cur_nm && json_is_array (cur_nm)) {
			selts = json_array_size (cur_nm);
			for (j = 0; j < selts; j++) {
				it_val = json_array_get (cur_nm, j);
				if (it_val && json_is_object (it_val)) {
					if (json_object_get (it_val,
						"name") && json_object_get (it_val, "value")) {
						if (!check_action_str (json_string_value (
								json_object_get (it_val, "name")), &test_act)) {
							msg_err ("unknown action: %s",
								json_string_value (json_object_get (it_val,
								"name")));
							g_slice_free1 (sizeof (struct dynamic_cfg_action),
								cur_action);
							continue;
						}
						cur_action = &cur_metric->actions[test_act];
						cur_action->action = test_act;
						cur_action->value =
							json_number_value (json_object_get (it_val,
								"value"));
					}
					else {
						msg_info (
							"json symbol object has no mandatory 'name' and 'value' attributes");
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

	jb->cfg->current_dynamic_conf = jb->config_metrics;

	json_decref (js);
}

/**
 * Init dynamic configuration using map logic and specific configuration
 * @param cfg config file
 */
void
init_dynamic_config (struct rspamd_config *cfg)
{
	struct config_json_buf *jb, **pjb;

	if (cfg->dynamic_conf == NULL) {
		/* No dynamic conf has been specified, so do not try to load it */
		return;
	}

	/* Now try to add map with json data */
	jb = g_malloc0 (sizeof (struct config_json_buf));
	pjb = g_malloc (sizeof (struct config_json_buf *));
	jb->buf = NULL;
	jb->cfg = cfg;
	*pjb = jb;
	if (!add_map (cfg, cfg->dynamic_conf, "Dynamic configuration map",
		json_config_read_cb, json_config_fin_cb, (void **)pjb)) {
		msg_err ("cannot add map for configuration %s", cfg->dynamic_conf);
	}
}

static gboolean
dump_dynamic_list (gint fd, GList *rules)
{
	GList *cur, *cur_elt;
	struct dynamic_cfg_metric *metric;
	struct dynamic_cfg_symbol *sym;
	struct dynamic_cfg_action *act;
	FILE *f;
	gint i;
	gboolean start = TRUE;

	/* Open buffered stream for the descriptor */
	if ((f = fdopen (fd, "a+")) == NULL) {
		msg_err ("fdopen failed: %s", strerror (errno));
		return FALSE;
	}


	if (rules) {
		fprintf (f, "[\n");
		cur = rules;
		while (cur) {
			metric = cur->data;
			fprintf (f, "{\n  \"metric\": \"%s\",\n", metric->name);
			if (metric->symbols) {
				fprintf (f, "  \"symbols\": [\n");
				cur_elt = metric->symbols;
				while (cur_elt) {
					sym = cur_elt->data;
					cur_elt = g_list_next (cur_elt);
					if (cur_elt) {
						fprintf (f,
							"    {\"name\": \"%s\",\"value\": %.2f},\n",
							sym->name,
							sym->value);
					}
					else {
						fprintf (f,
							"    {\"name\": \"%s\",\"value\": %.2f}\n",
							sym->name,
							sym->value);
					}
				}
				if (metric->actions) {
					fprintf (f, "  ],\n");
				}
				else {
					fprintf (f, "  ]\n");
				}
			}

			if (metric->actions) {
				fprintf (f, "  \"actions\": [\n");
				for (i = METRIC_ACTION_REJECT; i < METRIC_ACTION_MAX; i++) {
					act = &metric->actions[i];
					if (act->value < 0) {
						continue;
					}
					fprintf (f, "    %s{\"name\": \"%s\",\"value\": %.2f}\n",
						(start ? "" : ","), str_action_metric (
							act->action), act->value);
					if (start) {
						start = FALSE;
					}
				}
				fprintf (f, "  ]\n");
			}
			cur = g_list_next (cur);
			if (cur) {
				fprintf (f, "},\n");
			}
			else {
				fprintf (f, "}\n]\n");
			}
		}
	}
	fclose (f);

	return TRUE;
}

/**
 * Dump dynamic configuration to the disk
 * @param cfg
 * @return
 */
gboolean
dump_dynamic_config (struct rspamd_config *cfg)
{
	struct stat st;
	gchar *dir, pathbuf[PATH_MAX];
	gint fd;

	if (cfg->dynamic_conf == NULL || cfg->current_dynamic_conf == NULL) {
		/* No dynamic conf has been specified, so do not try to dump it */
		return FALSE;
	}

	dir = g_path_get_dirname (cfg->dynamic_conf);
	if (dir == NULL) {
		/* Inaccessible path */
		if (dir != NULL) {
			g_free (dir);
		}
		msg_err ("invalid file: %s", cfg->dynamic_conf);
		return FALSE;
	}

	if (stat (cfg->dynamic_conf, &st) == -1) {
		msg_debug ("%s is unavailable: %s", cfg->dynamic_conf,
			strerror (errno));
		st.st_mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
	}
	if (access (dir, W_OK | R_OK) == -1) {
		msg_warn ("%s is inaccessible: %s", dir, strerror (errno));
		g_free (dir);
		return FALSE;
	}
	rspamd_snprintf (pathbuf,
		sizeof (pathbuf),
		"%s%crconf-XXXXXX",
		dir,
		G_DIR_SEPARATOR);
	g_free (dir);
#ifdef HAVE_MKSTEMP
	/* Umask is set before */
	fd = mkstemp (pathbuf);
#else
	fd = g_mkstemp_full (pathbuf, O_RDWR, S_IWUSR | S_IRUSR);
#endif
	if (fd == -1) {
		msg_err ("mkstemp error: %s", strerror (errno));

		return FALSE;
	}

	if (!dump_dynamic_list (fd, cfg->current_dynamic_conf)) {
		close (fd);
		unlink (pathbuf);
		return FALSE;
	}

	(void)unlink (cfg->dynamic_conf);

	/* Rename old config */
	if (rename (pathbuf, cfg->dynamic_conf) == -1) {
		msg_err ("rename error: %s", strerror (errno));
		close (fd);
		unlink (pathbuf);
		return FALSE;
	}
	/* Set permissions */

	if (chmod (cfg->dynamic_conf, st.st_mode) == -1) {
		msg_warn ("chmod failed: %s", strerror (errno));
	}

	close (fd);
	return TRUE;
}

/**
 * Add symbol for specified metric
 * @param cfg config file object
 * @param metric metric's name
 * @param symbol symbol's name
 * @param value value of symbol
 * @return
 */
gboolean
add_dynamic_symbol (struct rspamd_config *cfg,
	const gchar *metric_name,
	const gchar *symbol,
	gdouble value)
{
	GList *cur;
	struct dynamic_cfg_metric *metric = NULL;
	struct dynamic_cfg_symbol *sym = NULL;

	if (cfg->dynamic_conf == NULL) {
		msg_info ("dynamic conf is disabled");
		return FALSE;
	}

	cur = cfg->current_dynamic_conf;
	while (cur) {
		metric = cur->data;
		if (g_ascii_strcasecmp (metric->name, metric_name) == 0) {
			break;
		}
		metric = NULL;
		cur = g_list_next (cur);
	}

	if (metric != NULL) {
		/* Search for a symbol */
		cur = metric->symbols;
		while (cur) {
			sym = cur->data;
			if (g_ascii_strcasecmp (sym->name, symbol) == 0) {
				sym->value = value;
				msg_debug ("change value of action %s to %.2f", symbol, value);
				break;
			}
			sym = NULL;
			cur = g_list_next (cur);
		}
		if (sym == NULL) {
			/* Symbol not found, insert it */
			sym = g_slice_alloc (sizeof (struct dynamic_cfg_symbol));
			sym->name = g_strdup (symbol);
			sym->value = value;
			metric->symbols = g_list_prepend (metric->symbols, sym);
			msg_debug ("create symbol %s in metric %s", symbol, metric_name);
		}
	}
	else {
		/* Metric not found, create it */
		metric = g_slice_alloc0 (sizeof (struct dynamic_cfg_metric));
		sym = g_slice_alloc (sizeof (struct dynamic_cfg_symbol));
		sym->name = g_strdup (symbol);
		sym->value = value;
		metric->symbols = g_list_prepend (metric->symbols, sym);
		metric->name = g_strdup (metric_name);
		cfg->current_dynamic_conf = g_list_prepend (cfg->current_dynamic_conf,
				metric);
		msg_debug ("create metric %s for symbol %s", metric_name, symbol);
	}

	apply_dynamic_conf (cfg->current_dynamic_conf, cfg);

	return TRUE;
}


/**
 * Add action for specified metric
 * @param cfg config file object
 * @param metric metric's name
 * @param action action's name
 * @param value value of symbol
 * @return
 */
gboolean
add_dynamic_action (struct rspamd_config *cfg,
	const gchar *metric_name,
	guint action,
	gdouble value)
{
	GList *cur;
	struct dynamic_cfg_metric *metric = NULL;

	if (cfg->dynamic_conf == NULL) {
		msg_info ("dynamic conf is disabled");
		return FALSE;
	}

	cur = cfg->current_dynamic_conf;
	while (cur) {
		metric = cur->data;
		if (g_ascii_strcasecmp (metric->name, metric_name) == 0) {
			break;
		}
		metric = NULL;
		cur = g_list_next (cur);
	}

	if (metric != NULL) {
		/* Search for an action */
		metric->actions[action].value = value;
	}
	else {
		/* Metric not found, create it */
		metric = g_slice_alloc0 (sizeof (struct dynamic_cfg_metric));
		metric->actions[action].value = value;
		metric->name = g_strdup (metric_name);
		cfg->current_dynamic_conf = g_list_prepend (cfg->current_dynamic_conf,
				metric);
		msg_debug ("create metric %s for action %d", metric_name, action);
	}

	apply_dynamic_conf (cfg->current_dynamic_conf, cfg);

	return TRUE;
}
