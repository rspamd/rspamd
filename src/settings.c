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

#include "config.h"
#include "cfg_file.h"
#include "map.h"
#include "main.h"
#include "settings.h"
#include "json/jansson.h"

struct json_buf {
	GHashTable                     *table;
	u_char                         *buf;
	u_char                         *pos;
	size_t                          buflen;
};

static void
settings_free (gpointer data)
{
	struct rspamd_settings         *s = data;

	if (s->statfile_alias) {
		g_free (s->statfile_alias);
	}
	if (s->factors) {
		g_hash_table_destroy (s->factors);
	}
	if (s->metric_scores) {
		g_hash_table_destroy (s->metric_scores);
	}
	if (s->reject_scores) {
		g_hash_table_destroy (s->reject_scores);
	}
	if (s->whitelist) {
		g_hash_table_destroy (s->whitelist);
	}
	g_free (s);
}


u_char                         *
json_read_cb (memory_pool_t * pool, u_char * chunk, size_t len, struct map_cb_data *data)
{
	struct json_buf                *jb;
	size_t                          free, off;

	if (data->cur_data == NULL) {
		jb = g_malloc (sizeof (struct json_buf));
		jb->table = ((struct json_buf *)data->prev_data)->table;
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
json_fin_cb (memory_pool_t * pool, struct map_cb_data *data)
{
	struct json_buf                *jb;
	int                             nelts, i, n, a;
	json_t                         *js, *cur_elt, *cur_nm, *it_val;
	json_error_t                    je;
	struct rspamd_settings         *cur_settings;
	char                           *cur_name;
	void                           *json_it;
	double                         *score;

	if (data->prev_data) {
		jb = data->prev_data;
		/* Clean prev data */
		if (jb->table) {
			g_hash_table_remove_all (jb->table);
		}
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

	nelts = json_array_size (js);
	for (i = 0; i < nelts; i++) {
		cur_settings = g_malloc (sizeof (struct rspamd_settings));
		cur_settings->metric_scores = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
		cur_settings->reject_scores = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
		cur_settings->factors = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
		cur_settings->whitelist = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
		cur_settings->statfile_alias = NULL;
		cur_settings->want_spam = FALSE;

		cur_elt = json_array_get (js, i);
		if (!cur_elt || !json_is_object (cur_elt)) {
			json_decref (js);
			msg_err ("loaded json is not an object");
			return;
		}
		cur_nm = json_object_get (cur_elt, "name");
		if (cur_nm == NULL || !json_is_string (cur_nm)) {
			json_decref (js);
			msg_err ("name is not a string or not exists");
			return;
		}
		cur_name = g_strdup (json_string_value (cur_nm));
		/* Now check other settings */
		/* Statfile */
		cur_nm = json_object_get (cur_elt, "statfile");
		if (cur_nm != NULL && json_is_string (cur_nm)) {
			cur_settings->statfile_alias = g_strdup (json_string_value (cur_nm));
		}
		/* Factors object */
		cur_nm = json_object_get (cur_elt, "factors");
		if (cur_nm != NULL && json_is_object (cur_nm)) {
			json_it = json_object_iter (cur_nm);
			while (json_it) {
				it_val = json_object_iter_value (json_it);
				if (it_val && json_is_string (it_val)) {
					g_hash_table_insert (cur_settings->factors, g_strdup (json_object_iter_key (json_it)), g_strdup (json_string_value (it_val)));
				}
				json_it = json_object_iter_next (cur_nm, json_it);
			}
		}
		/* Metrics object */
		cur_nm = json_object_get (cur_elt, "metrics");
		if (cur_nm != NULL && json_is_object (cur_nm)) {
			json_it = json_object_iter (cur_nm);
			while (json_it) {
				it_val = json_object_iter_value (json_it);
				if (it_val && json_is_number (it_val)) {
					score = g_malloc (sizeof (double));
					*score = json_number_value (it_val);
					g_hash_table_insert (cur_settings->metric_scores, g_strdup (json_object_iter_key (json_it)), score);
				}
				json_it = json_object_iter_next (cur_nm, json_it);
			}
		}
		/* Rejects object */
		cur_nm = json_object_get (cur_elt, "rejects");
		if (cur_nm != NULL && json_is_object (cur_nm)) {
			json_it = json_object_iter (cur_nm);
			while (json_it) {
				it_val = json_object_iter_value (json_it);
				if (it_val && json_is_number (it_val)) {
					score = g_malloc (sizeof (double));
					*score = json_number_value (it_val);
					g_hash_table_insert (cur_settings->reject_scores, g_strdup (json_object_iter_key (json_it)), 
											score);
				}
				json_it = json_object_iter_next(cur_nm, json_it);
			}
		}
		/* Whitelist object */
		cur_nm = json_object_get (cur_elt, "whitelist");
		if (cur_nm != NULL && json_is_array (cur_nm)) {
			n = json_array_size(cur_nm);
			for(a = 0; a < n; a++) {
				it_val = json_array_get(cur_nm, a);
				if (it_val && json_is_string (it_val)) {
					g_hash_table_insert (cur_settings->whitelist, g_strdup (json_string_value (it_val)), g_strdup (json_string_value (it_val)));
				}
		    
			}
		}
		/* Want spam */
		cur_nm = json_object_get (cur_elt, "want_spam");
		if (cur_nm != NULL) {
			if (json_is_true (cur_nm)) {
				cur_settings->want_spam = TRUE;
			}
		}
		g_hash_table_insert (((struct json_buf *)data->cur_data)->table, cur_name, cur_settings);
	}
	json_decref (js);
}

gboolean
read_settings (const char *path, struct config_file *cfg, GHashTable * table)
{
	struct json_buf                *jb = g_malloc (sizeof (struct json_buf)), **pjb;

	pjb = g_malloc (sizeof (struct json_buf *));

	jb->table = table;
	jb->buf = NULL;
	*pjb = jb;

	if (!add_map (path, json_read_cb, json_fin_cb, (void **)pjb)) {
		msg_err ("cannot add map %s", path);
		return FALSE;
	}

	return TRUE;
}

void
init_settings (struct config_file *cfg)
{
	cfg->domain_settings = g_hash_table_new_full (rspamd_strcase_hash, rspamd_strcase_equal, g_free, settings_free);
	cfg->user_settings = g_hash_table_new_full (rspamd_strcase_hash, rspamd_strcase_equal, g_free, settings_free);
}

static                          gboolean
check_setting (struct worker_task *task, struct rspamd_settings **user_settings, struct rspamd_settings **domain_settings)
{
	char                           *field = NULL, *domain = NULL;

	if (task->deliver_to != NULL) {
		/* First try to use deliver-to field */
		field = task->deliver_to;
	}
	else if (task->user != NULL) {
		/* Then user field */
		field = task->user;
	}
	else if (task->rcpt != NULL) {
		/* Then first recipient */
		field = task->rcpt->data;
	}
	else {
		return FALSE;
	}

	domain = strchr (field, '@');
	if (domain == NULL) {
		/* First try to search in first recipient */
		if (task->rcpt) {
			domain = strchr (task->rcpt->data, '@');
		}
	}
	if (domain != NULL) {
		domain++;
	}

	/* First try to search per-user settings */
	if (field != NULL) {
		*user_settings = g_hash_table_lookup (task->cfg->user_settings, field);
	}
	if (domain != NULL) {
		*domain_settings = g_hash_table_lookup (task->cfg->domain_settings, domain);
	}

	if (*domain_settings != NULL || *user_settings != NULL) {
		return TRUE;
	}

	return FALSE;
}

static				gboolean
check_whitelist(struct worker_task *task, struct rspamd_settings *s)
{
	char *src_email = NULL, *src_domain = NULL;

	if (task->from != NULL) {
		src_email = task->from;
	} else {
		return FALSE;
	}

	src_domain = strchr (src_email, '@');
	if(src_domain != NULL) {
		src_domain++;
	}

	if (((g_hash_table_lookup (s->whitelist, src_email) != NULL) ||
			( (src_domain != NULL) && (g_hash_table_lookup (s->whitelist, src_domain) != NULL)) )) {
		return TRUE;
	}
	return FALSE;
}

gboolean
check_metric_settings (struct worker_task * task, struct metric * metric, double *score, double *rscore)
{
	struct rspamd_settings         *us, *ds;
	double                         *sc, *rs;

	*rscore = DEFAULT_REJECT_SCORE;

	if (check_setting (task, &us, &ds)) {
		if (us != NULL) {
			/* First look in user white list */
			if (check_whitelist(task, us)) {
				*score = DEFAULT_REJECT_SCORE;
				return TRUE;
			}
			if ((rs = g_hash_table_lookup (us->reject_scores, metric->name)) != NULL) {
				*rscore = *rs;
			}
			if ((sc = g_hash_table_lookup (us->metric_scores, metric->name)) != NULL) {
				*score = *sc;
				return TRUE;
			}
			/* Now check in domain settings */
			if (ds && ((rs = g_hash_table_lookup (ds->reject_scores, metric->name)) != NULL)) {
				*rscore = *rs;
			}
			if (ds && (sc = g_hash_table_lookup (ds->metric_scores, metric->name)) != NULL) {
				*score = *sc;
				return TRUE;
			}
		}
		else if (ds != NULL) {
			if (check_whitelist(task, ds)) {
				*score = DEFAULT_REJECT_SCORE;
				return TRUE;
			}
			if ((rs = g_hash_table_lookup (ds->reject_scores, metric->name)) != NULL) {
				*rscore = *rs;
			}
			if ((sc = g_hash_table_lookup (ds->metric_scores, metric->name)) != NULL) {
				*score = *sc;
				return TRUE;
			}
		}
	}

	return FALSE;
}

gboolean
check_factor_settings (struct worker_task * task, const char *symbol, double *factor)
{
	struct rspamd_settings         *us, *ds;
	double                         *fc;

	if (check_setting (task, &us, &ds)) {
		if (us != NULL) {
			/* First search in user's settings */
			if ((fc = g_hash_table_lookup (us->factors, symbol)) != NULL) {
				*factor = *fc;
				return TRUE;
			}
			/* Now check in domain settings */
			if (ds && (fc = g_hash_table_lookup (ds->factors, symbol)) != NULL) {
				*factor = *fc;
				return TRUE;
			}
		}
		else if (ds != NULL) {
			if ((fc = g_hash_table_lookup (ds->factors, symbol)) != NULL) {
				*factor = *fc;
				return TRUE;
			}
		}
	}

	return FALSE;

}


gboolean
check_want_spam (struct worker_task * task)
{
	struct rspamd_settings         *us, *ds;

	if (check_setting (task, &us, &ds)) {
		if (us != NULL) {
			/* First search in user's settings */
			if (us->want_spam) {
				return TRUE;
			}
			/* Now check in domain settings */
			if (ds && ds->want_spam) {
				return TRUE;
			}
		}
		else if (ds != NULL) {
			if (ds->want_spam) {
				return TRUE;
			}
		}
	}

	return FALSE;
}

/* 
 * vi:ts=4 
 */
