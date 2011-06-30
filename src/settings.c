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
#include "filter.h"
#include "json/jansson.h"

struct json_buf {
	GHashTable                     *table;
	u_char                         *buf;
	u_char                         *pos;
	size_t                          buflen;
};

static void
settings_actions_free (gpointer data)
{
	GList                          *cur = data;

	while (cur) {
		g_free (cur->data);
		cur = g_list_next (cur);
	}

	g_list_free ((GList *)data);
}

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
	if (s->blacklist) {
		g_hash_table_destroy (s->blacklist);
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
	gint                            nelts, i, n, j;
	json_t                         *js, *cur_elt, *cur_nm, *it_val, *act_it, *act_value;
	json_error_t                    je;
	struct metric_action           *new_act;
	struct rspamd_settings         *cur_settings;
	GList                          *cur_act;
	gchar                           *cur_name;
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
		cur_settings->metric_actions = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, settings_actions_free);
		cur_settings->factors = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
		cur_settings->whitelist = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
		cur_settings->blacklist = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
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
					g_hash_table_insert (cur_settings->metric_scores,
							g_strdup (json_object_iter_key (json_it)), score);
				}
				else if (it_val && json_is_object (it_val)) {
					/* Assume this as actions hash */
					cur_act = NULL;
					act_it = json_object_iter (it_val);
					while (act_it) {
						act_value = json_object_iter_value (act_it);

						if (act_value && json_is_number (act_value)) {
							/* Special cases */
							if (g_ascii_strcasecmp (json_object_iter_key (act_it), "spam_score") == 0) {
								score = g_malloc (sizeof (double));
								*score = json_number_value (act_value);
								g_hash_table_insert (cur_settings->metric_scores,
										g_strdup (json_object_iter_key (json_it)), score);
							}
							else if (g_ascii_strcasecmp (json_object_iter_key (act_it), "reject_score") == 0) {
								score = g_malloc (sizeof (double));
								*score = json_number_value (act_value);
								g_hash_table_insert (cur_settings->reject_scores,
										g_strdup (json_object_iter_key (json_it)), score);
							}
							else if (check_action_str (json_object_iter_key (act_it), &j)) {
								new_act = g_malloc (sizeof (struct metric_action));
								new_act->action = j;
								new_act->score = json_number_value (act_value);
								cur_act = g_list_prepend (cur_act, new_act);
							}
						}
						act_it = json_object_iter_next (it_val, act_it);
					}
					if (cur_act != NULL) {
						g_hash_table_insert (cur_settings->metric_actions,
								g_strdup (json_object_iter_key (json_it)), cur_act);
					}
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
			for(j = 0; j < n; j++) {
				it_val = json_array_get(cur_nm, j);
				if (it_val && json_is_string (it_val)) {
					if (strlen (json_string_value (it_val)) > 0) {
						g_hash_table_insert (cur_settings->whitelist,
							g_strdup (json_string_value (it_val)), g_strdup (json_string_value (it_val)));
					}
				}
		    
			}
		}
		/* Blacklist object */
		cur_nm = json_object_get (cur_elt, "blacklist");
		if (cur_nm != NULL && json_is_array (cur_nm)) {
			n = json_array_size(cur_nm);
			for(j = 0; j < n; j++) {
				it_val = json_array_get(cur_nm, j);
				if (it_val && json_is_string (it_val)) {
					if (strlen (json_string_value (it_val)) > 0) {
						g_hash_table_insert (cur_settings->blacklist,
							g_strdup (json_string_value (it_val)), g_strdup (json_string_value (it_val)));
					}
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
read_settings (const gchar *path, struct config_file *cfg, GHashTable * table)
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
	gchar                           *field = NULL, *domain = NULL;
	gchar                            cmp_buf[1024];
	gint                             len;

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
		if (*field == '<') {
			field ++;
		}
		len = strcspn (field, ">");
		rspamd_strlcpy (cmp_buf, field, MIN (sizeof (cmp_buf), len + 1));
		*user_settings = g_hash_table_lookup (task->cfg->user_settings, cmp_buf);
	}
	if (domain != NULL) {
		len = strcspn (domain, ">");
		rspamd_strlcpy (cmp_buf, domain, MIN (sizeof (cmp_buf), len + 1));
		*domain_settings = g_hash_table_lookup (task->cfg->domain_settings, cmp_buf);
	}

	if (*domain_settings != NULL || *user_settings != NULL) {
		return TRUE;
	}

	return FALSE;
}

static				gboolean
check_bwhitelist (struct worker_task *task, struct rspamd_settings *s, gboolean *is_black)
{
	gchar                           *src_email = NULL, *src_domain = NULL, *data;

	if (task->from != NULL && *task->from != '\0') {
		src_email = task->from;
	} else {
		return FALSE;
	}

	src_domain = strchr (src_email, '@');
	if(src_domain != NULL) {
		src_domain++;
	}

	if ((((data = g_hash_table_lookup (s->blacklist, src_email)) != NULL) ||
			( (src_domain != NULL) && ((data = g_hash_table_lookup (s->blacklist, src_domain)) != NULL)) )) {
		*is_black = TRUE;
		msg_info ("<%s> blacklisted as domain %s is in settings blacklist", task->message_id, data);
		return TRUE;
	}
	if ((((data = g_hash_table_lookup (s->whitelist, src_email)) != NULL) ||
			( (src_domain != NULL) && ((data = g_hash_table_lookup (s->whitelist, src_domain)) != NULL)) )) {
		*is_black = FALSE;
		msg_info ("<%s> whitelisted as domain %s is in settings blacklist", task->message_id, data);
		return TRUE;
	}
	return FALSE;
}

gboolean
check_metric_settings (struct metric_result *res, double *score, double *rscore)
{
	struct rspamd_settings         *us = res->user_settings, *ds = res->domain_settings;
	double                         *sc, *rs;
	struct metric                  *metric = res->metric;

	*rscore = DEFAULT_REJECT_SCORE;

	if (us != NULL) {
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
		if ((rs = g_hash_table_lookup (ds->reject_scores, metric->name)) != NULL) {
			*rscore = *rs;
		}
		if ((sc = g_hash_table_lookup (ds->metric_scores, metric->name)) != NULL) {
			*score = *sc;
			return TRUE;
		}
	}

	return FALSE;
}

gboolean
check_metric_action_settings (struct worker_task *task, struct metric_result *res,
		double score, enum rspamd_metric_action *result)
{
	struct rspamd_settings         *us = res->user_settings, *ds = res->domain_settings;
	struct metric_action           *act, *sel = NULL;
	GList                          *cur;
	enum rspamd_metric_action       r = METRIC_ACTION_NOACTION;
	gboolean                        black;
	double                          rej = 0.;

	if (us != NULL) {
		/* Check whitelist and set appropriate action for whitelisted users */
		if (check_bwhitelist(task, us, &black)) {
			if (black) {
				*result = METRIC_ACTION_REJECT;
			}
			else {
				*result = METRIC_ACTION_NOACTION;
			}
			return TRUE;
		}
		if ((cur = g_hash_table_lookup (us->metric_actions, res->metric->name)) != NULL) {
			while (cur) {
				act = cur->data;
				if (score >= act->score) {
					r = act->action;
					sel = act;
				}
				if (r == METRIC_ACTION_REJECT) {
					rej = act->score;
				}
				cur = g_list_next (cur);
			}
		}
	}
	else if (ds != NULL) {
		/* Check whitelist and set appropriate action for whitelisted users */
		if (check_bwhitelist(task, ds, &black)) {
			if (black) {
				*result = METRIC_ACTION_REJECT;
			}
			else {
				*result = METRIC_ACTION_NOACTION;
			}
			return TRUE;
		}
		if ((cur = g_hash_table_lookup (ds->metric_actions, res->metric->name)) != NULL) {
			while (cur) {
				act = cur->data;
				if (score >= act->score) {
					r = act->action;
					sel = act;
				}
				cur = g_list_next (cur);
			}
		}
	}

	if (sel != NULL && result != NULL) {
		*result = r;
		return TRUE;
	}

	return FALSE;
}

gboolean
apply_metric_settings (struct worker_task *task, struct metric *metric, struct metric_result *res)
{
	struct rspamd_settings         *us = NULL, *ds = NULL;

	if (check_setting (task, &us, &ds)) {
		if (us != NULL || ds != NULL) {
			if (us != NULL) {
				res->user_settings = us;
			}
			if (ds != NULL) {
				res->domain_settings = ds;
			}
		}
		else {
			return FALSE;
		}
	}

	return TRUE;
}

gboolean
check_factor_settings (struct metric_result *res, const gchar *symbol, double *factor)
{
	double                         *fc;

	if (res->user_settings != NULL) {
		/* First search in user's settings */
		if ((fc = g_hash_table_lookup (res->user_settings->factors, symbol)) != NULL) {
			*factor = *fc;
			return TRUE;
		}
		/* Now check in domain settings */
		if (res->domain_settings && (fc = g_hash_table_lookup (res->domain_settings->factors, symbol)) != NULL) {
			*factor = *fc;
			return TRUE;
		}
	}
	else if (res->domain_settings != NULL) {
		if ((fc = g_hash_table_lookup (res->domain_settings->factors, symbol)) != NULL) {
			*factor = *fc;
			return TRUE;
		}
	}

	return FALSE;

}


gboolean
check_want_spam (struct worker_task *task)
{
	struct rspamd_settings         *us = NULL, *ds = NULL;

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
