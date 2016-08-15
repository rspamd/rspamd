/*-
 * Copyright 2016 Vsevolod Stakhov
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "config.h"
#include "rspamd.h"
#include "util.h"
#include "cfg_file.h"
#include "cfg_rcl.h"
#include "message.h"
#include "utlist.h"
#include "http.h"
#include "http_private.h"
#include "email_addr.h"
#include "worker_private.h"
#include "cryptobox.h"
#include <math.h>

/* Max line size */
#define OUTBUFSIZ BUFSIZ
/*
 * Just check if the passed message is spam or not and reply as
 * described below
 */
#define MSG_CMD_CHECK "check"
/*
 * Check if message is spam or not, and return score plus list
 * of symbols hit
 */
#define MSG_CMD_SYMBOLS "symbols"
/*
 * Check if message is spam or not, and return score plus report
 */
#define MSG_CMD_REPORT "report"
/*
 * Check if message is spam or not, and return score plus report
 * if the message is spam
 */
#define MSG_CMD_REPORT_IFSPAM "report_ifspam"
/*
 * Ignore this message -- client opened connection then changed
 */
#define MSG_CMD_SKIP "skip"
/*
 * Return a confirmation that spamd is alive
 */
#define MSG_CMD_PING "ping"
/*
 * Process this message as described above and return modified message
 */
#define MSG_CMD_PROCESS "process"

/*
 * Learn specified statfile using message
 */
#define MSG_CMD_LEARN "learn"

/*
 * spamassassin greeting:
 */
#define SPAMC_GREETING "SPAMC"
/*
 * rspamd greeting:
 */
#define RSPAMC_GREETING "RSPAMC"
/*
 * Headers
 */
#define CONTENT_LENGTH_HEADER "Content-length"
#define HELO_HEADER "Helo"
#define FROM_HEADER "From"
#define IP_ADDR_HEADER "IP"
#define NRCPT_HEADER "Recipient-Number"
#define RCPT_HEADER "Rcpt"
#define SUBJECT_HEADER "Subject"
#define SETTINGS_ID_HEADER "Settings-ID"
#define STATFILE_HEADER "Statfile"
#define QUEUE_ID_HEADER "Queue-ID"
#define ERROR_HEADER "Error"
#define USER_HEADER "User"
#define URLS_HEADER "URL-Format"
#define PASS_HEADER "Pass"
#define JSON_HEADER "Json"
#define HOSTNAME_HEADER "Hostname"
#define DELIVER_TO_HEADER "Deliver-To"
#define NO_LOG_HEADER "Log"
#define MLEN_HEADER "Message-Length"


static GQuark
rspamd_protocol_quark (void)
{
	return g_quark_from_static_string ("protocol-error");
}

/*
 * Remove <> from the fixed string and copy it to the pool
 */
static gchar *
rspamd_protocol_escape_braces (struct rspamd_task *task, rspamd_fstring_t *in)
{
	guint nchars = 0;
	const gchar *p;
	rspamd_ftok_t tok;
	gboolean has_obrace = FALSE;

	g_assert (in != NULL);
	g_assert (in->len > 0);

	p = in->str;

	while ((g_ascii_isspace (*p) || *p == '<') && nchars < in->len) {
		if (*p == '<') {
			has_obrace = TRUE;
		}

		p++;
		nchars ++;
	}

	tok.begin = p;

	p = in->str + in->len - 1;
	tok.len = in->len - nchars;

	while (g_ascii_isspace (*p) && tok.len > 0) {
		p--;
		tok.len --;
	}

	if (has_obrace && *p == '>') {
		tok.len --;
	}

	return rspamd_mempool_ftokdup (task->task_pool, &tok);
}

static gboolean
rspamd_protocol_handle_url (struct rspamd_task *task,
	struct rspamd_http_message *msg)
{
	GHashTable *query_args;
	GHashTableIter it;
	struct http_parser_url u;
	const gchar *p;
	gsize pathlen;
	rspamd_ftok_t *key, *value;
	gpointer k, v;

	if (msg->url == NULL || msg->url->len == 0) {
		g_set_error (&task->err, rspamd_protocol_quark(), 400, "missing command");
		return FALSE;
	}

	if (http_parser_parse_url (msg->url->str, msg->url->len, 0, &u) != 0) {
		g_set_error (&task->err, rspamd_protocol_quark(), 400, "bad request URL");

		return FALSE;
	}

	if (!(u.field_set & (1 << UF_PATH))) {
		g_set_error (&task->err, rspamd_protocol_quark(), 400,
				"bad request URL: missing path");

		return FALSE;
	}

	p = msg->url->str + u.field_data[UF_PATH].off;
	pathlen = u.field_data[UF_PATH].len;

	if (*p == '/') {
		p ++;
		pathlen --;
	}

	switch (*p) {
	case 'c':
	case 'C':
		/* check */
		if (g_ascii_strncasecmp (p, MSG_CMD_CHECK, pathlen) == 0) {
			task->cmd = CMD_CHECK;
		}
		else {
			goto err;
		}
		break;
	case 's':
	case 'S':
		/* symbols, skip */
		if (g_ascii_strncasecmp (p, MSG_CMD_SYMBOLS, pathlen) == 0) {
			task->cmd = CMD_SYMBOLS;
		}
		else if (g_ascii_strncasecmp (p, MSG_CMD_SKIP, pathlen) == 0) {
			task->cmd = CMD_SKIP;
		}
		else {
			goto err;
		}
		break;
	case 'p':
	case 'P':
		/* ping, process */
		if (g_ascii_strncasecmp (p, MSG_CMD_PING, pathlen) == 0) {
			task->cmd = CMD_PING;
		}
		else if (g_ascii_strncasecmp (p, MSG_CMD_PROCESS, pathlen) == 0) {
			task->cmd = CMD_PROCESS;
		}
		else {
			goto err;
		}
		break;
	case 'r':
	case 'R':
		/* report, report_ifspam */
		if (g_ascii_strncasecmp (p, MSG_CMD_REPORT, pathlen) == 0) {
			task->cmd = CMD_REPORT;
		}
		else if (g_ascii_strncasecmp (p, MSG_CMD_REPORT_IFSPAM,
				pathlen) == 0) {
			task->cmd = CMD_REPORT_IFSPAM;
		}
		else {
			goto err;
		}
		break;
	default:
		goto err;
	}

	if (u.field_set & (1 << UF_QUERY)) {
		/* In case if we have a query, we need to store it somewhere */
		query_args = rspamd_http_message_parse_query (msg);

		/* Insert the rest of query params as HTTP headers */
		g_hash_table_iter_init (&it, query_args);

		while (g_hash_table_iter_next (&it, &k, &v)) {
			key = k;
			value = v;
			/* Steal strings */
			g_hash_table_iter_steal (&it);
			rspamd_task_add_request_header (task, key, value);
			msg_debug_task ("added header \"%T\" -> \"%T\" from HTTP query",
					key, value);
		}

		g_hash_table_unref (query_args);
	}

	return TRUE;

err:
	g_set_error (&task->err, rspamd_protocol_quark(), 400, "invalid command: %*.s",
			(gint)pathlen, p);

	return FALSE;
}

#define IF_HEADER(name) \
	srch.begin = (name); \
	srch.len = sizeof (name) - 1; \
	if (rspamd_ftok_casecmp (hn_tok, &srch) == 0)

gboolean
rspamd_protocol_handle_headers (struct rspamd_task *task,
	struct rspamd_http_message *msg)
{
	rspamd_fstring_t *hn, *hv;
	rspamd_ftok_t *hn_tok, *hv_tok, srch;
	gboolean fl, has_ip = FALSE;
	struct rspamd_http_header *header, *h, *htmp;
	struct rspamd_email_address *addr;

	HASH_ITER (hh, msg->headers, header, htmp) {
		DL_FOREACH (header, h) {
			hn = rspamd_fstring_new_init (h->name->begin, h->name->len);
			hv = rspamd_fstring_new_init (h->value->begin, h->value->len);
			hn_tok = rspamd_ftok_map (hn);
			hv_tok = rspamd_ftok_map (hv);

			switch (*hn_tok->begin) {
			case 'd':
			case 'D':
				IF_HEADER (DELIVER_TO_HEADER) {
					task->deliver_to = rspamd_protocol_escape_braces (task, hv);
					debug_task ("read deliver-to header, value: %s",
							task->deliver_to);
				}
				else {
					debug_task ("wrong header: %V", hn);
				}
				break;
			case 'h':
			case 'H':
				IF_HEADER (HELO_HEADER) {
					task->helo = rspamd_mempool_ftokdup (task->task_pool, hv_tok);
					debug_task ("read helo header, value: %s", task->helo);
				}
				IF_HEADER (HOSTNAME_HEADER) {
					task->hostname = rspamd_mempool_ftokdup (task->task_pool,
							hv_tok);
					debug_task ("read hostname header, value: %s", task->hostname);
				}
				break;
			case 'f':
			case 'F':
				IF_HEADER (FROM_HEADER) {
					task->from_envelope = rspamd_email_address_from_smtp (hv->str,
							hv->len);
					if (!task->from_envelope) {
						msg_err_task ("bad from header: '%V'", hv);
					}
				}
				else {
					debug_task ("wrong header: %V", hn);
				}
				break;
			case 'j':
			case 'J':
				IF_HEADER (JSON_HEADER) {
					fl = rspamd_config_parse_flag (hv->str, hv->len);
					if (fl) {
						task->flags |= RSPAMD_TASK_FLAG_JSON;
					}
					else {
						task->flags &= ~RSPAMD_TASK_FLAG_JSON;
					}
				}
				else {
					debug_task ("wrong header: %V", hn);
				}
				break;
			case 'q':
			case 'Q':
				IF_HEADER (QUEUE_ID_HEADER) {
					task->queue_id = rspamd_mempool_ftokdup (task->task_pool,
							hv_tok);
					debug_task ("read queue_id header, value: %s", task->queue_id);
				}
				else {
					debug_task ("wrong header: %V", hn);
				}
				break;
			case 'r':
			case 'R':
				IF_HEADER (RCPT_HEADER) {
					addr = rspamd_email_address_from_smtp (hv->str, hv->len);

					if (addr) {
						if (task->rcpt_envelope == NULL) {
							task->rcpt_envelope = g_ptr_array_new ();
						}

						g_ptr_array_add (task->rcpt_envelope, addr);
					}
					else {
						msg_err_task ("bad from header: '%T'", h->value);
					}
					debug_task ("read rcpt header, value: %V", hv);
				}
				else {
					debug_task ("wrong header: %V", hn);
				}
				break;
			case 'i':
			case 'I':
				IF_HEADER (IP_ADDR_HEADER) {
					if (!rspamd_parse_inet_address (&task->from_addr, hv->str, hv->len)) {
						msg_err_task ("bad ip header: '%V'", hv);
						return FALSE;
					}
					debug_task ("read IP header, value: %V", hv);
					has_ip = TRUE;
				}
				else {
					debug_task ("wrong header: %V", hn);
				}
				break;
			case 'p':
			case 'P':
				IF_HEADER (PASS_HEADER) {
					srch.begin = "all";
					srch.len = 3;

					if (rspamd_ftok_casecmp (hv_tok, &srch) == 0) {
						task->flags |= RSPAMD_TASK_FLAG_PASS_ALL;
						debug_task ("pass all filters");
					}
				}
				break;
			case 's':
			case 'S':
				IF_HEADER (SUBJECT_HEADER) {
					task->subject = rspamd_mempool_ftokdup (task->task_pool, hv_tok);
				}
				IF_HEADER (SETTINGS_ID_HEADER) {
					guint64 h;
					guint32 *hp;

					h = rspamd_cryptobox_fast_hash_specific (RSPAMD_CRYPTOBOX_XXHASH64,
							hv_tok->begin, hv_tok->len, 0xdeadbabe);
					hp = rspamd_mempool_alloc (task->task_pool, sizeof (*hp));
					memcpy (hp, &h, sizeof (*hp));
					rspamd_mempool_set_variable (task->task_pool, "settings_hash",
							hp, NULL);
				}
				break;
			case 'u':
			case 'U':
				IF_HEADER (USER_HEADER) {
					/*
					 * We must ignore User header in case of spamc, as SA has
					 * different meaning of this header
					 */
					if (!RSPAMD_TASK_IS_SPAMC (task)) {
						task->user = rspamd_mempool_ftokdup (task->task_pool,
								hv_tok);
					}
				}
				IF_HEADER (URLS_HEADER) {
					srch.begin = "extended";
					srch.len = 8;

					if (rspamd_ftok_casecmp (hv_tok, &srch) == 0) {
						task->flags |= RSPAMD_TASK_FLAG_EXT_URLS;
						debug_task ("extended urls information");
					}
				}
				break;
			case 'l':
			case 'L':
				IF_HEADER (NO_LOG_HEADER) {
					srch.begin = "no";
					srch.len = 2;

					if (rspamd_ftok_casecmp (hv_tok, &srch) == 0) {
						task->flags |= RSPAMD_TASK_FLAG_NO_LOG;
					}
				}
				break;
			case 'm':
			case 'M':
				IF_HEADER (MLEN_HEADER) {
					if (!rspamd_strtoul (hv_tok->begin,
							hv_tok->len,
							&task->message_len)) {
						msg_err_task ("Invalid message length header: %V", hv);
					}
					else {
						task->flags |= RSPAMD_TASK_FLAG_HAS_CONTROL;
					}
				}
				break;
			default:
				debug_task ("unknown header: %V", hn);
				break;
			}

			rspamd_task_add_request_header (task, hn_tok, hv_tok);
		}
	}

	if (!has_ip) {
		task->flags |= RSPAMD_TASK_FLAG_NO_IP;
	}

	return TRUE;
}

#define BOOL_TO_FLAG(val, flags, flag) do {									\
	if ((val)) (flags) |= (flag);											\
	else (flags) &= ~(flag);												\
} while(0)

gboolean
rspamd_protocol_parse_task_flags (rspamd_mempool_t *pool,
	const ucl_object_t *obj,
	gpointer ud,
	struct rspamd_rcl_section *section,
	GError **err)
{
	struct rspamd_rcl_struct_parser *pd = ud;
	gint *target;
	const gchar *key;
	gboolean value;

	target = (gint *)(((gchar *)pd->user_struct) + pd->offset);
	key = ucl_object_key (obj);
	value = ucl_object_toboolean (obj);

	if (key != NULL) {
		if (g_ascii_strcasecmp (key, "pass_all") == 0) {
			BOOL_TO_FLAG (value, *target, RSPAMD_TASK_FLAG_PASS_ALL);
		}
		else if (g_ascii_strcasecmp (key, "no_log") == 0) {
			BOOL_TO_FLAG (value, *target, RSPAMD_TASK_FLAG_NO_LOG);
		}
	}

	return TRUE;
}

static struct rspamd_rcl_section *control_parser = NULL;

static void
rspamd_protocol_control_parser_init (void)
{
	struct rspamd_rcl_section *sub;

	if (control_parser == NULL) {
		sub = rspamd_rcl_add_section (&control_parser,
				"*",
				NULL,
				NULL,
				UCL_OBJECT,
				FALSE,
				TRUE);
		/* Default handlers */
		rspamd_rcl_add_default_handler (sub,
				"ip",
				rspamd_rcl_parse_struct_addr,
				G_STRUCT_OFFSET (struct rspamd_task, from_addr),
				0,
				NULL);
		rspamd_rcl_add_default_handler (sub,
				"from",
				rspamd_rcl_parse_struct_mime_addr,
				G_STRUCT_OFFSET (struct rspamd_task, from_envelope),
				0,
				NULL);
		rspamd_rcl_add_default_handler (sub,
				"rcpt",
				rspamd_rcl_parse_struct_mime_addr,
				G_STRUCT_OFFSET (struct rspamd_task, rcpt_envelope),
				0,
				NULL);
		rspamd_rcl_add_default_handler (sub,
				"helo",
				rspamd_rcl_parse_struct_string,
				G_STRUCT_OFFSET (struct rspamd_task, helo),
				0,
				NULL);
		rspamd_rcl_add_default_handler (sub,
				"user",
				rspamd_rcl_parse_struct_string,
				G_STRUCT_OFFSET (struct rspamd_task, user),
				0,
				NULL);
		rspamd_rcl_add_default_handler (sub,
				"pass_all",
				rspamd_protocol_parse_task_flags,
				G_STRUCT_OFFSET (struct rspamd_task, flags),
				0,
				NULL);
		rspamd_rcl_add_default_handler (sub,
				"json",
				rspamd_protocol_parse_task_flags,
				G_STRUCT_OFFSET (struct rspamd_task, flags),
				0,
				NULL);
	}
}

gboolean
rspamd_protocol_handle_control (struct rspamd_task *task,
		const ucl_object_t *control)
{
	GError *err = NULL;

	rspamd_protocol_control_parser_init ();

	if (!rspamd_rcl_parse (control_parser, task->cfg, task, task->task_pool,
			control, &err)) {
		msg_warn_task ("cannot parse control block: %e", err);
		g_error_free (err);

		return FALSE;
	}

	return TRUE;
}

gboolean
rspamd_protocol_handle_request (struct rspamd_task *task,
	struct rspamd_http_message *msg)
{
	gboolean ret = TRUE;

	if (msg->method == HTTP_SYMBOLS) {
		task->cmd = CMD_SYMBOLS;
		task->flags &= ~RSPAMD_TASK_FLAG_JSON;
	}
	else if (msg->method == HTTP_CHECK) {
		task->cmd = CMD_CHECK;
		task->flags &= ~RSPAMD_TASK_FLAG_JSON;
	}
	else {
		task->flags |= RSPAMD_TASK_FLAG_JSON;
		ret = rspamd_protocol_handle_url (task, msg);
	}

	if (msg->flags & RSPAMD_HTTP_FLAG_SPAMC) {
		task->flags &= ~RSPAMD_TASK_FLAG_JSON;
		task->flags |= RSPAMD_TASK_FLAG_SPAMC;
	}

	return ret;
}

/* Structure for writing tree data */
struct tree_cb_data {
	ucl_object_t *top;
	struct rspamd_task *task;
};

static ucl_object_t *
rspamd_protocol_extended_url (struct rspamd_url *url)
{
	ucl_object_t *obj, *elt;

	obj = ucl_object_typed_new (UCL_OBJECT);

	elt = ucl_object_fromlstring (url->string, url->urllen);
	ucl_object_insert_key (obj, elt, "url", 0, false);

	if (url->surbllen > 0) {
		elt = ucl_object_fromlstring (url->surbl, url->surbllen);
		ucl_object_insert_key (obj, elt, "surbl", 0, false);
	}
	if (url->hostlen > 0) {
		elt = ucl_object_fromlstring (url->host, url->hostlen);
		ucl_object_insert_key (obj, elt, "host", 0, false);
	}

	elt = ucl_object_frombool (url->flags & RSPAMD_URL_FLAG_PHISHED);
	ucl_object_insert_key (obj, elt, "phished", 0, false);

	elt = ucl_object_frombool (url->flags & RSPAMD_URL_FLAG_REDIRECTED);
	ucl_object_insert_key (obj, elt, "redirected", 0, false);

	if (url->phished_url) {
		elt = rspamd_protocol_extended_url (url->phished_url);
		ucl_object_insert_key (obj, elt, "orig_url", 0, false);
	}

	return obj;
}

/*
 * Callback for writing urls
 */
static void
urls_protocol_cb (gpointer key, gpointer value, gpointer ud)
{
	struct tree_cb_data *cb = ud;
	struct rspamd_url *url = value;
	ucl_object_t *obj;
	struct rspamd_task *task = cb->task;
	const gchar *user_field = "unknown";
	gboolean has_user = FALSE;
	guint len = 0;

	if (!(task->flags & RSPAMD_TASK_FLAG_EXT_URLS)) {
		obj = ucl_object_fromlstring (url->string, url->urllen);
	}
	else {
		obj = rspamd_protocol_extended_url (url);
	}

	ucl_array_append (cb->top, obj);

	if (cb->task->cfg->log_urls) {
		if (task->user) {
			user_field = task->user;
			len = strlen (task->user);
			has_user = TRUE;
		}
		else if (task->from_envelope) {
			user_field = task->from_envelope->addr;
			len = task->from_envelope->addr_len;
		}

		msg_info_task ("<%s> %s: %*s; ip: %s; URL: %*s",
			task->message_id,
			has_user ? "user" : "from",
			len, user_field,
			rspamd_inet_address_to_string (task->from_addr),
			url->urllen, url->string);
	}
}

static ucl_object_t *
rspamd_urls_tree_ucl (GHashTable *input, struct rspamd_task *task)
{
	struct tree_cb_data cb;
	ucl_object_t *obj;

	obj = ucl_object_typed_new (UCL_ARRAY);
	cb.top = obj;
	cb.task = task;

	g_hash_table_foreach (input, urls_protocol_cb, &cb);

	return obj;
}

static void
emails_protocol_cb (gpointer key, gpointer value, gpointer ud)
{
	struct tree_cb_data *cb = ud;
	struct rspamd_url *url = value;
	ucl_object_t *obj;

	if (url->userlen > 0 && url->hostlen > 0 &&
			url->host == url->user + url->userlen + 1) {
		obj = ucl_object_fromlstring (url->user,
				url->userlen + url->hostlen + 1);
		ucl_array_append (cb->top, obj);
	}
}

static ucl_object_t *
rspamd_emails_tree_ucl (GHashTable *input, struct rspamd_task *task)
{
	struct tree_cb_data cb;
	ucl_object_t *obj;

	obj = ucl_object_typed_new (UCL_ARRAY);
	cb.top = obj;
	cb.task = task;

	g_hash_table_foreach (input, emails_protocol_cb, &cb);

	return obj;
}


/* Write new subject */
static const gchar *
make_rewritten_subject (struct metric *metric, struct rspamd_task *task)
{
	static gchar subj_buf[1024];
	gchar *p = subj_buf, *end, *res;
	const gchar *s, *c;

	end = p + sizeof(subj_buf);
	c = metric->subject;
	if (c == NULL) {
		c = SPAM_SUBJECT;
	}

	s = g_mime_message_get_subject (task->message);

	while (p < end) {
		if (*c == '\0') {
			*p = '\0';
			break;
		}
		else if (*c == '%' && *(c + 1) == 's') {
			p += rspamd_strlcpy (p, (s != NULL) ? s : "", end - p);
			c += 2;
		}
		else {
			*p = *c++;
		}
		p++;
	}
	res = g_mime_utils_header_encode_text (subj_buf);

	rspamd_mempool_add_destructor (task->task_pool,
		(rspamd_mempool_destruct_t)g_free,
		res);

	return res;
}

static ucl_object_t *
rspamd_str_list_ucl (GList *str_list)
{
	ucl_object_t *top = NULL, *obj;
	GList *cur;

	top = ucl_object_typed_new (UCL_ARRAY);
	cur = str_list;
	while (cur) {
		obj = ucl_object_fromstring (cur->data);
		ucl_array_append (top, obj);
		cur = g_list_next (cur);
	}

	return top;
}

static ucl_object_t *
rspamd_metric_symbol_ucl (struct rspamd_task *task, struct metric *m,
	struct symbol *sym)
{
	ucl_object_t *obj = NULL;
	const gchar *description = NULL;

	if (sym->def != NULL) {
		description = sym->def->description;
	}

	obj = ucl_object_typed_new (UCL_OBJECT);
	ucl_object_insert_key (obj, ucl_object_fromstring (
			sym->name),	 "name",  0, false);
	ucl_object_insert_key (obj, ucl_object_fromdouble (
			sym->score), "score", 0, false);
	if (description) {
		ucl_object_insert_key (obj, ucl_object_fromstring (
				description), "description", 0, false);
	}
	if (sym->options != NULL) {
		ucl_object_insert_key (obj, rspamd_str_list_ucl (
				sym->options), "options", 0, false);
	}

	return obj;
}

static ucl_object_t *
rspamd_metric_result_ucl (struct rspamd_task *task,
	struct metric_result *mres)
{
	GHashTableIter hiter;
	struct symbol *sym;
	struct metric *m;
	gboolean is_spam;
	enum rspamd_metric_action action = METRIC_ACTION_NOACTION;
	ucl_object_t *obj = NULL, *sobj;;
	gpointer h, v;
	const gchar *subject;

	m = mres->metric;

	if (mres->action == METRIC_ACTION_MAX) {
		mres->action = rspamd_check_action_metric (task, mres);
	}

	action = mres->action;
	is_spam = (action < METRIC_ACTION_GREYLIST);

	obj = ucl_object_typed_new (UCL_OBJECT);
	ucl_object_insert_key (obj,
			ucl_object_frombool (is_spam),
			"is_spam", 0, false);
	ucl_object_insert_key (obj,
			ucl_object_frombool (RSPAMD_TASK_IS_SKIPPED (task)),
			"is_skipped", 0, false);
	if (!isnan (mres->score)) {
		ucl_object_insert_key (obj, ucl_object_fromdouble (mres->score),
			"score", 0, false);
	} else {
		ucl_object_insert_key (obj,
			ucl_object_fromdouble (0.0), "score", 0, false);
	}
	ucl_object_insert_key (obj,
			ucl_object_fromdouble (rspamd_task_get_required_score (task, mres)),
			"required_score", 0, false);
	ucl_object_insert_key (obj,
			ucl_object_fromstring (rspamd_action_to_str (action)),
			"action", 0, false);

	if (action == METRIC_ACTION_REWRITE_SUBJECT) {
		subject = make_rewritten_subject (m, task);
		ucl_object_insert_key (obj, ucl_object_fromstring (subject),
				"subject", 0, false);
	}
	/* Now handle symbols */
	g_hash_table_iter_init (&hiter, mres->symbols);
	while (g_hash_table_iter_next (&hiter, &h, &v)) {
		sym = (struct symbol *)v;
		sobj = rspamd_metric_symbol_ucl (task, m, sym);
		ucl_object_insert_key (obj, sobj, h, 0, false);
	}

	return obj;
}

void
rspamd_ucl_torspamc_output (const ucl_object_t *top,
	rspamd_fstring_t **out)
{
	const ucl_object_t *metric, *score,
	*required_score, *is_spam, *elt, *cur;
	ucl_object_iter_t iter = NULL;

	metric = ucl_object_lookup (top, DEFAULT_METRIC);
	if (metric != NULL) {
		score = ucl_object_lookup (metric, "score");
		required_score = ucl_object_lookup (metric, "required_score");
		is_spam = ucl_object_lookup (metric, "is_spam");
		rspamd_printf_fstring (out,
			"Metric: default; %s; %.2f / %.2f / 0.0\r\n",
			ucl_object_toboolean (is_spam) ? "True" : "False",
			ucl_object_todouble (score),
			ucl_object_todouble (required_score));
		elt = ucl_object_lookup (metric, "action");
		if (elt != NULL) {
			rspamd_printf_fstring (out, "Action: %s\r\n",
				ucl_object_tostring (elt));
		}

		iter = NULL;
		while ((elt = ucl_object_iterate (metric, &iter, true)) != NULL) {
			if (elt->type == UCL_OBJECT) {
				const ucl_object_t *sym_score;
				sym_score = ucl_object_lookup (elt, "score");
				rspamd_printf_fstring (out, "Symbol: %s(%.2f)\r\n",
					ucl_object_key (elt),
					ucl_object_todouble (sym_score));
			}
		}

		elt = ucl_object_lookup (metric, "subject");
		if (elt != NULL) {
			rspamd_printf_fstring (out, "Subject: %s\r\n",
				ucl_object_tostring (elt));
		}
	}

	elt = ucl_object_lookup (top, "messages");
	if (elt != NULL) {
		iter = NULL;
		while ((cur = ucl_object_iterate (elt, &iter, true)) != NULL) {
			if (cur->type == UCL_STRING) {
				rspamd_printf_fstring (out, "Message: %s\r\n",
						ucl_object_tostring (cur));
			}
		}
	}

	elt = ucl_object_lookup (top, "message-id");
	if (elt != NULL) {
		rspamd_printf_fstring (out, "Message-ID: %s\r\n",
				ucl_object_tostring (elt));
	}
}

static void
rspamd_ucl_tospamc_output (const ucl_object_t *top,
	rspamd_fstring_t **out)
{
	const ucl_object_t *metric, *score,
		*required_score, *is_spam, *elt;
	ucl_object_iter_t iter = NULL;
	rspamd_fstring_t *f;

	metric = ucl_object_lookup (top, DEFAULT_METRIC);
	if (metric != NULL) {
		score = ucl_object_lookup (metric, "score");
		required_score = ucl_object_lookup (metric, "required_score");
		is_spam = ucl_object_lookup (metric, "is_spam");
		rspamd_printf_fstring (out,
			"Spam: %s ; %.2f / %.2f\r\n\r\n",
			ucl_object_toboolean (is_spam) ? "True" : "False",
			ucl_object_todouble (score),
			ucl_object_todouble (required_score));

		while ((elt = ucl_object_iterate (metric, &iter, true)) != NULL) {
			if (elt->type == UCL_OBJECT) {
				rspamd_printf_fstring (out, "%s,",
					ucl_object_key (elt));
			}
		}
		/* Ugly hack, but the whole spamc is ugly */
		f = *out;
		if (f->str[f->len - 1] == ',') {
			f->len --;

			*out = rspamd_fstring_append (*out, CRLF, 2);
		}
	}
}

ucl_object_t *
rspamd_protocol_write_ucl (struct rspamd_task *task)
{
	struct metric_result *metric_res;
	ucl_object_t *top = NULL, *obj;
	GHashTableIter hiter;
	GString *dkim_sig;
	const ucl_object_t *rmilter_reply;
	gpointer h, v;

	g_hash_table_iter_init (&hiter, task->results);
	top = ucl_object_typed_new (UCL_OBJECT);
	/* Convert results to an ucl object */
	while (g_hash_table_iter_next (&hiter, &h, &v)) {
		metric_res = (struct metric_result *)v;
		obj = rspamd_metric_result_ucl (task, metric_res);
		ucl_object_insert_key (top, obj, h, 0, false);
	}

	if (task->messages != NULL) {
		ucl_object_insert_key (top, rspamd_str_list_ucl (
				task->messages), "messages", 0, false);
	}

	if (task->cfg->log_urls || (task->flags & RSPAMD_TASK_FLAG_EXT_URLS)) {
		if (g_hash_table_size (task->urls) > 0) {
			ucl_object_insert_key (top, rspamd_urls_tree_ucl (task->urls,
					task), "urls", 0, false);
		}
		if (g_hash_table_size (task->emails) > 0) {
			ucl_object_insert_key (top, rspamd_emails_tree_ucl (task->emails, task),
					"emails", 0, false);
		}
	}

	ucl_object_insert_key (top, ucl_object_fromstring (task->message_id),
			"message-id", 0, false);

	dkim_sig = rspamd_mempool_get_variable (task->task_pool, "dkim-signature");

	if (dkim_sig) {
		GString *folded_header = rspamd_header_value_fold ("DKIM-Signature",
				dkim_sig->str, 80);
		ucl_object_insert_key (top,
				ucl_object_fromstring_common (folded_header->str,
						folded_header->len, UCL_STRING_RAW),
				"dkim-signature", 0, false);
		g_string_free (folded_header, TRUE);
	}

	rmilter_reply = rspamd_mempool_get_variable (task->task_pool, "rmilter-reply");

	if (rmilter_reply) {
		ucl_object_insert_key (top, ucl_object_ref (rmilter_reply),
				"rmilter", 0, false);
	}

	return top;
}

void
rspamd_protocol_http_reply (struct rspamd_http_message *msg,
	struct rspamd_task *task)
{
	struct metric_result *metric_res;
	GHashTableIter hiter;
	const struct rspamd_re_cache_stat *restat;
	gpointer h, v;
	ucl_object_t *top = NULL;
	rspamd_fstring_t *reply;
	gint action;

	/* Write custom headers */
	g_hash_table_iter_init (&hiter, task->reply_headers);
	while (g_hash_table_iter_next (&hiter, &h, &v)) {
		rspamd_ftok_t *hn = h, *hv = v;

		rspamd_http_message_add_header (msg, hn->begin, hv->begin);
	}

	top = rspamd_protocol_write_ucl (task);

	if (!(task->flags & RSPAMD_TASK_FLAG_NO_LOG)) {
		rspamd_roll_history_update (task->worker->srv->history, task);
	}

	rspamd_task_write_log (task);

	if (task->cfg->log_re_cache) {
		restat = rspamd_re_cache_get_stat (task->re_rt);
		g_assert (restat != NULL);
		msg_info_task (
				"regexp statistics: %ud pcre regexps scanned, %ud regexps matched,"
				" %ud regexps total, %ud regexps cached,"
				" %HL bytes scanned using pcre, %HL bytes scanned total",
				restat->regexp_checked,
				restat->regexp_matched,
				restat->regexp_total,
				restat->regexp_fast_cached,
				restat->bytes_scanned_pcre,
				restat->bytes_scanned);
	}

	reply = rspamd_fstring_sized_new (1000);

	if (msg->method < HTTP_SYMBOLS && !RSPAMD_TASK_IS_SPAMC (task)) {
		rspamd_ucl_emit_fstring (top, UCL_EMIT_JSON_COMPACT, &reply);
	}
	else {
		if (RSPAMD_TASK_IS_SPAMC (task)) {
			rspamd_ucl_tospamc_output (top, &reply);
		}
		else {
			rspamd_ucl_torspamc_output (top, &reply);
		}
	}

	ucl_object_unref (top);
	rspamd_http_message_set_body_from_fstring_steal (msg, reply);

	if (!(task->flags & RSPAMD_TASK_FLAG_NO_STAT)) {
		/* Update stat for default metric */
		metric_res = g_hash_table_lookup (task->results, DEFAULT_METRIC);
		if (metric_res != NULL) {

			if (metric_res->action != METRIC_ACTION_MAX) {
				action = metric_res->action;
			}
			else {
				action = rspamd_check_action_metric (task, metric_res);
			}

			if (action <= METRIC_ACTION_NOACTION) {
#ifndef HAVE_ATOMIC_BUILTINS
				task->worker->srv->stat->actions_stat[action]++;
#else
				__atomic_add_fetch (&task->worker->srv->stat->actions_stat[action],
						1, __ATOMIC_RELEASE);
#endif
			}
		}

		/* Increase counters */
#ifndef HAVE_ATOMIC_BUILTINS
		task->worker->srv->stat->messages_scanned++;
#else
		__atomic_add_fetch (&task->worker->srv->stat->messages_scanned,
				1, __ATOMIC_RELEASE);
#endif
	}
}

static void
rspamd_protocol_write_log_pipe (struct rspamd_worker_ctx *ctx,
		struct rspamd_task *task)
{
	struct rspamd_worker_log_pipe *lp;
	struct rspamd_protocol_log_message_sum *ls;
	struct metric_result *mres;
	GHashTableIter it;
	gpointer k, v;
	struct symbol *sym;
	gint id, i;
	guint32 *sid;
	gsize sz;

	LL_FOREACH (ctx->log_pipes, lp) {
		if (lp->fd != -1) {
			switch (lp->type) {
			case RSPAMD_LOG_PIPE_SYMBOLS:
				mres = g_hash_table_lookup (task->results, DEFAULT_METRIC);

				if (mres) {
					sz = sizeof (*ls) +
							sizeof (struct rspamd_protocol_log_symbol_result) *
							g_hash_table_size (mres->symbols);
					ls = g_slice_alloc (sz);

					/* Handle settings id */
					sid = rspamd_mempool_get_variable (task->task_pool,
							"settings_hash");

					if (sid) {
						ls->settings_id = *sid;
					}
					else {
						ls->settings_id = 0;
					}

					ls->score = mres->score;
					ls->required_score = rspamd_task_get_required_score (task,
							mres);
					ls->nresults = g_hash_table_size (mres->symbols);

					g_hash_table_iter_init (&it, mres->symbols);
					i = 0;

					while (g_hash_table_iter_next (&it, &k, &v)) {
						id = rspamd_symbols_cache_find_symbol (task->cfg->cache,
								k);
						sym = v;

						if (id >= 0) {
							ls->results[i].id = id;
							ls->results[i].score = sym->score;
						}
						else {
							ls->results[i].id = -1;
							ls->results[i].score = 0.0;
						}

						i ++;
					}
				}
				else {
					sz = sizeof (*ls);
					ls = g_slice_alloc0 (sz);
					ls->nresults = 0;
				}

				/* We don't really care about return value here */
				if (write (lp->fd, ls, sz) == -1) {
					msg_info_task ("cannot write to log pipe: %s",
							strerror (errno));
				}

				g_slice_free1 (sz, ls);
				break;
			default:
				msg_err_task ("unknown log format %d", lp->type);
				break;
			}
		}
	}
}

void
rspamd_protocol_write_reply (struct rspamd_task *task)
{
	struct rspamd_http_message *msg;
	const gchar *ctype = "application/json";
	struct rspamd_abstract_worker_ctx *actx;
	rspamd_fstring_t *reply;

	msg = rspamd_http_new_message (HTTP_RESPONSE);

	if (rspamd_http_connection_is_encrypted (task->http_conn)) {
		msg_info_task ("<%s> writing encrypted reply", task->message_id);
	}

	if (!RSPAMD_TASK_IS_JSON (task)) {
		/* Turn compatibility on */
		msg->method = HTTP_SYMBOLS;
	}
	if (RSPAMD_TASK_IS_SPAMC (task)) {
		msg->flags |= RSPAMD_HTTP_FLAG_SPAMC;
	}

	msg->date = time (NULL);


	debug_task ("writing reply to client");
	if (task->err != NULL) {
		ucl_object_t *top = NULL;

		top = ucl_object_typed_new (UCL_OBJECT);
		msg->code = 500 + task->err->code % 100;
		msg->status = rspamd_fstring_new_init (task->err->message,
				strlen (task->err->message));
		ucl_object_insert_key (top, ucl_object_fromstring (task->err->message),
			"error", 0, false);
		ucl_object_insert_key (top,
			ucl_object_fromstring (g_quark_to_string (task->err->domain)),
			"error_domain", 0, false);
		reply = rspamd_fstring_sized_new (256);
		rspamd_ucl_emit_fstring (top, UCL_EMIT_JSON_COMPACT, &reply);
		ucl_object_unref (top);
		rspamd_http_message_set_body_from_fstring_steal (msg, reply);
	}
	else {
		msg->status = rspamd_fstring_new_init ("OK", 2);

		switch (task->cmd) {
		case CMD_REPORT_IFSPAM:
		case CMD_REPORT:
		case CMD_CHECK:
		case CMD_SYMBOLS:
		case CMD_PROCESS:
		case CMD_SKIP:
			rspamd_protocol_http_reply (msg, task);

			if (task->worker && task->worker->ctx) {
				actx = task->worker->ctx;

				if (actx->magic == rspamd_worker_magic) {
					rspamd_protocol_write_log_pipe (task->worker->ctx, task);
				}
			}
			break;
		case CMD_PING:
			rspamd_http_message_set_body (msg, "pong" CRLF, 6);
			ctype = "text/plain";
			break;
		case CMD_OTHER:
			msg_err_task ("BROKEN");
			break;
		}
	}

	rspamd_http_connection_reset (task->http_conn);
	rspamd_http_connection_write_message (task->http_conn, msg, NULL,
		ctype, task, task->sock, &task->tv, task->ev_base);

	task->processed_stages |= RSPAMD_TASK_STAGE_REPLIED;
}
