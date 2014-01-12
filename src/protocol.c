/*
 * Copyright (c) 2009-2012, Vsevolod Stakhov
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
#include "main.h"
#include "util.h"
#include "cfg_file.h"
#include "settings.h"
#include "message.h"

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
#define STATFILE_HEADER "Statfile"
#define QUEUE_ID_HEADER "Queue-ID"
#define ERROR_HEADER "Error"
#define USER_HEADER "User"
#define PASS_HEADER "Pass"
#define JSON_HEADER "Json"
#define HOSTNAME_HEADER "Hostname"
#define DELIVER_TO_HEADER "Deliver-To"

static GList                   *custom_commands = NULL;

/* XXX: remove this legacy sometimes */
static const gchar *
str_action_metric_spamc (enum rspamd_metric_action action)
{
	switch (action) {
	case METRIC_ACTION_REJECT:
		return "reject";
	case METRIC_ACTION_SOFT_REJECT:
		return "soft reject";
	case METRIC_ACTION_REWRITE_SUBJECT:
		return "rewrite subject";
	case METRIC_ACTION_ADD_HEADER:
		return "add header";
	case METRIC_ACTION_GREYLIST:
		return "greylist";
	case METRIC_ACTION_NOACTION:
		return "no action";
	case METRIC_ACTION_MAX:
		return "invalid max action";
	}

	return "unknown action";
}

static inline const gchar *
rspamc_proto_str (guint ver)
{

	if (G_LIKELY (ver == 12)) {
		return "1.2";
	}
	else if (G_UNLIKELY (ver == 11)) {
		return "1.1";
	}
	else if (G_UNLIKELY (ver == 13)) {
		return "1.3";
	}
	else if (G_UNLIKELY (ver == 14)) {
		return "1.4";
	}
	else if (G_UNLIKELY (ver == 15)) {
		return "1.5";
	}
	else {
		return "1.0";
	}
}

gchar                    *
separate_command (f_str_t * in, gchar c)
{
	guint                            r = 0;
	gchar                           *p = in->begin, *b;
	b = p;

	while (r < in->len) {
		if (*p == c) {
			*p = '\0';
			in->begin = p + 1;
			in->len -= r + 1;
			return b;
		}
		else if (*p == '\0') {
			/* Actually we cannot allow several \0 characters in string, so write to the log about it */
			msg_warn ("cannot separate command with \0 character, this can be an attack attempt");
			return NULL;
		}
		p++;
		r++;
	}

	return NULL;
}

static gboolean
parse_check_command (struct worker_task *task, gchar *token)
{
	GList                          *cur;
	struct custom_command          *cmd;

	switch (token[0]) {
	case 'c':
	case 'C':
		/* check */
		if (g_ascii_strcasecmp (token + 1, MSG_CMD_CHECK + 1) == 0) {
			task->cmd = CMD_CHECK;
		}
		else {
			debug_task ("bad command: %s", token);
			return FALSE;
		}
		break;
	case 's':
	case 'S':
		/* symbols, skip */
		if (g_ascii_strcasecmp (token + 1, MSG_CMD_SYMBOLS + 1) == 0) {
			task->cmd = CMD_SYMBOLS;
		}
		else if (g_ascii_strcasecmp (token + 1, MSG_CMD_SKIP + 1) == 0) {
			task->cmd = CMD_SKIP;
		}
		else {
			debug_task ("bad command: %s", token);
			return FALSE;
		}
		break;
	case 'p':
	case 'P':
		/* ping, process */
		if (g_ascii_strcasecmp (token + 1, MSG_CMD_PING + 1) == 0) {
			task->cmd = CMD_PING;
		}
		else if (g_ascii_strcasecmp (token + 1, MSG_CMD_PROCESS + 1) == 0) {
			task->cmd = CMD_PROCESS;
		}
		else {
			debug_task ("bad command: %s", token);
			return FALSE;
		}
		break;
	case 'r':
	case 'R':
		/* report, report_ifspam */
		if (g_ascii_strcasecmp (token + 1, MSG_CMD_REPORT + 1) == 0) {
			task->cmd = CMD_REPORT;
		}
		else if (g_ascii_strcasecmp (token + 1, MSG_CMD_REPORT_IFSPAM + 1) == 0) {
			task->cmd = CMD_REPORT_IFSPAM;
		}
		else {
			debug_task ("bad command: %s", token);
			return FALSE;
		}
		break;
	case 'l':
	case 'L':
		if (g_ascii_strcasecmp (token + 1, MSG_CMD_LEARN + 1) == 0) {
			if (task->allow_learn) {
				task->cmd = CMD_LEARN;
			}
			else {
				msg_info ("learning is disabled");
				return FALSE;
			}
		}
		else {
			debug_task ("bad command: %s", token);
			return FALSE;
		}
		break;
	default:
		cur = custom_commands;
		while (cur) {
			cmd = cur->data;
			if (g_ascii_strcasecmp (token, cmd->name) == 0) {
				task->cmd = CMD_OTHER;
				task->custom_cmd = cmd;
				break;
			}
			cur = g_list_next (cur);
		}

		if (cur == NULL) {
			debug_task ("bad command: %s", token);
			return FALSE;
		}
		break;
	}

	return TRUE;
}

static gboolean
parse_rspamc_command (struct worker_task *task, f_str_t * line)
{
	gchar                          *token;

	/* Separate line */
	token = separate_command (line, ' ');
	if (line == NULL || token == NULL) {
		debug_task ("bad command");
		return FALSE;
	}

	if (!parse_check_command (task, token)) {
		return FALSE;
	}

	if (g_ascii_strncasecmp (line->begin, RSPAMC_GREETING, sizeof (RSPAMC_GREETING) - 1) == 0) {
		task->proto = RSPAMC_PROTO;
		task->proto_ver = 10;
		if (*(line->begin + sizeof (RSPAMC_GREETING) - 1) == '/') {
			/* Extract protocol version */
			token = line->begin + sizeof (RSPAMC_GREETING);
			if (strncmp (token, RSPAMC_PROTO_1_1, sizeof (RSPAMC_PROTO_1_1) - 1) == 0) {
				task->proto_ver = 11;
			}
			else if (strncmp (token, RSPAMC_PROTO_1_2, sizeof (RSPAMC_PROTO_1_2) - 1) == 0) {
				task->proto_ver = 12;
			}
			else if (strncmp (token, RSPAMC_PROTO_1_3, sizeof (RSPAMC_PROTO_1_3) - 1) == 0) {
				task->proto_ver = 13;
			}
		}
	}
	else if (g_ascii_strncasecmp (line->begin, SPAMC_GREETING, sizeof (SPAMC_GREETING) - 1) == 0) {
		task->proto = SPAMC_PROTO;
		task->proto_ver = 12;
	}
	else {
		return FALSE;
	}

	task->state = READ_HEADER;

	return TRUE;
}

static gboolean
parse_http_command (struct worker_task *task, f_str_t * line)
{
	guint8                         *p, *end, *c;
	gint                            state = 0, next_state = 0;
	gchar                          *cmd;

	p = line->begin;
	c = p;
	end = p + line->len;
	task->proto = RSPAMC_PROTO;

	while (p < end) {
		switch (state) {
		case 0:
			/* Expect GET or POST here */
			if ((end - p > 3 &&
					(*p == 'G' || *p == 'g') &&
					(p[1] == 'E' || p[1] == 'e') &&
					(p[2] == 'T' || p[2] == 't')) ||
					(end - p > 4 &&
					(*p == 'P' || *p == 'p') &&
					(p[1] == 'O' || p[1] == 'o') &&
					(p[2] == 'S' || p[2] == 's') &&
					(p[3] == 'T' || p[3] == 't'))) {
				state = 99;
				next_state = 1;
				p += (*p == 'g' || *p == 'G') ? 3 : 4;
			}
			else {
				msg_info ("invalid HTTP request: %V", line);
				return FALSE;
			}
			break;
		case 1:
			/* Get command or path */
			if (!g_ascii_isspace (*p)) {
				p ++;
			}
			else {
				/* Copy command */
				cmd = memory_pool_alloc (task->task_pool, p - c + 1);
				rspamd_strlcpy (cmd, c, p - c + 1);
				/* Skip the first '/' */
				if (*cmd == '/') {
					cmd ++;
				}
				if (!parse_check_command (task, cmd)) {
					/* Assume that command is symbols */
					task->cmd = CMD_SYMBOLS;
				}
				state = 99;
				next_state = 2;
			}
			break;
		case 2:
			/* Get HTTP/1.0 or HTTP/1.1 */
			if (p == end - 1) {
				/* We are at the end */
				if (g_ascii_strncasecmp (c, "HTTP/1.0", sizeof ("HTTP/1.0") - 1) == 0 ||
						g_ascii_strncasecmp (c, "HTTP/1.1", sizeof ("HTTP/1.1") - 1) == 0) {
					task->state = READ_HEADER;
					return TRUE;
				}
			}
			else {
				p ++;
			}
			break;
		case 99:
			/* Skip spaces */
			if (g_ascii_isspace (*p)) {
				p ++;
			}
			else {
				state = next_state;
				c = p;
			}
			break;
		}
	}

	return FALSE;
}

static gboolean
parse_command (struct worker_task *task, f_str_t * line)
{
	task->proto_ver = 11;

	if (! task->is_http) {
		return parse_rspamc_command (task, line);
	}
	else {
		return parse_http_command (task, line);
	}
	
	/* Unreached */
	return FALSE;
}

static gboolean
parse_header (struct worker_task *task, f_str_t * line)
{
	gchar                           *headern, *err, *tmp;
	gboolean                         res = TRUE;

	/* Check end of headers */
	if (line->len == 0) {
		debug_task ("got empty line, assume it as end of headers");
		if (task->cmd == CMD_PING || task->cmd == CMD_SKIP) {
			task->state = WRITE_REPLY;
		}
		else {
			if (task->content_length > 0) {
				if (task->cmd == CMD_LEARN) {
					if (task->statfile != NULL) {
						rspamd_set_dispatcher_policy (task->dispatcher, BUFFER_CHARACTER, task->content_length);
						task->state = READ_MESSAGE;
					}
					else {
						task->last_error = "Unknown statfile";
						task->error_code = RSPAMD_STATFILE_ERROR;
						task->state = WRITE_ERROR;
						return FALSE;
					}
				}
				else {
					rspamd_set_dispatcher_policy (task->dispatcher, BUFFER_CHARACTER, task->content_length);
					task->state = READ_MESSAGE;
					task->msg = memory_pool_alloc0 (task->task_pool, sizeof (f_str_t));
				}
			}
			else if (task->cmd != CMD_LEARN && task->cmd != CMD_OTHER) {
				rspamd_set_dispatcher_policy (task->dispatcher, BUFFER_ANY, 0);
				task->state = READ_MESSAGE;
				task->msg = memory_pool_alloc0 (task->task_pool, sizeof (f_str_t));
			}
			else {
				task->last_error = "Unknown content length";
				task->error_code = RSPAMD_LENGTH_ERROR;
				task->state = WRITE_ERROR;
				return FALSE;
			}
		}
		return TRUE;
	}

	headern = separate_command (line, ':');

	if (line == NULL || headern == NULL) {
		return FALSE;
	}
	/* Eat whitespaces */
	g_strstrip (headern);
	fstrstrip (line);

	switch (headern[0]) {
	case 'c':
	case 'C':
		/* content-length */
		if (g_ascii_strncasecmp (headern, CONTENT_LENGTH_HEADER, sizeof (CONTENT_LENGTH_HEADER) - 1) == 0) {
			if (task->content_length == 0) {
				tmp = memory_pool_fstrdup (task->task_pool, line);
				task->content_length = strtoul (tmp, &err, 10);
				debug_task ("read Content-Length header, value: %ul", (guint32)task->content_length);
			}
		}
		else {
			msg_info ("wrong header: %s", headern);
			res = FALSE;
		}
		break;
	case 'd':
	case 'D':
		/* Deliver-To */
		if (g_ascii_strncasecmp (headern, DELIVER_TO_HEADER, sizeof (DELIVER_TO_HEADER) - 1) == 0) {
			task->deliver_to = escape_braces_addr_fstr (task->task_pool, line);
			debug_task ("read deliver-to header, value: %s", task->deliver_to);
		}
		else {
			msg_info ("wrong header: %s", headern);
			res = FALSE;
		}
		break;
	case 'h':
	case 'H':
		/* helo */
		if (g_ascii_strncasecmp (headern, HELO_HEADER, sizeof (HELO_HEADER) - 1) == 0) {
			task->helo = memory_pool_fstrdup (task->task_pool, line);
			debug_task ("read helo header, value: %s", task->helo);
		}
		else if (g_ascii_strncasecmp (headern, HOSTNAME_HEADER, sizeof (HOSTNAME_HEADER) - 1) == 0) {
			task->hostname = memory_pool_fstrdup (task->task_pool, line);
			debug_task ("read hostname header, value: %s", task->hostname);
		}
		else {
			msg_info ("wrong header: %s", headern);
			res = FALSE;
		}
		break;
	case 'f':
	case 'F':
		/* from */
		if (g_ascii_strncasecmp (headern, FROM_HEADER, sizeof (FROM_HEADER) - 1) == 0) {
			task->from = escape_braces_addr_fstr (task->task_pool, line);
			debug_task ("read from header, value: %s", task->from);
		}
		else {
			msg_info ("wrong header: %s", headern);
			res = FALSE;
		}
		break;
	case 'j':
	case 'J':
		/* json */
		if (g_ascii_strncasecmp (headern, JSON_HEADER, sizeof (JSON_HEADER) - 1) == 0) {
			task->is_json = parse_flag (memory_pool_fstrdup (task->task_pool, line));
		}
		else {
			msg_info ("wrong header: %s", headern);
			res = FALSE;
		}
		break;
	case 'q':
	case 'Q':
		/* Queue id */
		if (g_ascii_strncasecmp (headern, QUEUE_ID_HEADER, sizeof (QUEUE_ID_HEADER) - 1) == 0) {
			task->queue_id = memory_pool_fstrdup (task->task_pool, line);
			debug_task ("read queue_id header, value: %s", task->queue_id);
		}
		else {
			msg_info ("wrong header: %s", headern);
			res = FALSE;
		}
		break;
	case 'r':
	case 'R':
		/* rcpt */
		if (g_ascii_strncasecmp (headern, RCPT_HEADER, sizeof (RCPT_HEADER) - 1) == 0) {
			tmp = escape_braces_addr_fstr (task->task_pool, line);
			task->rcpt = g_list_prepend (task->rcpt, tmp);
			debug_task ("read rcpt header, value: %s", tmp);
		}
		else if (g_ascii_strncasecmp (headern, NRCPT_HEADER, sizeof (NRCPT_HEADER) - 1) == 0) {
			tmp = memory_pool_fstrdup (task->task_pool, line);
			task->nrcpt = strtoul (tmp, &err, 10);
			debug_task ("read rcpt header, value: %d", (gint)task->nrcpt);
		}
		else {
			msg_info ("wrong header: %s", headern);
			res = FALSE;
		}
		break;
	case 'i':
	case 'I':
		/* ip_addr */
		if (g_ascii_strncasecmp (headern, IP_ADDR_HEADER, sizeof (IP_ADDR_HEADER) - 1) == 0) {
			tmp = memory_pool_fstrdup (task->task_pool, line);
#ifdef HAVE_INET_PTON
			if (g_ascii_strncasecmp (tmp, "IPv6:", 5) == 0) {
				if (inet_pton (AF_INET6, tmp + 6, &task->from_addr.d.in6) == 1) {
					task->from_addr.ipv6 = TRUE;
				}
				else {
					msg_err ("bad ip header: '%s'", tmp);
					return FALSE;
				}
				task->from_addr.has_addr = TRUE;
			}
			else {
				if (inet_pton (AF_INET, tmp, &task->from_addr.d.in4) != 1) {
					/* Try ipv6 */
					if (inet_pton (AF_INET6, tmp, &task->from_addr.d.in6) == 1) {
						task->from_addr.ipv6 = TRUE;
					}
					else {
						msg_err ("bad ip header: '%s'", tmp);
						return FALSE;
					}
				}
				else {
					task->from_addr.ipv6 = FALSE;
				}
				task->from_addr.has_addr = TRUE;
			}
#else
			if (!inet_aton (tmp, &task->from_addr)) {
				msg_err ("bad ip header: '%s'", tmp);
				return FALSE;
			}
#endif
			debug_task ("read IP header, value: %s", tmp);
		}
		else {
			msg_info ("wrong header: %s", headern);
			res = FALSE;
		}
		break;
	case 'p':
	case 'P':
		/* Pass header */
		if (g_ascii_strncasecmp (headern, PASS_HEADER, sizeof (PASS_HEADER) - 1) == 0) {
			if (line->len == sizeof ("all") - 1 && g_ascii_strncasecmp (line->begin, "all", sizeof ("all") - 1) == 0) {
				task->pass_all_filters = TRUE;
				msg_info ("pass all filters");
			} 
		}
		else {
			res = FALSE;
		}
		break;
	case 's':
	case 'S':
		if (g_ascii_strncasecmp (headern, SUBJECT_HEADER, sizeof (SUBJECT_HEADER) - 1) == 0) {
			task->subject = memory_pool_fstrdup (task->task_pool, line);
		}
		else if (g_ascii_strncasecmp (headern, STATFILE_HEADER, sizeof (STATFILE_HEADER) - 1) == 0) {
			task->statfile = memory_pool_fstrdup (task->task_pool, line);
		}
		else {
			res = FALSE;
		}
		break;
	case 'u':
	case 'U':
		if (g_ascii_strncasecmp (headern, USER_HEADER, sizeof (USER_HEADER) - 1) == 0) {
			task->user = memory_pool_fstrdup (task->task_pool, line);
		}
		else {
			res = FALSE;
		}
		break;
	default:
		msg_info ("wrong header: %s", headern);
		res = FALSE;
		break;
	}

	if (!res && task->cfg->strict_protocol_headers) {
		msg_err ("deny processing of a request with incorrect or unknown headers");
		return FALSE;
	}

	return TRUE;
}

gboolean
read_rspamd_input_line (struct worker_task *task, f_str_t * line)
{
	switch (task->state) {
	case READ_COMMAND:
		return parse_command (task, line);
		break;
	case READ_HEADER:
		return parse_header (task, line);
		break;
	default:
		return FALSE;
	}
	return FALSE;
}

static void
write_hashes_to_log (struct worker_task *task, GString *logbuf)
{
	GList                          *cur;
	struct mime_text_part          *text_part;
	
	cur = task->text_parts;

	while (cur) {
		text_part = cur->data;
		if (text_part->fuzzy) {
			if (cur->next != NULL) {
				rspamd_printf_gstring (logbuf, " part: %Xd,", text_part->fuzzy->h);
			}
			else {
				rspamd_printf_gstring (logbuf, " part: %Xd", text_part->fuzzy->h);
			}
		}
		cur = g_list_next (cur);
	}
}


/* Structure for writing tree data */
struct tree_cb_data {
	GString *urls;
	struct worker_task *task;
};

/*
 * Callback for writing urls
 */
static gboolean
urls_protocol_cb (gpointer key, gpointer value, gpointer ud)
{
	struct tree_cb_data             *cb = ud;
	struct uri                      *url = value;

	rspamd_printf_gstring (cb->urls, " %*s,", url->hostlen, url->host);

	if (cb->task->cfg->log_urls) {
		msg_info ("<%s> URL: %s - %s: %s", cb->task->message_id, cb->task->user ?
				cb->task->user : (cb->task->from ? cb->task->from : "unknown"),
				inet_ntoa (cb->task->client_addr), struri (url));
	}

	return FALSE;
}

static ucl_object_t *
rspamd_urls_tree_ucl (GTree *input, struct worker_task *task)
{
	struct tree_cb_data             cb;
	ucl_object_t                    *obj;

	cb.urls = g_string_sized_new (BUFSIZ);
	cb.task = task;

	g_tree_foreach (input, urls_protocol_cb, &cb);
	/* Strip last ',' */
	if (cb.urls->str[cb.urls->len - 1] == ',') {
		cb.urls->len --;
	}

	obj = ucl_object_fromlstring (cb.urls->str, cb.urls->len);
	g_string_free (cb.urls, TRUE);
	return obj;
}


/* Write new subject */
static const gchar *
make_rewritten_subject (struct metric *metric, struct worker_task *task)
{
	static gchar                    subj_buf[1024];
	gchar                          *p = subj_buf, *end, *c, *res;
	const gchar                    *s;

	end = p + sizeof(subj_buf);
	c = metric->subject;
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
			*p = *c ++;
		}
		p ++;
	}
	res = g_mime_utils_header_encode_text (subj_buf);

	memory_pool_add_destructor (task->task_pool, (pool_destruct_func)g_free, res);

	return res;
}

static ucl_object_t *
rspamd_str_list_ucl (GList *str_list)
{
	ucl_object_t                    *top = NULL, *obj;
	GList                           *cur;

	top = ucl_object_typed_new (UCL_ARRAY);
	cur = str_list;
	while (cur) {
		obj = ucl_object_fromstring (cur->data);
		DL_APPEND (top->value.av, obj);
		cur = g_list_next (cur);
	}

	return top;
}

static ucl_object_t *
rspamd_metric_symbol_ucl (struct worker_task *task, struct metric *m,
		struct symbol *sym, GString *logbuf)
{
	ucl_object_t                    *obj = NULL;
	const gchar                     *description = NULL;

	rspamd_printf_gstring (logbuf, "%s,", sym->name);
	description = g_hash_table_lookup (m->descriptions, sym->name);

	obj = ucl_object_insert_key (obj, ucl_object_fromstring (sym->name), "name", 0, false);
	if (description) {
		obj = ucl_object_insert_key (obj, ucl_object_fromstring (description), "description", 0, false);
	}
	if (sym->options != NULL) {
		obj = ucl_object_insert_key (obj, rspamd_str_list_ucl (sym->options), "options", 0, false);
	}

	return obj;
}

static ucl_object_t *
rspamd_metric_result_ucl (struct worker_task *task, struct metric_result *mres, GString *logbuf)
{
	GHashTableIter                   hiter;
	struct symbol                  *sym;
	struct metric                  *m;
	gboolean                         is_spam;
	enum rspamd_metric_action        action = METRIC_ACTION_NOACTION;
	ucl_object_t                    *obj = NULL, *sobj;
	gdouble                          required_score;
	gpointer                         h, v;
	const gchar                     *subject;
	gchar                            action_char;

	m = mres->metric;

	/* XXX: handle settings */
	required_score = m->actions[METRIC_ACTION_REJECT].score;
	is_spam = (mres->score >= required_score);
	action = check_metric_action (mres->score, required_score, m);
	if (task->is_skipped) {
		action_char = 'S';
	}
	else if (is_spam) {
		action_char = 'T';
	}
	else {
		action_char = 'F';
	}
	rspamd_printf_gstring (logbuf, "(%s: %c (%s): [%.2f/%.2f] [",
			m->name, action_char,
			str_action_metric (action),
			mres->score, required_score);

	obj = ucl_object_insert_key (obj, ucl_object_frombool (is_spam), "is_spam", 0, false);
	obj = ucl_object_insert_key (obj, ucl_object_frombool (task->is_skipped), "is_skipped", 0, false);
	obj = ucl_object_insert_key (obj, ucl_object_fromdouble (mres->score), "score", 0, false);
	obj = ucl_object_insert_key (obj, ucl_object_fromdouble (required_score), "required_score", 0, false);
	obj = ucl_object_insert_key (obj, ucl_object_fromstring (str_action_metric (action)),
			"action", 0, false);

	if (action == METRIC_ACTION_REWRITE_SUBJECT) {
		subject = make_rewritten_subject (m, task);
		obj = ucl_object_insert_key (obj, ucl_object_fromstring (subject),
					"subject", 0, false);
	}
	/* Now handle symbols */
	g_hash_table_iter_init (&hiter, mres->symbols);
	while (g_hash_table_iter_next (&hiter, &h, &v)) {
		sym = (struct symbol *)v;
		sobj = rspamd_metric_symbol_ucl (task, m, sym, logbuf);
		obj = ucl_object_insert_key (obj, sobj, h, 0, false);
	}

	/* Cut the trailing comma if needed */
	if (logbuf->str[logbuf->len - 1] == ',') {
		logbuf->len --;
	}
	rspamd_printf_gstring (logbuf, "]), ");

	return obj;
}

static gboolean
write_check_reply (struct worker_task *task)
{
	GString                         *logbuf;
	struct metric_result           *metric_res;
	GHashTableIter                   hiter;
	gpointer                         h, v;
	ucl_object_t                    *top = NULL, *obj;

	/* Output the first line - check status */

	logbuf = g_string_sized_new (BUFSIZ);
	rspamd_printf_gstring (logbuf, "id: <%s>, qid: <%s>, ", task->message_id, task->queue_id);

	if (task->user) {
		rspamd_printf_gstring (logbuf, "user: %s, ", task->user);
	}

	rspamd_roll_history_update (task->worker->srv->history, task);
	g_hash_table_iter_init (&hiter, task->results);

	/* Convert results to an ucl object */
	while (g_hash_table_iter_next (&hiter, &h, &v)) {
		metric_res = (struct metric_result *)v;
		obj = rspamd_metric_result_ucl (task, metric_res, logbuf);
		top = ucl_object_insert_key (top, obj, h, 0, false);
	}

	if (task->messages != NULL) {
		top = ucl_object_insert_key (top, rspamd_str_list_ucl (task->messages), "messages", 0, false);
	}
	if (g_tree_nnodes (task->urls) > 0) {
		top = ucl_object_insert_key (top, rspamd_urls_tree_ucl (task->urls, task), "urls", 0, false);
	}
	if (g_tree_nnodes (task->emails) > 0) {
		top = ucl_object_insert_key (top, rspamd_urls_tree_ucl (task->emails, task), "emails", 0, false);
	}
	
	top = ucl_object_insert_key (top, ucl_object_fromstring (task->message_id), "message-id", 0, false);

	write_hashes_to_log (task, logbuf);
	msg_info ("%v", logbuf);

	/* Increase counters */
	task->worker->srv->stat->messages_scanned++;

	return TRUE;
}

gboolean
write_reply (struct worker_task *task)
{
	gint                            r;
	gchar                           outbuf[OUTBUFSIZ];

	debug_task ("writing reply to client");
	if (task->error_code != 0) {
		/* Write error message and error code to reply */
		if (task->is_http) {
			r = rspamd_snprintf (outbuf, sizeof (outbuf), "HTTP/1.0 400 Bad request" CRLF
					"Connection: close" CRLF CRLF "Error: %d - %s" CRLF, task->error_code, task->last_error);
		}
		else {
			if (task->proto == SPAMC_PROTO) {
				r = rspamd_snprintf (outbuf, sizeof (outbuf), "%s/%s %d %s" CRLF CRLF,
						SPAMD_REPLY_BANNER, rspamc_proto_str (task->proto_ver), task->error_code, SPAMD_ERROR);
				debug_task ("writing error: %s", outbuf);
			}
			else {
				r = rspamd_snprintf (outbuf, sizeof (outbuf), "%s/%s %d %s" CRLF "%s: %s" CRLF CRLF,
						RSPAMD_REPLY_BANNER, rspamc_proto_str (task->proto_ver), task->error_code, SPAMD_ERROR, ERROR_HEADER, task->last_error);
				debug_task ("writing error: %s", outbuf);
			}
		}
		/* Write to bufferevent error message */
		return rspamd_dispatcher_write (task->dispatcher, outbuf, r, FALSE, FALSE);
	}
	else {
		switch (task->cmd) {
		case CMD_REPORT_IFSPAM:
		case CMD_REPORT:
		case CMD_CHECK:
		case CMD_SYMBOLS:
		case CMD_PROCESS:
			return write_check_reply (task);
			break;
		case CMD_SKIP:
			r = rspamd_snprintf (outbuf, sizeof (outbuf), "%s/%s 0 %s" CRLF, 
					(task->proto == SPAMC_PROTO) ? SPAMD_REPLY_BANNER : RSPAMD_REPLY_BANNER, rspamc_proto_str (task->proto_ver), SPAMD_OK);
			return rspamd_dispatcher_write (task->dispatcher, outbuf, r, FALSE, FALSE);
			break;
		case CMD_PING:
			r = rspamd_snprintf (outbuf, sizeof (outbuf), "%s/%s 0 PONG" CRLF, 
					(task->proto == SPAMC_PROTO) ? SPAMD_REPLY_BANNER : RSPAMD_REPLY_BANNER, rspamc_proto_str (task->proto_ver));
			return rspamd_dispatcher_write (task->dispatcher, outbuf, r, FALSE, FALSE);
			break;
		case CMD_LEARN:
			if (task->is_http) {
				r = rspamd_snprintf (outbuf, sizeof (outbuf), "HTTP/1.0 200 Ok" CRLF
									"Connection: close" CRLF CRLF "%s" CRLF, task->last_error);
			}
			else {
				r = rspamd_snprintf (outbuf, sizeof (outbuf), "%s/%s 0 LEARN" CRLF CRLF "%s" CRLF,
						(task->proto == SPAMC_PROTO) ? SPAMD_REPLY_BANNER : RSPAMD_REPLY_BANNER,
						rspamc_proto_str (task->proto_ver),
						task->last_error);
			}
			return rspamd_dispatcher_write (task->dispatcher, outbuf, r, FALSE, FALSE);
			break;
		case CMD_OTHER:
			return task->custom_cmd->func (task);
		}
	}

	return FALSE;
}

void
register_protocol_command (const gchar *name, protocol_reply_func func)
{
	struct custom_command          *cmd;

	cmd = g_malloc (sizeof (struct custom_command));
	cmd->name = name;
	cmd->func = func;

	custom_commands = g_list_prepend (custom_commands, cmd);
}
