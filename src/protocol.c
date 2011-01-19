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
#include "main.h"
#include "util.h"
#include "cfg_file.h"
#include "settings.h"
#include "message.h"

/* Max line size as it is defined in rfc2822 */
#define OUTBUFSIZ 1000
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
#define QUEUE_ID_HEADER "Queue-ID"
#define ERROR_HEADER "Error"
#define USER_HEADER "User"
#define PASS_HEADER "Pass"
#define DELIVER_TO_HEADER "Deliver-To"

static GList                   *custom_commands = NULL;

/* For default metric, dirty hack, but much faster than hash lookup */
static double default_score, default_required_score;

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

static gchar                    *
separate_command (f_str_t * in, gchar c)
{
	gint                            r = 0;
	gchar                           *p = in->begin, *b;
	b = p;

	while (r < in->len) {
		if (*p == c) {
			*p = '\0';
			in->begin = p + 1;
			in->len -= r + 1;
			return b;
		}
		p++;
		r++;
	}

	return NULL;
}

static gint
parse_command (struct worker_task *task, f_str_t * line)
{
	gchar                           *token;
	struct custom_command          *cmd;
	GList                          *cur;

	task->proto_ver = 11;
	token = separate_command (line, ' ');
	if (line == NULL || token == NULL) {
		debug_task ("bad command");
		return -1;
	}

	switch (token[0]) {
	case 'c':
	case 'C':
		/* check */
		if (g_ascii_strcasecmp (token + 1, MSG_CMD_CHECK + 1) == 0) {
			task->cmd = CMD_CHECK;
		}
		else {
			debug_task ("bad command: %s", token);
			return -1;
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
			return -1;
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
			return -1;
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
			return -1;
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
			return -1;
		}
		break;
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
		}
	}
	else if (g_ascii_strncasecmp (line->begin, SPAMC_GREETING, sizeof (SPAMC_GREETING) - 1) == 0) {
		task->proto = SPAMC_PROTO;
		task->proto_ver = 12;
	}
	else {
		return -1;
	}

	task->state = READ_HEADER;
	
	return 0;
}

static gint
parse_header (struct worker_task *task, f_str_t * line)
{
	gchar                           *headern, *err, *tmp;

	/* Check end of headers */
	if (line->len == 0) {
		debug_task ("got empty line, assume it as end of headers");
		if (task->cmd == CMD_PING || task->cmd == CMD_SKIP) {
			task->state = WRITE_REPLY;
		}
		else {
			if (task->content_length > 0) {
				rspamd_set_dispatcher_policy (task->dispatcher, BUFFER_CHARACTER, task->content_length);
				task->state = READ_MESSAGE;
			}
			else {
				task->last_error = "Unknown content length";
				task->error_code = RSPAMD_LENGTH_ERROR;
				task->state = WRITE_ERROR;
				return -1;
			}
		}
		return 0;
	}

	headern = separate_command (line, ':');

	if (line == NULL || headern == NULL) {
		return -1;
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
			return -1;
		}
		break;
	case 'd':
	case 'D':
		/* Deliver-To */
		if (g_ascii_strncasecmp (headern, DELIVER_TO_HEADER, sizeof (DELIVER_TO_HEADER) - 1) == 0) {
			task->deliver_to = memory_pool_fstrdup (task->task_pool, line);
			debug_task ("read deliver-to header, value: %s", task->deliver_to);
		}
		else {
			msg_info ("wrong header: %s", headern);
			return -1;
		}
		break;
	case 'h':
	case 'H':
		/* helo */
		if (g_ascii_strncasecmp (headern, HELO_HEADER, sizeof (HELO_HEADER) - 1) == 0) {
			task->helo = memory_pool_fstrdup (task->task_pool, line);
			debug_task ("read helo header, value: %s", task->helo);
		}
		else {
			msg_info ("wrong header: %s", headern);
			return -1;
		}
		break;
	case 'f':
	case 'F':
		/* from */
		if (g_ascii_strncasecmp (headern, FROM_HEADER, sizeof (FROM_HEADER) - 1) == 0) {
			task->from = memory_pool_fstrdup (task->task_pool, line);
			debug_task ("read from header, value: %s", task->from);
		}
		else {
			msg_info ("wrong header: %s", headern);
			return -1;
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
			return -1;
		}
		break;
	case 'r':
	case 'R':
		/* rcpt */
		if (g_ascii_strncasecmp (headern, RCPT_HEADER, sizeof (RCPT_HEADER) - 1) == 0) {
			tmp = memory_pool_fstrdup (task->task_pool, line);
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
			return -1;
		}
		break;
	case 'i':
	case 'I':
		/* ip_addr */
		if (g_ascii_strncasecmp (headern, IP_ADDR_HEADER, sizeof (IP_ADDR_HEADER) - 1) == 0) {
			tmp = memory_pool_fstrdup (task->task_pool, line);
			if (!inet_aton (tmp, &task->from_addr)) {
				msg_info ("bad ip header: '%s'", tmp);
				return -1;
			}
			debug_task ("read IP header, value: %s", tmp);
		}
		else {
			msg_info ("wrong header: %s", headern);
			return -1;
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
		break;
	case 's':
	case 'S':
		if (g_ascii_strncasecmp (headern, SUBJECT_HEADER, sizeof (SUBJECT_HEADER) - 1) == 0) {
			task->subject = memory_pool_fstrdup (task->task_pool, line);
		}
		else {
			return -1;
		}
		break;
	case 'u':
	case 'U':
		if (g_ascii_strncasecmp (headern, USER_HEADER, sizeof (USER_HEADER) - 1) == 0) {
			/* XXX: use this header somehow */
			task->user = memory_pool_fstrdup (task->task_pool, line);
		}
		else {
			return -1;
		}
		break;
	default:
		msg_info ("wrong header: %s", headern);
		return -1;
	}

	return 0;
}

gint
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
		return -1;
	}
	return -1;
}

struct metric_callback_data {
	struct worker_task             *task;
	gchar                           *log_buf;
	gint                            log_offset;
	gint                            log_size;
	gchar                           *symbols_buf;
	gint                            symbols_size;
	gboolean                        alive;
	gboolean                        report;
};

static void
write_hashes_to_log (struct worker_task *task, gchar *logbuf, gint offset, gint size) 
{
	GList                          *cur;
	struct mime_text_part          *text_part;
	
	cur = task->text_parts;

	while (cur && offset < size) {
		text_part = cur->data;
		if (text_part->fuzzy) {
			if (cur->next != NULL) {
				offset += rspamd_snprintf (logbuf + offset, size - offset, " part: %Xd,", text_part->fuzzy->h);
			}
			else {
				offset += rspamd_snprintf (logbuf + offset, size - offset, " part: %Xd", text_part->fuzzy->h);
			}
		}
		cur = g_list_next (cur);
	}
}

static gint
compare_url_func (gconstpointer a, gconstpointer b)
{
	const struct uri               *u1 = a, *u2 = b;

	if (u1->hostlen != u2->hostlen) {
		return u1->hostlen - u2->hostlen;
	}
	else {
		return memcmp (u1->host, u2->host, u1->hostlen);
	}
}

static gboolean
show_url_header (struct worker_task *task)
{
	gint                            r = 0;
	gchar                           outbuf[OUTBUFSIZ], c;
	struct uri                     *url;
	GList                          *cur;
	f_str_t                         host;
	GTree                          *url_tree;

	r = rspamd_snprintf (outbuf, sizeof (outbuf), "Urls: ");
	url_tree = g_tree_new (compare_url_func);
	cur = task->urls;
	while (cur) {
		url = cur->data;
        if (task->cfg->log_urls) {
            /* Write this url to log as well */
            msg_info ("url found: <%s>, score: [%.2f / %.2f]", struri (url), default_score, default_required_score);
        }
		if (g_tree_lookup (url_tree, url) == NULL && url->hostlen > 0) {
			g_tree_insert (url_tree, url, url);
			host.begin = url->host;
			host.len = url->hostlen;
			/* Skip long hosts to avoid protocol coollisions */
			if (host.len > OUTBUFSIZ) {
				cur = g_list_next (cur);
				continue;
			}
			/* Do header folding */
			if (host.len + r >= OUTBUFSIZ - 3) {
				outbuf[r++] = '\r';
				outbuf[r++] = '\n';
				outbuf[r] = ' ';
				if (! rspamd_dispatcher_write (task->dispatcher, outbuf, r, TRUE, FALSE)) {
					return FALSE;
				}
				r = 0;
			}
			/* Write url host to buf */
			if (g_list_next (cur) != NULL) {
				c = *(host.begin + host.len);
				*(host.begin + host.len) = '\0';
				debug_task ("write url: %s", host.begin);
				r += rspamd_snprintf (outbuf + r, sizeof (outbuf) - r, "%s, ", host.begin);
				*(host.begin + host.len) = c;
			}
			else {
				c = *(host.begin + host.len);
				*(host.begin + host.len) = '\0';
				debug_task ("write url: %s", host.begin);
				r += rspamd_snprintf (outbuf + r, sizeof (outbuf) - r, "%s", host.begin);
				*(host.begin + host.len) = c;
			}
		}
		cur = g_list_next (cur);
	}
	if (r == 0) {
		return TRUE;
	}
	r += rspamd_snprintf (outbuf + r, sizeof (outbuf) - r, CRLF);

	return rspamd_dispatcher_write (task->dispatcher, outbuf, r, FALSE, FALSE);
}

static void
metric_symbols_callback (gpointer key, gpointer value, void *user_data)
{
	struct metric_callback_data    *cd = (struct metric_callback_data *)user_data;
	struct worker_task             *task = cd->task;
	gint                            r = 0;
	gchar                           outbuf[OUTBUFSIZ];
	struct symbol                  *s = (struct symbol *)value;
	GList                          *cur;

	if (! cd->alive) {
		return;
	}
	if (cd->task->cmd == CMD_SYMBOLS) {
		if (s->options) {
			if (task->proto_ver >= 12) {
				r = rspamd_snprintf (outbuf, OUTBUFSIZ, "Symbol: %s(%.2f); ", (gchar *)key, s->score);
			}
			else {
				r = rspamd_snprintf (outbuf, OUTBUFSIZ, "Symbol: %s; ", (gchar *)key);
			}
			cur = s->options;
			while (cur) {
				if (g_list_next (cur)) {
					r += rspamd_snprintf (outbuf + r, OUTBUFSIZ - r, "%s,", (gchar *)cur->data);
				}
				else {
					r += rspamd_snprintf (outbuf + r, OUTBUFSIZ - r, "%s" CRLF, (gchar *)cur->data);
				}
				cur = g_list_next (cur);
			}
			/* End line with CRLF strictly */
			if (r >= OUTBUFSIZ - 1) {
				outbuf[OUTBUFSIZ - 2] = '\r';
				outbuf[OUTBUFSIZ - 1] = '\n';
			}
		}
		else {
			if (task->proto_ver >= 12) {
				r = rspamd_snprintf (outbuf, OUTBUFSIZ, "Symbol: %s(%.2f)" CRLF, (gchar *)key, s->score);
			}
			else {
				r = rspamd_snprintf (outbuf, OUTBUFSIZ, "Symbol: %s" CRLF, (gchar *)key);
			}
		}
		if (! rspamd_dispatcher_write (task->dispatcher, outbuf, r, FALSE, FALSE)) {
			cd->alive = FALSE;
		}
	}
	cd->log_offset += rspamd_snprintf (cd->log_buf + cd->log_offset, cd->log_size - cd->log_offset, "%s,", (gchar *)key);
}

static gboolean
show_metric_symbols (struct metric_result *metric_res, struct metric_callback_data *cd)
{
	gint                            r = 0;
	GList                          *symbols, *cur;

	if (cd->task->proto == SPAMC_PROTO) {
		symbols = g_hash_table_get_keys (metric_res->symbols);
		cur = symbols;
		while (cur) {
			if (g_list_next (cur) != NULL) {
				if (cd->task->cmd == CMD_SYMBOLS) {
					r += rspamd_snprintf (cd->symbols_buf + r, cd->symbols_size - r, "%s,", (gchar *)cur->data);
				}
				cd->log_offset += rspamd_snprintf (cd->log_buf + cd->log_offset, cd->log_size - cd->log_offset,
						"%s,", (gchar *)cur->data);
			}
			else {
				if (cd->task->cmd == CMD_SYMBOLS) {
					r += rspamd_snprintf (cd->symbols_buf + r, cd->symbols_size - r, "%s" CRLF, (gchar *)cur->data);
				}
				cd->log_offset += rspamd_snprintf (cd->log_buf + cd->log_offset, cd->log_size - cd->log_offset,
						"%s", (gchar *)cur->data);
			}
			cur = g_list_next (cur);
		}
		g_list_free (symbols);
	}
	else {
		g_hash_table_foreach (metric_res->symbols, metric_symbols_callback, cd);
		/* Remove last , from log buf */
		if (cd->log_buf[cd->log_offset - 1] == ',') {
			cd->log_buf[--cd->log_offset] = '\0';
		}
	}

	return TRUE;
}

static void
show_metric_result (gpointer metric_name, gpointer metric_value, void *user_data)
{
	struct metric_callback_data    *cd = (struct metric_callback_data *)user_data;
	struct worker_task             *task = cd->task;
	gint                            r = 0;
	gchar                           outbuf[OUTBUFSIZ];
	struct metric_result           *metric_res = (struct metric_result *)metric_value;
	struct metric                  *m;
	gint                            is_spam = 0;
	double                          ms = 0, rs = 0;
	enum rspamd_metric_action       action = METRIC_ACTION_NOACTION;

	if (! cd->alive) {
		return;
	}
	if (metric_name == NULL || metric_value == NULL) {
		m = g_hash_table_lookup (task->cfg->metrics, DEFAULT_METRIC);
        default_required_score = m->required_score;
        default_score = 0;
		if (!check_metric_settings (task, m, &ms, &rs)) {
			ms = m->required_score;
			rs = m->reject_score;
		}
		if (task->proto == SPAMC_PROTO) {
			r = rspamd_snprintf (outbuf, sizeof (outbuf), "Spam: False ; 0 / %.2f" CRLF, ms);
		}
		else {
			if (task->proto_ver >= 11) {
                if (!task->is_skipped) {
				    r = rspamd_snprintf (outbuf, sizeof (outbuf), "Metric: default; False; 0 / %.2f / %.2f" CRLF, ms, rs);
                }
                else {
				    r = rspamd_snprintf (outbuf, sizeof (outbuf), "Metric: default; Skip; 0 / %.2f / %.2f" CRLF, ms, rs);
                }
			}
			else {
				r = rspamd_snprintf (outbuf, sizeof (outbuf), "Metric: default; False; 0 / %.2f" CRLF, ms);
			}
			r += rspamd_snprintf (outbuf + r, sizeof (outbuf) - r, "Action: %s" CRLF, str_action_metric (METRIC_ACTION_NOACTION));
		}
        if (!task->is_skipped) {
		    cd->log_offset += rspamd_snprintf (cd->log_buf + cd->log_offset, cd->log_size - cd->log_offset, "(%s: F (no action): [0/%.2f/%.2f] [", "default", ms, rs);
        }
        else {
		    cd->log_offset += rspamd_snprintf (cd->log_buf + cd->log_offset, cd->log_size - cd->log_offset, "(%s: S: [0/%.2f/%.2f] [", "default", ms, rs);
        }
	}
	else {
        /* XXX: dirty hack */
        if (strcmp (metric_res->metric->name, DEFAULT_METRIC) == 0) {
            default_required_score = metric_res->metric->required_score;
            default_score = metric_res->score;
        }

		if (!check_metric_settings (task, metric_res->metric, &ms, &rs)) {
			ms = metric_res->metric->required_score;
			rs = metric_res->metric->reject_score;
		}
		if (! check_metric_action_settings (task, metric_res->metric, metric_res->score, &action)) {
			action = check_metric_action (metric_res->score, ms, metric_res->metric);
		}

		if (metric_res->score >= ms) {
			is_spam = 1;
		}

		if (task->proto == SPAMC_PROTO) {
			if (task->cmd != CMD_REPORT_IFSPAM || is_spam) {
				r = rspamd_snprintf (outbuf, sizeof (outbuf), "Spam: %s ; %.2f / %.2f" CRLF, (is_spam) ? "True" : "False", metric_res->score, ms);
			}
		}
		else {
			if (task->proto_ver >= 11) {
                if (!task->is_skipped) {
				    r = rspamd_snprintf (outbuf, sizeof (outbuf), "Metric: %s; %s; %.2f / %.2f / %.2f" CRLF, 
						(gchar *)metric_name, (is_spam) ? "True" : "False", metric_res->score, ms, rs);
                }
                else {
				    r = rspamd_snprintf (outbuf, sizeof (outbuf), "Metric: %s; Skip; %.2f / %.2f / %.2f" CRLF, 
						(gchar *)metric_name, metric_res->score, ms, rs);
                }
			}
			else {
				r = rspamd_snprintf (outbuf, sizeof (outbuf), "Metric: %s; %s; %.2f / %.2f" CRLF, 
						(gchar *)metric_name, (is_spam) ? "True" : "False", metric_res->score, ms);
			}
			r += rspamd_snprintf (outbuf + r, sizeof (outbuf) - r, "Action: %s" CRLF, str_action_metric(action));
		}
        if (!task->is_skipped) {
		    cd->log_offset += rspamd_snprintf (cd->log_buf + cd->log_offset, cd->log_size - cd->log_offset, "(%s: %c (%s): [%.2f/%.2f/%.2f] [",
				(gchar *)metric_name, is_spam ? 'T' : 'F', str_action_metric (action), metric_res->score, ms, rs);
        }
        else {
		    cd->log_offset += rspamd_snprintf (cd->log_buf + cd->log_offset, cd->log_size - cd->log_offset, "(%s: %c (default): [%.2f/%.2f/%.2f] [",
				(gchar *)metric_name, 'S', metric_res->score, ms, rs);
        
        }
	}
	if (task->cmd == CMD_PROCESS) {
#ifndef GMIME24
		g_mime_message_add_header (task->message, "X-Spam-Status", outbuf);
#else
		g_mime_object_append_header (GMIME_OBJECT (task->message), "X-Spam-Status", outbuf);
#endif
	}
	else {
		if (! rspamd_dispatcher_write (task->dispatcher, outbuf, r, FALSE, FALSE)) {
			cd->alive = FALSE;
			return;
		}

		if (metric_value != NULL) {
			if (! show_metric_symbols (metric_res, cd)) {
				cd->alive = FALSE;
				return;
			}
		}
	}
#ifdef HAVE_CLOCK_GETTIME
	cd->log_offset += rspamd_snprintf (cd->log_buf + cd->log_offset, cd->log_size - cd->log_offset, "]), len: %z, time: %s,",
		task->msg->len, calculate_check_time (&task->tv, &task->ts, task->cfg->clock_res));
#else
	cd->log_offset += rspamd_snprintf (cd->log_buf + cd->log_offset, cd->log_size - cd->log_offset, "]), len: %z, time: %s,",
		task->msg->len, calculate_check_time (&task->tv, task->cfg->clock_res));
#endif
}

static gboolean
show_messages (struct worker_task *task)
{
	gint                            r = 0;
	gchar                           outbuf[OUTBUFSIZ];
	GList                          *cur;
	
	cur = task->messages;
	while (cur) {
		r += rspamd_snprintf (outbuf + r, sizeof (outbuf) - r, "Message: %s" CRLF, (gchar *)cur->data);
		cur = g_list_next (cur);
	}

	if (r == 0) {
		return TRUE;
	}

	return rspamd_dispatcher_write (task->dispatcher, outbuf, r, FALSE, FALSE);
}

static gboolean
write_check_reply (struct worker_task *task)
{
	gint                            r, len;
	gchar                           outbuf[OUTBUFSIZ], logbuf[OUTBUFSIZ], symbolsbuf[OUTBUFSIZ];
	struct metric_result           *metric_res;
	struct metric_callback_data     cd;

	r = rspamd_snprintf (outbuf, sizeof (outbuf), "%s/%s 0 %s" CRLF, (task->proto == SPAMC_PROTO) ? SPAMD_REPLY_BANNER : RSPAMD_REPLY_BANNER,
				rspamc_proto_str (task->proto_ver), SPAMD_OK);
	if (! rspamd_dispatcher_write (task->dispatcher, outbuf, r, TRUE, FALSE)) {
		return FALSE;
	}

	cd.task = task;
	cd.log_buf = logbuf;
	cd.log_offset = rspamd_snprintf (logbuf, sizeof (logbuf), "id: <%s>, qid: <%s>, ", task->message_id, task->queue_id);
	cd.log_size = sizeof (logbuf);
	if (task->user) {
		cd.log_offset += rspamd_snprintf (logbuf + cd.log_offset, sizeof (logbuf) - cd.log_offset,
				"user: %s, ", task->user);
	}
	cd.alive = TRUE;
	cd.report = FALSE;

	if (task->proto == SPAMC_PROTO) {
		/* Ignore metrics, just write report for 'default' metric */
		cd.symbols_buf = symbolsbuf;
		cd.symbols_size = sizeof (symbolsbuf);
		metric_res = g_hash_table_lookup (task->results, "default");
		if (metric_res == NULL) {
			/* Implicit metric result */
			show_metric_result (NULL, NULL, (void *)&cd);
			if (! cd.alive) {
				return FALSE;
			}
		}
		else {
			show_metric_result ((gpointer) "default", (gpointer) metric_res, (void *)&cd);
			if (! cd.alive) {
				return FALSE;
			}
		}
	}
	else {
		/* Show default metric first */
		metric_res = g_hash_table_lookup (task->results, "default");
		if (metric_res == NULL) {
			/* Implicit metric result */
			show_metric_result (NULL, NULL, (void *)&cd);
			if (! cd.alive) {
				return FALSE;
			}
		}
		else {
			show_metric_result ((gpointer) "default", (gpointer) metric_res, (void *)&cd);
			if (! cd.alive) {
				return FALSE;
			}
		}
		g_hash_table_remove (task->results, "default");

		/* Write result for each metric separately */
		g_hash_table_foreach (task->results, show_metric_result, &cd);
		if (!cd.alive) {
			return FALSE;
		}
		/* Messages */
		if (! show_messages (task)) {
			return FALSE;
		}
		/* URL stat */
		if (! show_url_header (task)) {
			return FALSE;
		}
	}
	
	write_hashes_to_log (task, logbuf, cd.log_offset, cd.log_size);
	msg_info ("%s", logbuf);
	if (task->proto == RSPAMC_PROTO && task->proto_ver >= 12) {
		r = rspamd_snprintf (outbuf, sizeof (outbuf), "Message-ID: %s" CRLF CRLF, task->message_id);
		if (! rspamd_dispatcher_write (task->dispatcher, outbuf, r, FALSE, FALSE)) {
			return FALSE;
		}
	}
	else if (task->proto == SPAMC_PROTO && task->cmd == CMD_SYMBOLS) {
		len = strlen (cd.symbols_buf);
		r = rspamd_snprintf (outbuf, sizeof (outbuf), CONTENT_LENGTH_HEADER ": %d" CRLF CRLF "%s" CRLF,
				len + sizeof (CRLF) - 1,  cd.symbols_buf);
		if (! rspamd_dispatcher_write (task->dispatcher, outbuf, r, FALSE, FALSE)) {
			return FALSE;
		}
	}

	if (task->cmd == CMD_REPORT || task->cmd == CMD_REPORT_IFSPAM) {
		cd.report = TRUE;
		g_hash_table_foreach (task->results, show_metric_result, &cd);
		if (!cd.alive) {
			return FALSE;
		}
		if (default_score >= default_required_score) {
			r = rspamd_snprintf (outbuf, sizeof (outbuf), CONTENT_LENGTH_HEADER ": %d" CRLF CRLF
					"This message is likely spam" CRLF, sizeof ("This message is likely spam" CRLF) - 1);
		}
		else if (default_score > 0.01) {
			r = rspamd_snprintf (outbuf, sizeof (outbuf), CONTENT_LENGTH_HEADER ": %d" CRLF CRLF
					"This message is probably spam" CRLF, sizeof ("This message is probably spam" CRLF) - 1);
		}
		else {
			r = rspamd_snprintf (outbuf, sizeof (outbuf), CONTENT_LENGTH_HEADER ": %d" CRLF CRLF
					"This message is not spam" CRLF, sizeof ("This message is not spam" CRLF) - 1);
		}
		if (! rspamd_dispatcher_write (task->dispatcher, outbuf, r, FALSE, FALSE)) {
			return FALSE;
		}
	}

	task->worker->srv->stat->messages_scanned++;
	if (default_score >= default_required_score) {
		task->worker->srv->stat->messages_spam ++;
	}
	else {
		task->worker->srv->stat->messages_ham ++;
	}

	return TRUE;
}

static gboolean
write_process_reply (struct worker_task *task)
{
	gint                            r, rr;
	gchar                           *outmsg;
	gchar                           outbuf[OUTBUFSIZ], sizbuf[128], logbuf[OUTBUFSIZ];
	gsize                           len;
	struct metric_result           *metric_res;
	struct metric_callback_data     cd;

	r = rspamd_snprintf (outbuf, sizeof (outbuf), "%s/%s 0 %s" CRLF,
			(task->proto == SPAMC_PROTO) ? SPAMD_REPLY_BANNER : RSPAMD_REPLY_BANNER, 
			rspamc_proto_str (task->proto_ver), SPAMD_OK);

	cd.task = task;
	cd.log_buf = logbuf;
	cd.log_offset = rspamd_snprintf (logbuf, sizeof (logbuf), "id: <%s>, qid: <%s>, ", task->message_id, task->queue_id);
	if (task->user) {
		cd.log_offset += rspamd_snprintf (logbuf + cd.log_offset, sizeof (logbuf) - cd.log_offset,
				"user: %s, ", task->user);
	}
	cd.log_size = sizeof (logbuf);
	cd.alive = TRUE;

	if (task->proto == SPAMC_PROTO) {
		/* Ignore metrics, just write report for 'default' metric */
		metric_res = g_hash_table_lookup (task->results, "default");
		if (metric_res == NULL) {
			/* Implicit metric result */
			show_metric_result (NULL, NULL, (void *)&cd);
			if (! cd.alive) {
				return FALSE;
			}
		}
		else {
			show_metric_result ((gpointer) "default", (gpointer) metric_res, (void *)&cd);
			if (! cd.alive) {
				return FALSE;
			}
		}
	}
	else {
		/* Show default metric first */
		metric_res = g_hash_table_lookup (task->results, "default");
		if (metric_res == NULL) {
			/* Implicit metric result */
			show_metric_result (NULL, NULL, (void *)&cd);
			if (! cd.alive) {
				return FALSE;
			}
		}
		else {
			show_metric_result ((gpointer) "default", (gpointer) metric_res, (void *)&cd);
			if (! cd.alive) {
				return FALSE;
			}
		}
		g_hash_table_remove (task->results, "default");

		/* Write result for each metric separately */
		g_hash_table_foreach (task->results, show_metric_result, &cd);
		if (! cd.alive) {
			return FALSE;
		}
		/* Messages */
		if (! show_messages (task)) {
			return FALSE;
		}
	}
	write_hashes_to_log (task, logbuf, cd.log_offset, cd.log_size);
	msg_info ("%s", logbuf);

	outmsg = g_mime_object_to_string (GMIME_OBJECT (task->message));
	memory_pool_add_destructor (task->task_pool, (pool_destruct_func) g_free, outmsg);

	len = strlen (outmsg);
	rr = rspamd_snprintf (sizbuf, sizeof (sizbuf), CONTENT_LENGTH_HEADER ": %z" CRLF CRLF, len);
	if (! rspamd_dispatcher_write (task->dispatcher, outbuf, r, TRUE, FALSE)) {
		return FALSE;
	}
	if (! rspamd_dispatcher_write (task->dispatcher, sizbuf, rr, TRUE, FALSE)) {
		return FALSE;
	}
	if (! rspamd_dispatcher_write (task->dispatcher, outmsg, len, FALSE, TRUE)) {
		return FALSE;
	}

	task->worker->srv->stat->messages_scanned++;
	if (default_score >= default_required_score) {
		task->worker->srv->stat->messages_spam ++;
	}
	else {
		task->worker->srv->stat->messages_ham ++;
	}

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
		/* Write to bufferevent error message */
		return rspamd_dispatcher_write (task->dispatcher, outbuf, r, FALSE, FALSE);
	}
	else {
		switch (task->cmd) {
		case CMD_REPORT_IFSPAM:
		case CMD_REPORT:
		case CMD_CHECK:
		case CMD_SYMBOLS:
			return write_check_reply (task);
			break;
		case CMD_PROCESS:
			return write_process_reply (task);
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
