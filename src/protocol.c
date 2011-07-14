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
	gint                            state = 0, next_state;
	gchar                          *cmd;

	p = line->begin;
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
				}
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
			return FALSE;
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
			return FALSE;
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
			return FALSE;
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
			return FALSE;
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
			return FALSE;
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
			return FALSE;
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
			return FALSE;
		}
		break;
	case 'i':
	case 'I':
		/* ip_addr */
		if (g_ascii_strncasecmp (headern, IP_ADDR_HEADER, sizeof (IP_ADDR_HEADER) - 1) == 0) {
			tmp = memory_pool_fstrdup (task->task_pool, line);
			if (!inet_aton (tmp, &task->from_addr)) {
				msg_info ("bad ip header: '%s'", tmp);
				return FALSE;
			}
			debug_task ("read IP header, value: %s", tmp);
		}
		else {
			msg_info ("wrong header: %s", headern);
			return FALSE;
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
			return FALSE;
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
			return FALSE;
		}
		break;
	case 'u':
	case 'U':
		if (g_ascii_strncasecmp (headern, USER_HEADER, sizeof (USER_HEADER) - 1) == 0) {
			/* XXX: use this header somehow */
			task->user = memory_pool_fstrdup (task->task_pool, line);
		}
		else {
			return FALSE;
		}
		break;
	default:
		msg_info ("wrong header: %s", headern);
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

struct metric_callback_data {
	struct worker_task             *task;
	gchar                           *log_buf;
	gint                            log_offset;
	gint                            log_size;
	gchar                           *report_buf;
	gint                            report_offset;
	gint                            report_size;
	gchar                           *symbols_buf;
	gint                            symbols_size;
	gint                            symbols_offset;
	gboolean                        alive;
	struct metric                  *cur_metric;
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


/* Structure for writing tree data */
struct tree_cb_data {
	gchar                          *buf;
	gsize                           len;
	gsize                           off;
};

/*
 * Callback for writing urls
 */
static gboolean
urls_protocol_cb (gpointer key, gpointer value, gpointer ud)
{
	struct tree_cb_data             *cb = ud;
	struct uri                      *url = value;
	gsize                            len;

	len = url->hostlen + url->userlen + 1;
	if (cb->off + len >= cb->len) {
		msg_info ("cannot write urls header completely, stripped reply at: %z", cb->off);
		return TRUE;
	}
	else {
		cb->off += rspamd_snprintf (cb->buf + cb->off, cb->len - cb->off, " %*s,",
								url->hostlen, url->host);
	}
	return FALSE;
}

static gboolean
show_url_header (struct worker_task *task)
{
	gint                            r = 0;
	gchar                           outbuf[OUTBUFSIZ];
	struct tree_cb_data             cb;

	r = rspamd_snprintf (outbuf, sizeof (outbuf), "Urls: ");

	cb.buf = outbuf;
	cb.len = sizeof (outbuf);
	cb.off = r;

	g_tree_foreach (task->urls, urls_protocol_cb, &cb);
	/* Strip last ',' */
	if (cb.buf[cb.off - 1] == ',') {
		cb.buf[--cb.off] = '\0';
	}
	cb.off += rspamd_snprintf (cb.buf + cb.off, cb.len - cb.off, CRLF);

	return rspamd_dispatcher_write (task->dispatcher, outbuf, cb.off, FALSE, FALSE);
}

/*
 * Callback for writing emails
 */
static gboolean
emails_protocol_cb (gpointer key, gpointer value, gpointer ud)
{
	struct tree_cb_data             *cb = ud;
	struct uri                      *url = value;
	gsize                            len;

	len = url->hostlen + url->userlen + 1;
	if (cb->off + len >= cb->len) {
		msg_info ("cannot write emails header completely, stripped reply at: %z", cb->off);
		return TRUE;
	}
	else {
		cb->off += rspamd_snprintf (cb->buf + cb->off, cb->len - cb->off, " %*s@%*s,",
								url->userlen, url->user,
								url->hostlen, url->host);
	}
	return FALSE;
}

/*
 * Show header for emails found in a message
 */
static gboolean
show_email_header (struct worker_task *task)
{
	gint                            r = 0;
	gchar                           outbuf[OUTBUFSIZ];
	struct tree_cb_data             cb;

	r = rspamd_snprintf (outbuf, sizeof (outbuf), "Emails: ");

	cb.buf = outbuf;
	cb.len = sizeof (outbuf);
	cb.off = r;

	g_tree_foreach (task->emails, emails_protocol_cb, &cb);
	/* Strip last ',' */
	if (cb.buf[cb.off - 1] == ',') {
		cb.buf[--cb.off] = '\0';
	}
	cb.off += rspamd_snprintf (cb.buf + cb.off, cb.len - cb.off, CRLF);

	return rspamd_dispatcher_write (task->dispatcher, outbuf, cb.off, FALSE, FALSE);
}

/*
 * Print a single symbol using rspamc protocol
 */
static void
metric_symbols_callback_rspamc (gpointer key, gpointer value, void *user_data)
{
	struct metric_callback_data    *cd = (struct metric_callback_data *)user_data;
	struct worker_task             *task = cd->task;
	gint                            r = 0;
	gchar                           outbuf[OUTBUFSIZ], *description;
	struct symbol                  *s = (struct symbol *)value;
	GList                          *cur;

	if (! cd->alive) {
		return;
	}
	if (cd->task->proto == SPAMC_PROTO) {
		cd->symbols_offset = rspamd_snprintf (cd->symbols_buf + cd->symbols_offset,
				cd->symbols_size - cd->symbols_offset, "%s," CRLF, (gchar *)key);
	}
	description = g_hash_table_lookup (cd->cur_metric->descriptions, key);
	if (s->options) {
		if (task->proto_ver >= 13) {
			if (description != NULL) {
				r = rspamd_snprintf (outbuf, OUTBUFSIZ, "Symbol: %s(%.2f); %s;", (gchar *)key, s->score, description);
			}
			else {
				r = rspamd_snprintf (outbuf, OUTBUFSIZ, "Symbol: %s(%.2f);;", (gchar *)key, s->score);
			}
		}
		else if (task->proto_ver >= 12) {
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
		if (task->proto_ver >= 13) {
			if (description != NULL) {
				r = rspamd_snprintf (outbuf, OUTBUFSIZ, "Symbol: %s(%.2f); %s" CRLF, (gchar *)key, s->score, description);
			}
			else {
				r = rspamd_snprintf (outbuf, OUTBUFSIZ, "Symbol: %s(%.2f);" CRLF, (gchar *)key, s->score);
			}
		}
		else if (task->proto_ver >= 12) {
			r = rspamd_snprintf (outbuf, OUTBUFSIZ, "Symbol: %s(%.2f)" CRLF, (gchar *)key, s->score);
		}
		else {
			r = rspamd_snprintf (outbuf, OUTBUFSIZ, "Symbol: %s" CRLF, (gchar *)key);
		}
	}
	if (cd->task->cmd == CMD_SYMBOLS) {
		if (! rspamd_dispatcher_write (task->dispatcher, outbuf, r, FALSE, FALSE)) {
			cd->alive = FALSE;
		}
	}
	cd->report_offset += rspamd_snprintf (cd->report_buf + cd->report_offset, cd->report_size - cd->report_offset,
			"%*s", r, outbuf);
	cd->log_offset += rspamd_snprintf (cd->log_buf + cd->log_offset, cd->log_size - cd->log_offset,
			"%s,", (gchar *)key);
}

static gboolean
show_metric_symbols_rspamc (struct metric_result *metric_res, struct metric_callback_data *cd)
{
	cd->cur_metric = metric_res->metric;
	g_hash_table_foreach (metric_res->symbols, metric_symbols_callback_rspamc, cd);
	/* Remove last , from log buf */
	if (cd->log_buf[cd->log_offset - 1] == ',') {
		cd->log_buf[--cd->log_offset] = '\0';
	}
	if (cd->symbols_buf[cd->symbols_offset - 1] == ',') {
		cd->symbols_buf[--cd->symbols_offset] = '\0';
	}

	return TRUE;
}

/*
 * JSON symbols output
 */
static void
metric_symbols_callback_json (gpointer key, gpointer value, void *user_data)
{
	struct metric_callback_data    *cd = (struct metric_callback_data *)user_data;
	gchar                          *description;
	struct symbol                  *s = (struct symbol *)value;
	GList                          *cur;

	if (! cd->alive) {
		return;
	}
	description = g_hash_table_lookup (cd->cur_metric->descriptions, key);

	cd->symbols_offset += rspamd_snprintf (cd->symbols_buf + cd->symbols_offset, cd->symbols_size - cd->symbols_offset,
				CRLF "      {" CRLF "        \"name\": \"%s\"," CRLF
				"        \"weight\": %.2f," CRLF,
				(gchar *)key, s->score);
	if (description != NULL) {
		cd->symbols_offset += rspamd_snprintf (cd->symbols_buf + cd->symbols_offset, cd->symbols_size - cd->symbols_offset,
				"        \"description\": \"%s\"" CRLF, description);
	}
	if (s->options) {
		cd->symbols_offset += rspamd_snprintf (cd->symbols_buf + cd->symbols_offset, cd->symbols_size - cd->symbols_offset,
						"        \"options\": [" CRLF "        ");
		cur = s->options;
		while (cur) {
			if (g_list_next (cur)) {
				cd->symbols_offset += rspamd_snprintf (cd->symbols_buf + cd->symbols_offset, cd->symbols_size - cd->symbols_offset,
						"\"%s\", ", (gchar *)cur->data);
			}
			else {
				cd->symbols_offset += rspamd_snprintf (cd->symbols_buf + cd->symbols_offset, cd->symbols_size - cd->symbols_offset,
						"\"%s\"" CRLF "        ]" CRLF, (gchar *)cur->data);

			}
			cur = g_list_next (cur);
		}
	}
	cd->symbols_offset += rspamd_snprintf (cd->symbols_buf + cd->symbols_offset, cd->symbols_size - cd->symbols_offset,
			"      },");
}
/*
 * Print a single symbol using json protocol
 */
static gboolean
show_metric_symbols_json (struct metric_result *metric_res, struct metric_callback_data *cd)
{

	cd->cur_metric = metric_res->metric;
	cd->symbols_offset = 0;
	cd->symbols_offset += rspamd_snprintf (cd->symbols_buf + cd->symbols_offset, cd->symbols_size - cd->symbols_offset,
			"    \"symbols\": [");

	/* Print all symbols */
	g_hash_table_foreach (metric_res->symbols, metric_symbols_callback_json, cd);
	/* Remove last ',' symbol */
	if (cd->symbols_buf[cd->symbols_offset - 1] == ',') {
			cd->symbols_buf[--cd->symbols_offset] = '\0';
	}
	cd->symbols_offset += rspamd_snprintf (cd->symbols_buf + cd->symbols_offset, cd->symbols_size - cd->symbols_offset,
				CRLF "    ]" CRLF "  }" CRLF);
	if (! rspamd_dispatcher_write (cd->task->dispatcher, cd->symbols_buf, cd->symbols_offset, FALSE, FALSE)) {
		cd->alive = FALSE;
	}
	return cd->alive;
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

/* Print a single metric line */
static gint
print_metric_data_rspamc (struct worker_task *task, gchar *outbuf, gsize size,
		struct metric_result *metric_res,
		struct metric *m, double ms, double rs,
		enum rspamd_metric_action action)
{
	gint                            r = 0;
	gboolean                        is_spam = FALSE;

	if (metric_res == NULL) {
		if (task->proto == SPAMC_PROTO) {
			r = rspamd_snprintf (outbuf, size,
					"Spam: False ; 0 / %.2f" CRLF, ms);
		}
		else {
			if (task->proto_ver >= 11) {
				if (!task->is_skipped) {
					r = rspamd_snprintf (outbuf, size,
							"Metric: default; False; 0.00 / %.2f / %.2f" CRLF, ms,
							rs);
				}
				else {
					r = rspamd_snprintf (outbuf, size,
							"Metric: default; Skip; 0.00 / %.2f / %.2f" CRLF, ms,
							rs);
				}
			}
			else {
				r = rspamd_snprintf (outbuf, size,
						"Metric: default; False; 0.00 / %.2f" CRLF, ms);
			}
			r += rspamd_snprintf (outbuf + r, size - r,
					"Action: %s" CRLF, str_action_metric (
							METRIC_ACTION_NOACTION));
		}
	}
	else {
		is_spam = metric_res->score >= ms;

		if (task->proto == SPAMC_PROTO) {
			if (task->cmd != CMD_REPORT_IFSPAM || is_spam) {
				r = rspamd_snprintf (outbuf, size,
						"Spam: %s ; %.2f / %.2f" CRLF, (is_spam) ? "True"
								: "False", metric_res->score, ms);
			}
		}
		else {
			if (task->proto_ver >= 11) {
				if (!task->is_skipped) {
					r = rspamd_snprintf (outbuf, size,
							"Metric: %s; %s; %.2f / %.2f / %.2f" CRLF,
							(gchar *) m->name,
							(is_spam) ? "True" : "False", metric_res->score,
									ms, rs);
				}
				else {
					r = rspamd_snprintf (outbuf, size,
							"Metric: %s; Skip; %.2f / %.2f / %.2f" CRLF,
							(gchar *) m->name, metric_res->score, ms, rs);
				}
			}
			else {
				r = rspamd_snprintf (outbuf, size,
						"Metric: %s; %s; %.2f / %.2f" CRLF,
						(gchar *) m->name, (is_spam) ? "True" : "False",
								metric_res->score, ms);
			}
			r += rspamd_snprintf (outbuf + r, size - r,
					"Action: %s" CRLF, str_action_metric (action));
		}
		if (action == METRIC_ACTION_REWRITE_SUBJECT && metric_res->metric->subject != NULL) {
			r += rspamd_snprintf (outbuf + r, size - r,
					"Subject: %s" CRLF, make_rewritten_subject (metric_res->metric, task));
		}
	}

	return r;
}

/* Print a single metric line in json */
static gint
print_metric_data_json (struct worker_task *task, gchar *outbuf, gsize size,
		struct metric_result *metric_res,
		struct metric *m, double ms, double rs,
		enum rspamd_metric_action action)
{
	gint                            r = 0;


	if (metric_res == NULL) {
			r = rspamd_snprintf (outbuf, size,
					"  {" CRLF "    \"name\": \"default\"," CRLF
					"    \"is_spam\": false," CRLF
					"    \"is_skipped\": %s," CRLF
					"    \"score\": 0.00," CRLF
					"    \"required_score\": %.2f," CRLF
					"    \"reject_score\": %.2f," CRLF
					"    \"action\": \"%s\"," CRLF,
					task->is_skipped ? "true" : "false", ms, rs,
					str_action_metric (METRIC_ACTION_NOACTION));
	}
	else {
		r = rspamd_snprintf (outbuf, size,
					"  {" CRLF "    \"name\": \"default\"," CRLF
					"    \"is_spam\": %s," CRLF
					"    \"is_skipped\": %s," CRLF
					"    \"score\": %.2f," CRLF
					"    \"required_score\": %.2f," CRLF
					"    \"reject_score\": %.2f," CRLF
					"    \"action\": \"%s\"," CRLF,
					metric_res->score >= ms ? "true" : "false",
					metric_res->score,
					task->is_skipped ? "true" : "false", ms, rs,
					str_action_metric (action));
		if (action == METRIC_ACTION_REWRITE_SUBJECT && metric_res->metric->subject != NULL) {
			r += rspamd_snprintf (outbuf + r, size - r,
					"    \"subject\": \"%s\"," CRLF, make_rewritten_subject (metric_res->metric, task));
		}
	}

	return r;
}

static void
show_metric_result (gpointer metric_name, gpointer metric_value, void *user_data)
{
	struct metric_callback_data    *cd = (struct metric_callback_data *)user_data;
	struct worker_task             *task = cd->task;

	gchar                           outbuf[OUTBUFSIZ];
	struct metric_result           *metric_res = (struct metric_result *)metric_value;
	struct metric                  *m;
	gboolean                        is_spam;
	gint                            r;

	double                          ms = 0, rs = 0;
	enum rspamd_metric_action       action = METRIC_ACTION_NOACTION;

	if (! cd->alive) {
		return;
	}
	if (metric_name == NULL || metric_value == NULL) {
		m = g_hash_table_lookup (task->cfg->metrics, DEFAULT_METRIC);
		default_required_score = m->required_score;
		default_score = 0;
		if (metric_res != NULL && !check_metric_settings (metric_res, &ms, &rs)) {
			ms = m->required_score;
			rs = m->reject_score;
		}

		if (!task->is_json) {
			r = print_metric_data_rspamc (task, outbuf, sizeof (outbuf), NULL, m, ms, rs, action);
		}
		else {
			r = print_metric_data_json (task, outbuf, sizeof (outbuf), NULL, m, ms, rs, action);
		}

		/* Write log line */
		if (!task->is_skipped) {
			cd->log_offset += rspamd_snprintf (cd->log_buf + cd->log_offset,
					cd->log_size - cd->log_offset,
					"(%s: F (no action): [0.00/%.2f/%.2f] [", "default", ms, rs);
		}
		else {
			cd->log_offset += rspamd_snprintf (cd->log_buf + cd->log_offset,
					cd->log_size - cd->log_offset, "(%s: S: [0.00/%.2f/%.2f] [",
					"default", ms, rs);
		}
	}
	else {
		/* XXX: dirty hack */
		if (strcmp (metric_res->metric->name, DEFAULT_METRIC) == 0) {
			default_required_score = metric_res->metric->required_score;
			default_score = metric_res->score;
		}

		if (!check_metric_settings (metric_res, &ms, &rs)) {
			ms = metric_res->metric->required_score;
			rs = metric_res->metric->reject_score;
		}
		if (!check_metric_action_settings (task, metric_res,
				metric_res->score, &action)) {
			action = check_metric_action (metric_res->score, ms,
					metric_res->metric);
		}

		if (!task->is_json) {
			r = print_metric_data_rspamc (task, outbuf, sizeof (outbuf), metric_res, metric_res->metric, ms, rs, action);
		}
		else {
			r = print_metric_data_json (task, outbuf, sizeof (outbuf), metric_res, metric_res->metric, ms, rs, action);
		}
		/* Write log line */
		if (!task->is_skipped) {
			is_spam = metric_res->score >= ms;

			cd->log_offset += rspamd_snprintf (cd->log_buf + cd->log_offset,
					cd->log_size - cd->log_offset,
					"(%s: %c (%s): [%.2f/%.2f/%.2f] [", (gchar *) metric_name,
					is_spam ? 'T' : 'F', str_action_metric (action),
					metric_res->score, ms, rs);
		}
		else {
			cd->log_offset += rspamd_snprintf (cd->log_buf + cd->log_offset,
					cd->log_size - cd->log_offset,
					"(%s: %c (default): [%.2f/%.2f/%.2f] [",
					(gchar *) metric_name, 'S', metric_res->score, ms, rs);

		}
	}
	if (task->cmd == CMD_PROCESS) {
		if (task->is_json) {
			r += rspamd_snprintf (outbuf + r, sizeof (outbuf) - r, "}" CRLF);
		}
#ifndef GMIME24
		g_mime_message_add_header (task->message, "X-Spam-Status", outbuf);
#else
		g_mime_object_append_header (GMIME_OBJECT (task->message),
				"X-Spam-Status", outbuf);
#endif

	}
	else {
		if (!rspamd_dispatcher_write (task->dispatcher, outbuf, r, FALSE, FALSE)) {
			cd->alive = FALSE;
			return;
		}

		if (metric_value != NULL) {
			if (task->is_json) {
				if (!show_metric_symbols_json (metric_res, cd)) {
					cd->alive = FALSE;
					return;
				}
			}
			else {
				if (!show_metric_symbols_rspamc (metric_res, cd)) {
					cd->alive = FALSE;
					return;
				}
			}
		}
		else {
			if (task->is_json) {
				if (!rspamd_dispatcher_write (task->dispatcher, "  }" CRLF, 5, FALSE, TRUE)) {
					cd->alive = FALSE;
					return;
				}
			}
		}
	}
#ifdef HAVE_CLOCK_GETTIME
	cd->log_offset += rspamd_snprintf (cd->log_buf + cd->log_offset,
			cd->log_size - cd->log_offset, "]), len: %z, time: %s, dns req: %d,",
			task->msg->len, calculate_check_time (&task->tv, &task->ts,
					task->cfg->clock_res), task->dns_requests);
#else
	cd->log_offset += rspamd_snprintf (cd->log_buf + cd->log_offset, cd->log_size - cd->log_offset,
			"]), len: %z, time: %s, dns req: %d,",
			task->msg->len, calculate_check_time (&task->tv, task->cfg->clock_res), task->dns_requests);
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
	static gchar                    outbuf[OUTBUFSIZ], logbuf[OUTBUFSIZ],
									reportbuf[OUTBUFSIZ], symbolsbuf[OUTBUFSIZ];
	struct metric_result           *metric_res;
	struct metric_callback_data     cd;

	/* Output the first line - check status */
	if (task->is_http) {
		r = rspamd_snprintf (outbuf, sizeof (outbuf), "HTTP/1.0 200 OK" CRLF "Connection: close" CRLF CRLF);
		if (! rspamd_dispatcher_write (task->dispatcher, outbuf, r, TRUE, FALSE)) {
			return FALSE;
		}
	}
	else {
		r = rspamd_snprintf (outbuf, sizeof (outbuf), "%s/%s 0 %s" CRLF, (task->proto == SPAMC_PROTO) ? SPAMD_REPLY_BANNER : RSPAMD_REPLY_BANNER,
				rspamc_proto_str (task->proto_ver), SPAMD_OK);
		if (! rspamd_dispatcher_write (task->dispatcher, outbuf, r, TRUE, FALSE)) {
			return FALSE;
		}
	}

	cd.task = task;
	cd.log_buf = logbuf;
	cd.log_offset = rspamd_snprintf (logbuf, sizeof (logbuf), "id: <%s>, qid: <%s>, ", task->message_id, task->queue_id);
	cd.log_size = sizeof (logbuf);
	cd.symbols_buf = symbolsbuf;
	cd.symbols_size = sizeof (symbolsbuf);
	cd.symbols_offset = 0;
	cd.report_buf = reportbuf;
	cd.report_size = sizeof (reportbuf);
	cd.report_offset = 0;

	if (task->user) {
		cd.log_offset += rspamd_snprintf (logbuf + cd.log_offset, sizeof (logbuf) - cd.log_offset,
				"user: %s, ", task->user);
	}
	cd.alive = TRUE;

	if (task->proto == SPAMC_PROTO && !task->is_http) {
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
		if (task->is_json) {
			if (! rspamd_dispatcher_write (task->dispatcher, "[" CRLF, 3, TRUE, TRUE)) {
				return FALSE;
			}
		}
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
		if (task->is_json) {
			if (! rspamd_dispatcher_write (task->dispatcher, "]" CRLF, 3, FALSE, TRUE)) {
				return FALSE;
			}
		}
		else {
			/* XXX: add this for JSON as well */
			/* Messages */
			if (! show_messages (task)) {
				return FALSE;
			}
			/* URL stat */
			if (! show_url_header (task)) {
				return FALSE;
			}
			/* Emails stat */
			if (! show_email_header (task)) {
				return FALSE;
			}
		}
	}
	
	write_hashes_to_log (task, logbuf, cd.log_offset, cd.log_size);
	msg_info ("%s", logbuf);
	if (!task->is_json) {
		/* Write message id */
		if (task->proto == RSPAMC_PROTO && task->proto_ver >= 12) {
			r = rspamd_snprintf (outbuf, sizeof (outbuf), "Message-ID: %s" CRLF CRLF, task->message_id);
			if (! rspamd_dispatcher_write (task->dispatcher, outbuf, r, FALSE, FALSE)) {
				return FALSE;
			}
		}
		/* Write symbols for spamc proto */
		else if (task->proto == SPAMC_PROTO && task->cmd == CMD_SYMBOLS) {
			len = strlen (cd.symbols_buf);
			r = rspamd_snprintf (outbuf, sizeof (outbuf), CONTENT_LENGTH_HEADER ": %d" CRLF CRLF "%s" CRLF,
					len + sizeof (CRLF) - 1,  cd.symbols_buf);
			if (! rspamd_dispatcher_write (task->dispatcher, outbuf, r, FALSE, FALSE)) {
				return FALSE;
			}
		}
		/* Write report, based on score of default metric */
		if (task->cmd == CMD_REPORT || task->cmd == CMD_REPORT_IFSPAM) {
			if (default_score >= default_required_score) {
				r = rspamd_snprintf (outbuf, sizeof (outbuf), CONTENT_LENGTH_HEADER ": %d" CRLF CRLF
						"This message is likely spam" CRLF "%s",
						sizeof ("This message is likely spam" CRLF) - 1 + cd.report_offset,
						cd.report_buf);
			}
			else if (default_score > 0.01) {
				r = rspamd_snprintf (outbuf, sizeof (outbuf), CONTENT_LENGTH_HEADER ": %d" CRLF CRLF
						"This message is probably spam" CRLF "%s",
						sizeof ("This message is probably spam" CRLF) - 1 + cd.report_offset,
						cd.report_buf);
			}
			else {
				r = rspamd_snprintf (outbuf, sizeof (outbuf), CONTENT_LENGTH_HEADER ": %d" CRLF CRLF
						"This message is not spam" CRLF "%s",
						sizeof ("This message is not spam" CRLF) - 1 + cd.report_offset,
						cd.report_buf);
			}
			if (! rspamd_dispatcher_write (task->dispatcher, outbuf, r, FALSE, FALSE)) {
				return FALSE;
			}
		}
	}

	/* Increase counters */
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

	/* Output the first line - check status */
	if (task->is_http) {
		r = rspamd_snprintf (outbuf, sizeof (outbuf), "HTTP/1.0 200 OK" CRLF "Connection: close" CRLF CRLF);
		if (! rspamd_dispatcher_write (task->dispatcher, outbuf, r, TRUE, FALSE)) {
			return FALSE;
		}
	}
	else {
		r = rspamd_snprintf (outbuf, sizeof (outbuf), "%s/%s 0 %s" CRLF, (task->proto == SPAMC_PROTO) ? SPAMD_REPLY_BANNER : RSPAMD_REPLY_BANNER,
				rspamc_proto_str (task->proto_ver), SPAMD_OK);
		if (! rspamd_dispatcher_write (task->dispatcher, outbuf, r, TRUE, FALSE)) {
			return FALSE;
		}
	}

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

	/* Now prepare and write message itself */
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
