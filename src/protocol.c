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
#define CONTENT_LENGTH_HEADER "Content-Length"
#define HELO_HEADER "Helo"
#define FROM_HEADER "From"
#define IP_ADDR_HEADER "IP"
#define NRCPT_HEADER "Recipient-Number"
#define RCPT_HEADER "Rcpt"
#define QUEUE_ID_HEADER "Queue-ID"
#define ERROR_HEADER "Error"
/*
 * Reply messages
 */
#define RSPAMD_REPLY_BANNER "RSPAMD/1.0"
#define SPAMD_REPLY_BANNER "SPAMD/1.1"
#define SPAMD_OK "EX_OK"
/* XXX: try to convert rspamd errors to spamd errors */
#define SPAMD_ERROR "EX_ERROR"

static char *
separate_command (f_str_t *in, char c)
{
	int r = 0;
	char *p = in->begin, *b;
	b = p;

	while (r < in->len) {
		if (*p == c) {
			*p = '\0';
			in->begin = p + 1;
			in->len -= r + 1;
			return b;
		}
		p ++;
		r ++;
	}

	return NULL;
}

static int
parse_command (struct worker_task *task, f_str_t *line)
{
	char *token;

	token = separate_command (line, ' ');
	if (line == NULL || token == NULL) {
		msg_debug ("parse_command: bad command: %s", token);
		return -1;
	}

	switch (token[0]) {
		case 'c':
		case 'C':
			/* check */
			if (strcasecmp (token + 1, MSG_CMD_CHECK + 1) == 0) {
				task->cmd = CMD_CHECK;	
			}
			else {
				msg_debug ("parse_command: bad command: %s", token);
				return -1;
			}
			break;
		case 's':
		case 'S':
			/* symbols, skip */
			if (strcasecmp (token + 1, MSG_CMD_SYMBOLS + 1) == 0) {
				task->cmd = CMD_SYMBOLS;
			}
			else if (strcasecmp (token + 1, MSG_CMD_SKIP + 1) == 0) {
				task->cmd = CMD_SKIP;
			}
			else {
				msg_debug ("parse_command: bad command: %s", token);
				return -1;
			}
			break;
		case 'p':
		case 'P':
			/* ping, process */
			if (strcasecmp (token + 1, MSG_CMD_PING + 1) == 0) {
				task->cmd = CMD_PING;
			}
			else if (strcasecmp (token + 1, MSG_CMD_PROCESS + 1) == 0) {
				task->cmd = CMD_PROCESS;
			}
			else {
				msg_debug ("parse_command: bad command: %s", token);
				return -1;
			}
			break;
		case 'r':
		case 'R':
			/* report, report_ifspam */
			if (strcasecmp (token + 1, MSG_CMD_REPORT + 1) == 0) {
				task->cmd = CMD_REPORT;
			}
			else if (strcasecmp (token + 1, MSG_CMD_REPORT_IFSPAM + 1) == 0) {
				task->cmd = CMD_REPORT_IFSPAM;
			}
			else {
				msg_debug ("parse_command: bad command: %s", token);
				return -1;
			}
			break;
		default:
			msg_debug ("parse_command: bad command: %s", token);
			return -1;
	}

	if (strncasecmp (line->begin, RSPAMC_GREETING, sizeof (RSPAMC_GREETING) - 1) == 0) {
		task->proto = RSPAMC_PROTO;
	}
	else if (strncasecmp (line->begin, SPAMC_GREETING, sizeof (SPAMC_GREETING) -1) == 0) {
		task->proto = SPAMC_PROTO;
	}
	else {
		return -1;
	}
	task->state = READ_HEADER;
	return 0;
}

static int
parse_header (struct worker_task *task, f_str_t *line)
{
	char *headern, *err, *tmp;
	
	/* Check end of headers */
	if (line->len == 0) {
		msg_debug ("parse_header: got empty line, assume it as end of headers");
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
			if (strncasecmp (headern, CONTENT_LENGTH_HEADER, sizeof (CONTENT_LENGTH_HEADER) - 1) == 0) {
                if (task->content_length == 0) {
					tmp = memory_pool_fstrdup (task->task_pool, line);
				    task->content_length = strtoul (tmp, &err, 10);
					msg_debug ("parse_header: read Content-Length header, value: %lu", (unsigned long int)task->content_length);
				}
			}
			else {
				msg_info ("parse_header: wrong header: %s", headern);
				return -1;
			}
			break;
		case 'h':
		case 'H':
			/* helo */
			if (strncasecmp (headern, HELO_HEADER, sizeof (HELO_HEADER) - 1) == 0) {
				task->helo = memory_pool_fstrdup (task->task_pool, line);
				msg_debug ("parse_header: read helo header, value: %s", task->helo);
			}
			else {
				msg_info ("parse_header: wrong header: %s", headern);
				return -1;
			}
			break;
		case 'f':
		case 'F':
			/* from */
			if (strncasecmp (headern, FROM_HEADER, sizeof (FROM_HEADER) - 1) == 0) {
				task->from = memory_pool_fstrdup (task->task_pool, line);
				msg_debug ("parse_header: read from header, value: %s", task->from);
			}
			else {
				msg_info ("parse_header: wrong header: %s", headern);
				return -1;
			}
			break;
		case 'q':
		case 'Q':
			/* Queue id */
			if (strncasecmp (headern, QUEUE_ID_HEADER, sizeof (QUEUE_ID_HEADER) - 1) == 0) {
				task->queue_id = memory_pool_fstrdup (task->task_pool, line);
				msg_debug ("parse_header: read queue_id header, value: %s", task->queue_id);
			}
			else {
				msg_info ("parse_header: wrong header: %s", headern);
				return -1;
			}
			break;
		case 'r':
		case 'R':
			/* rcpt */
			if (strncasecmp (headern, RCPT_HEADER, sizeof (RCPT_HEADER) - 1) == 0) {
				tmp = memory_pool_fstrdup (task->task_pool, line);
				task->rcpt = g_list_prepend (task->rcpt, tmp);
				msg_debug ("parse_header: read rcpt header, value: %s", tmp);
			}
			else {
				msg_info ("parse_header: wrong header: %s", headern);
				return -1;
			}
			break;
		case 'n':
		case 'N':
			/* nrcpt */
			if (strncasecmp (headern, NRCPT_HEADER, sizeof (NRCPT_HEADER) - 1) == 0) {
				tmp = memory_pool_fstrdup (task->task_pool, line);
				task->nrcpt = strtoul (tmp, &err, 10);
				msg_debug ("parse_header: read rcpt header, value: %d", (int)task->nrcpt);
			}
			else {
				msg_info ("parse_header: wrong header: %s", headern);
				return -1;
			}
			break;
		case 'i':
		case 'I':
			/* ip_addr */
			if (strncasecmp (headern, IP_ADDR_HEADER, sizeof (IP_ADDR_HEADER) - 1) == 0) {
				tmp = memory_pool_fstrdup (task->task_pool, line);
				if (!inet_aton (tmp, &task->from_addr)) {
					msg_info ("parse_header: bad ip header: '%s'", tmp);
					return -1;
				}
				msg_debug ("parse_header: read IP header, value: %s", tmp);
			}
			else {
				msg_info ("parse_header: wrong header: %s", headern);
				return -1;
			}
			break;
		default:
			msg_info ("parse_header: wrong header: %s", headern);
			return -1;
	}

	return 0;
}

int
read_rspamd_input_line (struct worker_task *task, f_str_t *line)
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
	struct worker_task *task;
	char *log_buf;
	int log_offset;
	int log_size;
};

static void
show_url_header (struct worker_task *task)
{
	int r = 0;
	char outbuf[OUTBUFSIZ], c;
	struct uri *url;
	f_str_t host;

	r = snprintf (outbuf, sizeof (outbuf), "Urls: ");
	TAILQ_FOREACH (url, &task->urls, next) {
		host.begin = url->host;
		host.len = url->hostlen;
		/* Skip long hosts to avoid protocol coollisions */
		if (host.len > OUTBUFSIZ) {
			continue;
		}
		/* Do header folding */
		if (host.len + r >= OUTBUFSIZ - 3) {
			outbuf[r ++] = '\r'; outbuf[r ++] = '\n'; outbuf[r] = ' ';
			rspamd_dispatcher_write (task->dispatcher, outbuf, r, TRUE);
			r = 0;
		}
		/* Write url host to buf */
		if (TAILQ_NEXT (url, next) != NULL) {
			c = *(host.begin + host.len);
			*(host.begin + host.len) = '\0';
			msg_debug ("show_url_header: write url: %s", host.begin);
			r += snprintf (outbuf + r, sizeof (outbuf) - r, "%s, ", host.begin);
			*(host.begin + host.len) = c;
		}
		else {
			c = *(host.begin + host.len);
			*(host.begin + host.len) = '\0';
			msg_debug ("show_url_header: write url: %s", host.begin);
			r += snprintf (outbuf + r, sizeof (outbuf) - r, "%s" CRLF, host.begin);
			*(host.begin + host.len) = c;
		}
	}
	rspamd_dispatcher_write (task->dispatcher, outbuf, r, FALSE);
}

static void
metric_symbols_callback (gpointer key, gpointer value, void *user_data)
{
	struct metric_callback_data *cd = (struct metric_callback_data *)user_data;
	struct worker_task *task = cd->task;
	int r = 0;
	char outbuf[OUTBUFSIZ];
	struct symbol *s = (struct symbol *)value;	
	GList *cur;

	if (s->options) {
		r = snprintf (outbuf, OUTBUFSIZ, "Symbol: %s; ", (char *)key);
		cur = s->options;
		while (cur) {
			if (g_list_next (cur)) {
				r += snprintf (outbuf + r, OUTBUFSIZ - r, "%s,", (char *)cur->data);
			}
			else {
				r += snprintf (outbuf + r, OUTBUFSIZ - r, "%s" CRLF, (char *)cur->data);
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
		r = snprintf (outbuf, OUTBUFSIZ, "Symbol: %s" CRLF, (char *)key);
	}
	cd->log_offset += snprintf (cd->log_buf + cd->log_offset, cd->log_size - cd->log_offset,
						"%s,", (char *)key); 

	rspamd_dispatcher_write (task->dispatcher, outbuf, r, FALSE);
}

static void
show_metric_symbols (struct metric_result *metric_res, struct metric_callback_data *cd)
{
	int r = 0;
	GList *symbols, *cur;
	char outbuf[OUTBUFSIZ];

	if (cd->task->proto == SPAMC_PROTO) {
		symbols = g_hash_table_get_keys (metric_res->symbols);
		cur = symbols;
		while (cur) {
			if (g_list_next (cur) != NULL) {
				r += snprintf (outbuf + r, sizeof (outbuf) - r, "%s,", (char *)cur->data);
			}
			else {
				r += snprintf (outbuf + r, sizeof (outbuf) - r, "%s" CRLF, (char *)cur->data);
			}
			cur = g_list_next (cur);
		}
		g_list_free (symbols);
		rspamd_dispatcher_write (cd->task->dispatcher, outbuf, r, FALSE);
	}
	else {
		g_hash_table_foreach (metric_res->symbols, metric_symbols_callback, cd);
		/* Remove last , from log buf */
		if (cd->log_buf[cd->log_offset - 1] == ',') {
			cd->log_buf[--cd->log_offset] = '\0';
		}
	}
}

static void
show_metric_result (gpointer metric_name, gpointer metric_value, void *user_data)
{
	struct metric_callback_data *cd = (struct metric_callback_data *)user_data;
	struct worker_task *task = cd->task;
	int r;
	char outbuf[OUTBUFSIZ];
	struct metric_result *metric_res = (struct metric_result *)metric_value;
	struct metric *m;
	int is_spam = 0;
	
	if (metric_name == NULL || metric_value == NULL) {
		m = g_hash_table_lookup (task->cfg->metrics, "default");
		if (task->proto == SPAMC_PROTO) {
			r = snprintf (outbuf, sizeof (outbuf), "Spam: False ; 0 / %.2f" CRLF,
						m != NULL ? m->required_score : 0);
		}
		else {
			r = snprintf (outbuf, sizeof (outbuf), "Metric: default; False; 0 / %.2f" CRLF,
						m != NULL ? m->required_score : 0);
		}
		cd->log_offset += snprintf (cd->log_buf + cd->log_offset, cd->log_size - cd->log_offset,
						"(%s: F: [0/%.2f] [", "default", m != NULL ? m->required_score : 0); 
	}
	else {
		if (metric_res->score >= metric_res->metric->required_score) {
			is_spam = 1;
		}
		if (task->proto == SPAMC_PROTO) {
			r = snprintf (outbuf, sizeof (outbuf), "Spam: %s ; %.2f / %.2f" CRLF,
						(is_spam) ? "True" : "False", metric_res->score, metric_res->metric->required_score);
		}
		else {
			r = snprintf (outbuf, sizeof (outbuf), "Metric: %s; %s; %.2f / %.2f" CRLF, (char *)metric_name,
						(is_spam) ? "True" : "False", metric_res->score, metric_res->metric->required_score);
		}
		cd->log_offset += snprintf (cd->log_buf + cd->log_offset, cd->log_size - cd->log_offset,
						"(%s: %s: [%.2f/%.2f] [", (char *)metric_name, is_spam ? "T" : "F", 
						metric_res->score, metric_res->metric->required_score); 
	}
	rspamd_dispatcher_write (task->dispatcher, outbuf, r, FALSE);

	if (task->cmd == CMD_SYMBOLS && metric_value != NULL) {
		show_metric_symbols (metric_res, cd);
	}
	cd->log_offset += snprintf (cd->log_buf + cd->log_offset, cd->log_size - cd->log_offset, "]), len: %ld, time: %sms",
							(long int)task->msg->len, calculate_check_time (&task->ts, task->cfg->clock_res));
}

static int
write_check_reply (struct worker_task *task)
{
	int r;
	char outbuf[OUTBUFSIZ], logbuf[OUTBUFSIZ];
	struct metric_result *metric_res;
	struct metric_callback_data cd;

	r = snprintf (outbuf, sizeof (outbuf), "%s 0 %s" CRLF, (task->proto == SPAMC_PROTO) ? SPAMD_REPLY_BANNER : RSPAMD_REPLY_BANNER, "OK");
	rspamd_dispatcher_write (task->dispatcher, outbuf, r, TRUE);

	cd.task = task;
	cd.log_buf = logbuf;
	cd.log_offset = snprintf (logbuf, sizeof (logbuf), "process_message: msg ok, id: <%s>, ", task->message_id);
	cd.log_size = sizeof (logbuf);

	if (task->proto == SPAMC_PROTO) {
		/* Ignore metrics, just write report for 'default' metric */
		metric_res = g_hash_table_lookup (task->results, "default");
		if (metric_res == NULL) {
			/* Implicit metric result */
			show_metric_result (NULL, NULL, (void *)&cd);
		}
		else {
			show_metric_result ((gpointer)"default", (gpointer)metric_res, (void *)&cd);
		}
	}
	else {
		/* Show default metric first */
		metric_res = g_hash_table_lookup (task->results, "default");
		if (metric_res == NULL) {
			/* Implicit metric result */
			show_metric_result (NULL, NULL, (void *)&cd);
		}
		else {
			show_metric_result ((gpointer)"default", (gpointer)metric_res, (void *)&cd);
		}
		g_hash_table_remove (task->results, "default");

		/* Write result for each metric separately */
		g_hash_table_foreach (task->results, show_metric_result, &cd);
		/* URL stat */
		show_url_header (task);
	}
	msg_info ("%s", logbuf);
	rspamd_dispatcher_write (task->dispatcher, CRLF, sizeof (CRLF) - 1, FALSE);

	return 0;
}

static int
write_process_reply (struct worker_task *task)
{
	int r;
	char outbuf[OUTBUFSIZ];

	r = snprintf (outbuf, sizeof (outbuf), "%s 0 %s" CRLF "Content-Length: %zd" CRLF CRLF, 
					(task->proto == SPAMC_PROTO) ? SPAMD_REPLY_BANNER : RSPAMD_REPLY_BANNER, "OK", task->msg->len);
	rspamd_dispatcher_write (task->dispatcher, outbuf, r, TRUE);
	rspamd_dispatcher_write (task->dispatcher, task->msg->begin, task->msg->len, FALSE);

	return 0;
}

int
write_reply (struct worker_task *task)
{
	int r;
	char outbuf[OUTBUFSIZ];

	msg_debug ("write_reply: writing reply to client");
	if (task->error_code != 0) {
		/* Write error message and error code to reply */
		if (task->proto == SPAMC_PROTO) {
			r = snprintf (outbuf, sizeof (outbuf), "%s %d %s" CRLF CRLF, SPAMD_REPLY_BANNER, task->error_code, SPAMD_ERROR);
			msg_debug ("write_reply: writing error: %s", outbuf);
		}
		else {
			r = snprintf (outbuf, sizeof (outbuf), "%s %d %s" CRLF "%s: %s" CRLF CRLF, RSPAMD_REPLY_BANNER, task->error_code, 
								SPAMD_ERROR, ERROR_HEADER, task->last_error);
			msg_debug ("write_reply: writing error: %s", outbuf);
		}
		/* Write to bufferevent error message */
		rspamd_dispatcher_write (task->dispatcher, outbuf, r, FALSE);
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
				r = snprintf (outbuf, sizeof (outbuf), "%s 0 %s" CRLF, (task->proto == SPAMC_PROTO) ? SPAMD_REPLY_BANNER : RSPAMD_REPLY_BANNER,
																SPAMD_OK);
				rspamd_dispatcher_write (task->dispatcher, outbuf, r, FALSE);
				break;
			case CMD_PING:
				r = snprintf (outbuf, sizeof (outbuf), "%s 0 PONG" CRLF, (task->proto == SPAMC_PROTO) ? SPAMD_REPLY_BANNER : RSPAMD_REPLY_BANNER);
				rspamd_dispatcher_write (task->dispatcher, outbuf, r, FALSE);
				break;
		}
	}

	return 0;
}
