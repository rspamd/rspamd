#include <sys/types.h>
#include <string.h>
#include <stdlib.h>
#include <glib.h>
#include "main.h"

#define CRLF "\r\n"
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
#define ERROR_HEADER "Error"
/*
 * Reply messages
 */
#define RSPAMD_REPLY_BANNER "RSPAMD/1.0"
#define SPAMD_REPLY_BANNER "SPAMD/1.1"
#define SPAMD_OK "EX_OK"
/* XXX: try to convert rspamd errors to spamd errors */
#define SPAMD_ERROR "EX_ERROR"

static int
parse_command (struct worker_task *task, char *line)
{
	char *token;

	token = strsep (&line, " ");
	if (line == NULL || token == NULL) {
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
				msg_debug ("parse_command: bad comand: %s", token);
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
				msg_debug ("parse_command: bad comand: %s", token);
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
				msg_debug ("parse_command: bad comand: %s", token);
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
				msg_debug ("parse_command: bad comand: %s", token);
				return -1;
			}
			break;
		default:
			msg_debug ("parse_command: bad comand: %s", token);
			return -1;
	}

	if (strncasecmp (line, RSPAMC_GREETING, sizeof (RSPAMC_GREETING) - 1) == 0) {
		task->proto = RSPAMC_PROTO;
	}
	else if (strncasecmp (line, SPAMC_GREETING, sizeof (SPAMC_GREETING) -1) == 0) {
		task->proto = SPAMC_PROTO;
	}
	else {
		msg_debug ("parse_command: bad protocol version: %s", line);
		return -1;
	}
	task->state = READ_HEADER;
	return 0;
}

static int
parse_header (struct worker_task *task, char *line)
{
	char *headern, *err;
	headern = strsep (&line, ":");

	/* Check end of headers */
	if (*line == '\r' && *(line + 1) == '\n') {
		task->state = READ_MESSAGE;
		return 0;
	}

	if (line == NULL || headern == NULL) {
		return -1;
	}
	/* Eat whitespaces */
	g_strstrip (line);
	g_strstrip (headern);

	switch (headern[0]) {
		case 'c':
		case 'C':
			/* content-length */
			if (strncasecmp (headern, CONTENT_LENGTH_HEADER, sizeof (CONTENT_LENGTH_HEADER) - 1) == 0) {
				task->content_length = strtoul (line, &err, 10);
				task->msg = memory_pool_alloc (task->task_pool, sizeof (f_str_buf_t));
				task->msg->buf = fstralloc (task->task_pool, task->content_length);
				if (task->msg->buf == NULL) {
					msg_err ("read_socket: cannot allocate memory for message buffer");
					return -1;
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
				task->helo = memory_pool_strdup (task->task_pool, line);
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
				task->from = memory_pool_strdup (task->task_pool, line);
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
				task->rcpt = memory_pool_strdup (task->task_pool, line);
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
				task->nrcpt = strtoul (line, &err, 10);
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
				if (!inet_aton (line, &task->from_addr)) {
					msg_info ("parse_header: bad ip header: '%s'", line);
					return -1;
				}
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
read_rspamd_input_line (struct worker_task *task, char *line)
{
	switch (task->state) {
		case READ_COMMAND:
			return parse_command (task, line);
			break;
		case READ_HEADER:
			return parse_header (task, line);
			break;
	}
}

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
			bufferevent_write (task->bev, outbuf, r);
			r = 0;
		}
		/* Write url host to buf */
		if (TAILQ_NEXT (url, next) != NULL) {
			c = *(host.begin + host.len);
			*(host.begin + host.len) = '\0';
			r += snprintf (outbuf, sizeof (outbuf) - r, "%s, ", host.begin);
			*(host.begin + host.len) = c;
		}
		else {
			c = *(host.begin + host.len);
			*(host.begin + host.len) = '\0';
			r += snprintf (outbuf, sizeof (outbuf) - r, "%s" CRLF, host.begin);
			*(host.begin + host.len) = c;
		}
	}
	bufferevent_write (task->bev, outbuf, r);
}

static void
show_metric_result (gpointer metric_name, gpointer metric_value, void *user_data)
{
	struct worker_task *task = (struct worker_task *)user_data;
	int r;
	char outbuf[OUTBUFSIZ];
	struct metric_result *metric_res = (struct metric_result *)metric_value;
	int is_spam = 0;

	if (metric_res->score >= metric_res->metric->required_score) {
		is_spam = 1;
	}
	if (task->proto == SPAMC_PROTO) {
		r = snprintf (outbuf, sizeof (outbuf), "Spam: %s ; %.2f / %.2f" CRLF,
					(is_spam) ? "True" : "False", metric_res->score, metric_res->metric->required_score);
	}
	else {
		r = snprintf (outbuf, sizeof (outbuf), "%s: %s ; %.2f / %.2f" CRLF, (char *)metric_name,
					(is_spam) ? "True" : "False", metric_res->score, metric_res->metric->required_score);
	}
	bufferevent_write (task->bev, outbuf, r);
}

static int
write_check_reply (struct worker_task *task)
{
	int r;
	char outbuf[OUTBUFSIZ];
	struct metric_result *metric_res;

	r = snprintf (outbuf, sizeof (outbuf), "%s 0 %s" CRLF, (task->proto == SPAMC_PROTO) ? SPAMD_REPLY_BANNER : RSPAMD_REPLY_BANNER);
	bufferevent_write (task->bev, outbuf, r);
	if (task->proto == SPAMC_PROTO) {
		/* Ignore metrics, just write report for 'default' metric */
		metric_res = g_hash_table_lookup (task->results, "default");
		if (metric_res == NULL) {
			return -1;
		}
		else {
			show_metric_result ((gpointer)"default", (gpointer)metric_res, (void *)task);
		}
	}
	else {
		/* Write result for each metric separately */
		g_hash_table_foreach (task->results, show_metric_result, task);
		/* URL stat */
		show_url_header (task);
	}
	bufferevent_write (task->bev, CRLF, sizeof (CRLF) - 1);

	return 0;
}

static void
show_metric_symbols (gpointer metric_name, gpointer metric_value, void *user_data)
{
	struct worker_task *task = (struct worker_task *)user_data;
	int r = 0;
	char outbuf[OUTBUFSIZ];
	struct filter_result *result;
	struct metric_result *metric_res = (struct metric_result *)metric_value;

	if (task->proto == RSPAMC_PROTO) {
		r = snprintf (outbuf, sizeof (outbuf), "%s: ", (char *)metric_name);
	}

	LIST_FOREACH (result, &metric_res->results, next) {
		if (result->flag) {
			if (LIST_NEXT (result, next) != NULL) {
				r += snprintf (outbuf + r, sizeof (outbuf) - r, "%s,", result->symbol);
			}
			else {
				r += snprintf (outbuf + r, sizeof (outbuf) - r, "%s", result->symbol);
			}
		}
	}
	outbuf[r++] = '\r'; outbuf[r] = '\n';
	bufferevent_write (task->bev, outbuf, r);
}

static int
write_symbols_reply (struct worker_task *task)
{
	struct metric_result *metric_res;
	
	/* First of all write normal results by calling write_check_reply */
	if (write_check_reply (task) == -1) {
		return -1;
	}
	/* Now write symbols */
	if (task->proto == SPAMC_PROTO) {
		/* Ignore metrics, just write report for 'default' metric */
		metric_res = g_hash_table_lookup (task->results, "default");
		if (metric_res == NULL) {
			return -1;
		}
		else {
			show_metric_symbols ((gpointer)"default", (gpointer)metric_res, (void *)task);
		}
	}
	else {
		/* Write result for each metric separately */
		g_hash_table_foreach (task->results, show_metric_symbols, task);
	}
	return 0;
}

static int
write_process_reply (struct worker_task *task)
{
	int r;
	char outbuf[OUTBUFSIZ];

	r = snprintf (outbuf, sizeof (outbuf), "%s 0 %s" CRLF "Content-Length: %zd" CRLF CRLF, 
					(task->proto == SPAMC_PROTO) ? SPAMD_REPLY_BANNER : RSPAMD_REPLY_BANNER, task->msg->buf->len);
	bufferevent_write (task->bev, outbuf, r);
	bufferevent_write (task->bev, task->msg->buf->begin, task->msg->buf->len);

	return 0;
}

int
write_reply (struct worker_task *task)
{
	int r;
	char outbuf[OUTBUFSIZ];

	if (task->error_code != 0) {
		/* Write error message and error code to reply */
		if (task->proto == SPAMC_PROTO) {
			r = snprintf (outbuf, sizeof (outbuf), "%s %d %s" CRLF CRLF, SPAMD_REPLY_BANNER, task->error_code, SPAMD_ERROR);
		}
		else {
			r = snprintf (outbuf, sizeof (outbuf), "%s %d %s" CRLF "%s: %s" CRLF CRLF, RSPAMD_REPLY_BANNER, task->error_code, 
								SPAMD_ERROR, ERROR_HEADER, task->last_error);
		}
		/* Write to bufferevent error message */
		bufferevent_write (task->bev, outbuf, r);
	}
	else {
		switch (task->cmd) {
			case CMD_REPORT_IFSPAM:
			case CMD_REPORT:
			case CMD_CHECK:
				return write_check_reply (task);
				break;
			case CMD_SYMBOLS:
				return write_symbols_reply (task);
				break;
			case CMD_PROCESS:
				return write_process_reply (task);
				break;
			case CMD_SKIP:
				r = snprintf (outbuf, sizeof (outbuf), "%s 0 %s" CRLF CRLF, (task->proto == SPAMC_PROTO) ? SPAMD_REPLY_BANNER : RSPAMD_REPLY_BANNER,
																SPAMD_OK);
				bufferevent_write (task->bev, outbuf, r);
				break;
			case CMD_PING:
				r = snprintf (outbuf, sizeof (outbuf), "%s 0 PONG" CRLF CRLF, (task->proto == SPAMC_PROTO) ? SPAMD_REPLY_BANNER : RSPAMD_REPLY_BANNER);
				bufferevent_write (task->bev, outbuf, r);
				break;
		}
	}

	return 0;
}
