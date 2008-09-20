#include <sys/types.h>
#include <string.h>
#include <stdlib.h>
#include <glib.h>
#include "main.h"

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
				task->msg = g_malloc (sizeof (f_str_buf_t));
				task->msg->buf = fstralloc (task->content_length);
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
				task->helo = g_strdup (line);
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
				task->from = g_strdup (line);
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
				task->rcpt = g_strdup (line);
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
