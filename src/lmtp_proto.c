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
#include "cfg_file.h"
#include "lmtp.h"
#include "lmtp_proto.h"

/* Max line size as it is defined in rfc2822 */
#define OUTBUFSIZ 1000

/* LMTP commands */
static f_str_t lhlo_command = {
	.begin = "LHLO",
	.len = sizeof ("LHLO") - 1
};
static f_str_t mail_command = {
	.begin = "MAIL FROM:",
	.len = sizeof ("MAIL FROM:") - 1
};
static f_str_t rcpt_command = {
	.begin = "RCPT TO:",
	.len = sizeof ("RCPT TO:") - 1
};
static f_str_t data_command = {
	.begin = "DATA",
	.len = sizeof ("DATA") - 1
};
static f_str_t data_dot = {
	.begin = ".\r\n",
	.len = sizeof (".\r\n") - 1
};

static const char *mail_regexp = "[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?";
static GRegex *mail_re = NULL;

/*
 * Extract e-mail from read line 
 * return <> if no valid address detected
 */
static char *
extract_mail (memory_pool_t *pool, f_str_t *line)
{
	GError *err = NULL;
	char *match;
	GMatchInfo *info;

	if (mail_re == NULL) {
		/* Compile regexp */
		mail_re = g_regex_new (mail_regexp, G_REGEX_RAW, 0, &err);
	}

	if (g_regex_match_full (mail_re, line->begin, line->len, 0, 0, &info, NULL) == TRUE) {
		match = memory_pool_strdup (pool, g_match_info_fetch (info, 0));
		g_match_info_free (info);
	}
	else {
		match = "<>";
	}

	return match;
}

static void
out_lmtp_reply (struct rspamd_lmtp_proto *lmtp, int code, char *rcode, char *msg)
{
	char outbuf[OUTBUFSIZ];
	int r;
	
	if (*rcode == '\0') {
		r = snprintf (outbuf, OUTBUFSIZ, "%d %s\r\n", code, msg);
	}
	else {
		r = snprintf (outbuf, OUTBUFSIZ, "%d %s %s\r\n", code, rcode, msg);
	}
	rspamd_dispatcher_write (lmtp->task->dispatcher, outbuf, r, FALSE);
}

int 
read_lmtp_input_line (struct rspamd_lmtp_proto *lmtp, f_str_t *line)
{
	char *c, *rcpt;
	f_str_t fstr;
	unsigned int i = 0, l = 0, size;

	switch (lmtp->state) {
		case LMTP_READ_LHLO:
			/* Search LHLO line */
			if ((i = fstrstri (line, &lhlo_command)) == -1) {
				msg_info ("read_lmtp_input_line: LHLO expected but not found");
				out_lmtp_reply (lmtp, LMTP_BAD_CMD, "5.0.0", "Need LHLO here");
				return -1;
			}
			else {
				i += lhlo_command.len;
				c = line->begin + i;
				/* Skip spaces */
				while (isspace (*c) && i < line->len) {
					i ++;
					c ++;
				}
				lmtp->task->helo = memory_pool_alloc (lmtp->task->task_pool, line->len - i + 1);
				/* Strlcpy makes string null terminated by design */
				g_strlcpy (lmtp->task->helo, c, line->len - i + 1);
				lmtp->state = LMTP_READ_FROM;
				out_lmtp_reply (lmtp, LMTP_OK, "", "Ok");
				return 0;
			}
			break;
		case LMTP_READ_FROM:
			/* Search MAIL FROM: line */
			if ((i = fstrstri (line, &mail_command)) == -1) {
				msg_info ("read_lmtp_input_line: MAIL expected but not found");
				out_lmtp_reply (lmtp, LMTP_BAD_CMD, "5.0.0", "Need MAIL here");
				return -1;
			}
			else {
				i += mail_command.len;
				c = line->begin + i;
				fstr.begin = line->begin + i;
				fstr.len = line->len - i;
				lmtp->task->from = extract_mail (lmtp->task->task_pool, &fstr);
				lmtp->state = LMTP_READ_RCPT;
				out_lmtp_reply (lmtp, LMTP_OK, "2.1.0", "Sender ok");
				return 0;
			}
			break;
		case LMTP_READ_RCPT:
			/* Search RCPT_TO: line */
			if ((i = fstrstri (line, &rcpt_command)) == -1) {
				msg_info ("read_lmtp_input_line: RCPT expected but not found");
				out_lmtp_reply (lmtp, LMTP_NO_RCPT, "5.5.4", "Need RCPT here");
				return -1;
			}
			else {
				i += rcpt_command.len;
				c = line->begin + i;
				fstr.begin = line->begin + i;
				fstr.len = line->len - i;
				rcpt = extract_mail (lmtp->task->task_pool, &fstr);
				if (*rcpt == '<' && *(rcpt + 1) == '>') {
					/* Invalid or empty rcpt not allowed */
					msg_info ("read_lmtp_input_line: bad recipient");
					out_lmtp_reply (lmtp, LMTP_NO_RCPT, "5.5.4", "Bad recipient");
					return -1;
				}
				/* Strlcpy makes string null terminated by design */
				lmtp->task->rcpt = g_list_prepend (lmtp->task->rcpt, rcpt);
				lmtp->state = LMTP_READ_DATA;
				out_lmtp_reply (lmtp, LMTP_OK, "2.1.0", "Recipient ok");
				return 0;
			}
			break;
		case LMTP_READ_DATA:
			/* Search DATA line */
			if ((i = fstrstri (line, &data_command)) == -1) {
				msg_info ("read_lmtp_input_line: DATA expected but not found");
				out_lmtp_reply (lmtp, LMTP_BAD_CMD, "5.0.0", "Need DATA here");
				return -1;
			}
			else {
				i += data_command.len;
				c = line->begin + i;
				/* Skip spaces */
				while (isspace (*c++)) {
					i ++;
				}
				rcpt = memory_pool_alloc (lmtp->task->task_pool, line->len - i + 1);
				/* Strlcpy makes string null terminated by design */
				g_strlcpy (rcpt, c, line->len - i + 1);
				lmtp->task->rcpt = g_list_prepend (lmtp->task->rcpt, rcpt);
				lmtp->state = LMTP_READ_MESSAGE;
				out_lmtp_reply (lmtp, LMTP_DATA, "", "Enter message, ending with \".\" on a line by itself");
				lmtp->task->msg = fstralloc (lmtp->task->task_pool, BUFSIZ);
				return 0;
			}
			break;
		case LMTP_READ_MESSAGE:
			if (strncmp (line->begin, data_dot.begin, line->len) == 0) {
				lmtp->state = LMTP_READ_DOT;
				lmtp->task->state = READ_MESSAGE;
				return 0;
			}
			else {
				l = lmtp->task->msg->len;
				size = lmtp->task->msg->size;
				if (l + line->len > size) {
					/* Grow buffer */
					if (line->len > size) {
						size += line->len << 1;
					}
					else {
						/* size *= 2 */
						size <<= 1;
					}
					lmtp->task->msg = fstrgrow (lmtp->task->task_pool, lmtp->task->msg, size);
				}
				fstrcat (lmtp->task->msg, line);
				return 0;
			}
			break;
		case LMTP_READ_DOT:
			/* We have some input after reading dot, close connection as we have no currently support of multiply 
			 * messages per session
			 */
			out_lmtp_reply (lmtp, LMTP_QUIT, "", "Bye");
			return 0;
			break;
	}	
}

static char*
format_lda_args (struct worker_task *task)
{
	char *arg, *res, *c, *r;
	size_t len;
	GList *rcpt;
	gboolean got_args = FALSE;

	c = task->cfg->deliver_agent_path;
	/* Find first arg */
	if ((c = strchr (c, ' ')) == NULL) {
		return task->cfg->deliver_agent_path;
	}
	
	/* Calculate length of result string */
	len = strlen (task->cfg->deliver_agent_path);
	while (*c) {
		if (*c == '%') {
			c++;
			switch (*c) {
				case 'f':
					/* Insert from */
					len += strlen (task->from) - 2;
					break;
				case 'r':
					/* Insert list of recipients */
					rcpt = g_list_first (task->rcpt);
					len -= 2;
					while (rcpt) {
						len += strlen ((char *)rcpt->data) + 1;
						rcpt = g_list_next (rcpt);
					}
					break;
			}
		}
		c ++;
		len ++;
	}
	res = memory_pool_alloc (task->task_pool, len + 1);
	r = res;
	c = task->cfg->deliver_agent_path;
	
	while (*c) {
		if (*c == ' ') {
			got_args = TRUE;
		}
		if (got_args && *c == '%') {
			switch (*(c + 1)) {
				case 'f':
					/* Insert from */
					c += 2;
					len = strlen (task->from);
					memcpy (r, task->from, len);
					r += len;
					break;
				case 'r':
					/* Insert list of recipients */
					c += 2;
					rcpt = g_list_first (task->rcpt);
					while (rcpt) {
						len = strlen ((char *)rcpt->data) + 1;
						memcpy (r, rcpt->data, len);
						r += len;
						*r++ = ' ';
						rcpt = g_list_next (rcpt);
					}
					break;
				default:
					*r = *c;
					r ++;
					c ++;
					break;
			}
		}
		else {
			*r = *c;
			r ++;
			c ++;
		}
	}

	return res;
}

static int
lmtp_deliver_lda (struct worker_task *task)
{
	char *args, **argv;
	GMimeStream *stream;
	int rc, ecode, p[2], argc;
	pid_t cpid, pid;

	if ((args = format_lda_args (task)) == NULL) {
		return -1;
	}
	
	/* Format arguments in shell style */
	if (!g_shell_parse_argv (args, &argc, &argv, NULL)) {
		msg_info ("lmtp_deliver_lda: cannot parse arguments");
		return -1;
	}

	if (pipe (p) == -1) {
		g_strfreev (argv);
		msg_info ("lmtp_deliver_lda: cannot open pipe: %m");
		return -1;
	}
	
	/* Fork to exec LDA */
#ifdef HAVE_VFORK
	if ((cpid = vfork ()) == -1) {
		g_strfreev (argv);
		msg_info ("lmtp_deliver_lda: cannot fork: %m");
		return -1;
	}
#else 
	if ((cpid = fork ()) == -1) {
		g_strfreev (argv);
		msg_info ("lmtp_deliver_lda: cannot fork: %m");
		return -1;
	}
#endif

	if (cpid == 0) {
		/* Child process, close write pipe and keep only read one */
		close (p[1]);
		/* Set standart IO descriptors */
		if (p[0] != STDIN_FILENO) {
			(void)dup2(p[0], STDIN_FILENO);
			(void)close(p[0]);
		}

		execv (argv[0], argv);
		_exit (127);
	}
	
	close (p[0]);
	stream = g_mime_stream_fs_new (p[1]);

	if (g_mime_object_write_to_stream ((GMimeObject *)task->message, stream) == -1) {
		g_strfreev (argv);
		msg_info ("lmtp_deliver_lda: cannot write stream to lda");
		return -1;
	}

	g_object_unref (stream);
	close (p[1]);

#if defined(HAVE_WAIT4)
	do {
		pid = wait4(cpid, &rc, 0, NULL);
	} while (pid == -1 && errno == EINTR);
#elif defined(HAVE_WAITPID)
	do {
		pid = waitpid(cpid, &rc, 0);
	} while (pid == -1 && errno == EINTR);
#else
#error wait mechanisms are undefined
#endif
	if (rc == -1) {
		g_strfreev (argv);
		msg_info ("lmtp_deliver_lda: lda returned error code");
		return -1;
	}
	else if (WIFEXITED (rc)) {
		ecode = WEXITSTATUS (rc);
		if (ecode == 0) {
			g_strfreev (argv);
			return 0;
		}
		else {
			g_strfreev (argv);
			msg_info ("lmtp_deliver_lda: lda returned error code %d", ecode);
			return -1;
		}
	}

	g_strfreev (argv);
	return -1;
}

int
lmtp_deliver_message (struct worker_task *task)
{
	if (task->cfg->deliver_agent_path != NULL) {
		/* Do deliver to LDA */
		return lmtp_deliver_lda (task);
	}
	else {
		/* XXX: do lmtp/smtp client */
		return -1;
	}
}

int
write_lmtp_reply (struct rspamd_lmtp_proto *lmtp)
{
	int r;
	char outbuf[OUTBUFSIZ];

	msg_debug ("write_lmtp_reply: writing reply to client");
	if (lmtp->task->error_code != 0) {
		out_lmtp_reply (lmtp, lmtp->task->error_code, "", lmtp->task->last_error);
	}
	else {
		/* Do delivery */
		if (lmtp_deliver_message (lmtp->task) == -1) {
			out_lmtp_reply (lmtp, LMTP_FAILURE, "", "Delivery failure");
			return -1;
		}
		else {
			out_lmtp_reply (lmtp, LMTP_OK, "", "Delivery completed");
		}
	}

	return 0;
}

/* 
 * vi:ts=4 
 */
