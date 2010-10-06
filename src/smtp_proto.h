#ifndef RSPAMD_SMTP_PROTO_H
#define RSPAMD_SMTP_PROTO_H

#include "config.h"
#include "smtp.h"

/* SMTP errors */
#define SMTP_ERROR_BAD_COMMAND "500 Syntax error, command unrecognized" CRLF
#define SMTP_ERROR_BAD_ARGUMENTS "501 Syntax error in parameters or arguments" CRLF
#define SMTP_ERROR_SEQUENCE "503 Bad sequence of commands" CRLF
#define SMTP_ERROR_RECIPIENTS "554 No valid recipients" CRLF
#define SMTP_ERROR_UNIMPLIMENTED "502 Command not implemented" CRLF
#define SMTP_ERROR_LIMIT "505 Too many errors. Aborting." CRLF
#define SMTP_ERROR_UPSTREAM "421 Service not available, closing transmission channel" CRLF
#define SMTP_ERROR_FILE "420 Service not available, filesystem error" CRLF
#define SMTP_ERROR_OK "250 Requested mail action okay, completed" CRLF
#define SMTP_ERROR_DATA_OK "354 Start mail input; end with <CRLF>.<CRLF>" CRLF

#define DATA_END_TRAILER "." CRLF


struct smtp_command {
	enum {
		SMTP_COMMAND_HELO,
		SMTP_COMMAND_EHLO,
		SMTP_COMMAND_QUIT,
		SMTP_COMMAND_NOOP,
		SMTP_COMMAND_MAIL,
		SMTP_COMMAND_RCPT,
		SMTP_COMMAND_RSET,
		SMTP_COMMAND_DATA,
		SMTP_COMMAND_VRFY,
		SMTP_COMMAND_EXPN,
		SMTP_COMMAND_HELP
	} command;
	GList *args;
};

gchar * make_smtp_error (struct smtp_session *session, gint error_code, const gchar *format, ...);
gboolean parse_smtp_command (struct smtp_session *session, f_str_t *line, struct smtp_command **cmd);
gboolean parse_smtp_helo (struct smtp_session *session, struct smtp_command *cmd);
gboolean parse_smtp_from (struct smtp_session *session, struct smtp_command *cmd);
gboolean parse_smtp_rcpt (struct smtp_session *session, struct smtp_command *cmd);

/* Upstream SMTP */
gboolean smtp_upstream_read_socket (f_str_t * in, void *arg);
gboolean smtp_upstream_write_socket (void *arg);
void smtp_upstream_err_socket (GError *err, void *arg);
void smtp_upstream_finalize_connection (gpointer data);
size_t smtp_upstream_write_list (GList *args, gchar *buf, size_t buflen);

#endif
