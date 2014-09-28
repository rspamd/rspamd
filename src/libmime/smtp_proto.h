#ifndef RSPAMD_SMTP_PROTO_H
#define RSPAMD_SMTP_PROTO_H

#include "config.h"

/* SMTP errors */
#define SMTP_ERROR_BAD_COMMAND "500 Syntax error, command unrecognized" CRLF
#define SMTP_ERROR_BAD_ARGUMENTS "501 Syntax error in parameters or arguments" \
	CRLF
#define SMTP_ERROR_SEQUENCE "503 Bad sequence of commands" CRLF
#define SMTP_ERROR_RECIPIENTS "554 No valid recipients" CRLF
#define SMTP_ERROR_UNIMPLIMENTED "502 Command not implemented" CRLF
#define SMTP_ERROR_LIMIT "505 Too many errors. Aborting." CRLF
#define SMTP_ERROR_UPSTREAM \
	"421 Service not available, closing transmission channel" CRLF
#define SMTP_ERROR_FILE "420 Service not available, filesystem error" CRLF
#define SMTP_ERROR_OK "250 Requested mail action okay, completed" CRLF
#define SMTP_ERROR_DATA_OK "354 Start mail input; end with <CRLF>.<CRLF>" CRLF

#define DATA_END_TRAILER "." CRLF

#define XCLIENT_HOST_UNAVAILABLE "[UNAVAILABLE]"
#define XCLIENT_HOST_TEMPFAIL "[TEMPUNAVAIL]"

#define MAX_SMTP_UPSTREAMS 128

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

/*
 * Generate SMTP error message
 */
gchar * make_smtp_error (rspamd_mempool_t *pool,
	gint error_code,
	const gchar *format,
	...);

/*
 * Parse a single SMTP command
 */
gboolean parse_smtp_command (struct smtp_session *session,
	f_str_t *line,
	struct smtp_command **cmd);

/*
 * Parse HELO command
 */
gboolean parse_smtp_helo (struct smtp_session *session,
	struct smtp_command *cmd);

/*
 * Parse MAIL command
 */
gboolean parse_smtp_from (struct smtp_session *session,
	struct smtp_command *cmd);

/*
 * Parse RCPT command
 */
gboolean parse_smtp_rcpt (struct smtp_session *session,
	struct smtp_command *cmd);

/* Upstream SMTP */

/*
 * Read a line from SMTP upstream
 */
gboolean smtp_upstream_read_socket (f_str_t * in, void *arg);

/*
 * Write to SMTP upstream
 */
gboolean smtp_upstream_write_socket (void *arg);

/*
 * Error handler for SMTP upstream
 */
void smtp_upstream_err_socket (GError *err, void *arg);

/*
 * Terminate connection with upstream
 */
void smtp_upstream_finalize_connection (gpointer data);

/*
 * Write a list of strings to the upstream
 */
size_t smtp_upstream_write_list (GList *args, gchar *buf, size_t buflen);

#endif
