#ifndef SMTP_UTILS_H_
#define SMTP_UTILS_H_

#include "config.h"
#include "main.h"
#include "smtp.h"

/**
 * @file smtp_utils.h
 * Contains utilities for smtp protocol handling
 */

struct smtp_upstream {
	struct upstream up;

	const gchar *name;
	gchar *addr;
	guint16 port;
	gboolean is_unix;
};

#define MAX_SMTP_UPSTREAMS 128

struct smtp_session;

/**
 * Send message to upstream
 * @param session session object
 */
gboolean smtp_send_upstream_message (struct smtp_session *session);

/**
 * Create connection to upstream
 * @param session session object
 */
gboolean create_smtp_upstream_connection (struct smtp_session *session);

/**
 * Create temporary file for smtp session
 */
gboolean make_smtp_tempfile (struct smtp_session *session);

/**
 * Write reply to upstream
 * @param session session object
 */
gboolean write_smtp_reply (struct smtp_session *session);

/**
 * Frees smtp session object
 */
void free_smtp_session (gpointer arg);

/**
 * Parse upstreams line
 * @param upstreams pointer to the array of upstreams (must be at least MAX_SMTP_UPSTREAMS size)
 * @param line description line
 * @param count targeted count
 * @return
 */
gboolean parse_upstreams_line (rspamd_mempool_t *pool, struct smtp_upstream *upstreams, const gchar *line, gsize *count);

#endif /* SMTP_UTILS_H_ */
