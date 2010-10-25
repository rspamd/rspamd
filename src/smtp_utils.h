#ifndef SMTP_UTILS_H_
#define SMTP_UTILS_H_

#include "config.h"
#include "main.h"
#include "smtp.h"
#include "smtp_proto.h"

/**
 * @file smtp_utils.h
 * Contains utilities for smtp protocol handling
 */

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
 * Write reply to upstream
 * @param session session object
 */
gboolean write_smtp_reply (struct smtp_session *session);

/**
 * Frees smtp session object
 */
void free_smtp_session (gpointer arg);

#endif /* SMTP_UTILS_H_ */
