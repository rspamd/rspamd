/*-
 * Copyright 2017 Vsevolod Stakhov
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef RSPAMD_MILTER_H
#define RSPAMD_MILTER_H

#include "config.h"
#include "fstring.h"
#include "addr.h"
#include "contrib/libucl/ucl.h"
#include "contrib/libev/ev.h"
#include "ref.h"

#ifdef  __cplusplus
extern "C" {
#endif

enum rspamd_milter_reply {
	RSPAMD_MILTER_ADDRCPT = '+',
	RSPAMD_MILTER_DELRCPT = '-',
	RSPAMD_MILTER_ACCEPT = 'a',
	RSPAMD_MILTER_CONTINUE = 'c',
	RSPAMD_MILTER_DISCARD = 'd',
	RSPAMD_MILTER_CHGFROM = 'e',
	RSPAMD_MILTER_ADDHEADER = 'h',
	RSPAMD_MILTER_CHGHEADER = 'm',
	RSPAMD_MILTER_INSHEADER = 'i',
	RSPAMD_MILTER_REPLBODY = 'b',
	RSPAMD_MILTER_REJECT = 'r',
	RSPAMD_MILTER_TEMPFAIL = 't',
	RSPAMD_MILTER_REPLYCODE = 'y',
	RSPAMD_MILTER_OPTNEG = 'O',
	RSPAMD_MILTER_PROGRESS = 'p',
	RSPAMD_MILTER_QUARANTINE = 'q',
};

struct rspamd_email_address;
struct ev_loop;
struct rspamd_http_message;
struct rspamd_config;

struct rspamd_milter_context {
	const gchar *spam_header;
	const gchar *client_ca_name;
	const gchar *reject_message;
	void *sessions_cache;
	struct rspamd_config *cfg;
	gboolean discard_on_reject;
	gboolean quarantine_on_reject;
};

struct rspamd_milter_session {
	GHashTable *macros;
	rspamd_inet_addr_t *addr;
	struct rspamd_email_address *from;
	GPtrArray *rcpts;
	rspamd_fstring_t *helo;
	rspamd_fstring_t *hostname;
	rspamd_fstring_t *message;
	void *priv;
	ref_entry_t ref;
};

typedef void (*rspamd_milter_finish) (gint fd,
									  struct rspamd_milter_session *session, void *ud);

typedef void (*rspamd_milter_error) (gint fd,
									 struct rspamd_milter_session *session,
									 void *ud, GError *err);

/**
 * Handles socket with milter protocol
 * @param fd
 * @param finish_cb
 * @param error_cb
 * @param ud
 * @return
 */
gboolean rspamd_milter_handle_socket (gint fd, ev_tstamp timeout,
									  rspamd_mempool_t *pool,
									  struct ev_loop *ev_base, rspamd_milter_finish finish_cb,
									  rspamd_milter_error error_cb, void *ud);

/**
 * Updates userdata for a session, returns previous userdata
 * @param session
 * @param ud
 * @return
 */
void *rspamd_milter_update_userdata (struct rspamd_milter_session *session,
									 void *ud);

/**
 * Sets SMTP reply string
 * @param session
 * @param rcode
 * @param xcode
 * @param reply
 * @return
 */
gboolean rspamd_milter_set_reply (struct rspamd_milter_session *session,
								  rspamd_fstring_t *rcode,
								  rspamd_fstring_t *xcode,
								  rspamd_fstring_t *reply);

/**
 * Send some action to the MTA
 * @param fd
 * @param session
 * @param act
 * @return
 */
gboolean rspamd_milter_send_action (struct rspamd_milter_session *session,
									enum rspamd_milter_reply act, ...);

/**
 * Adds some header
 * @param session
 * @param name
 * @param value
 * @return
 */
gboolean rspamd_milter_add_header (struct rspamd_milter_session *session,
								   GString *name, GString *value);

/**
 * Removes some header
 * @param session
 * @param name
 * @return
 */
gboolean rspamd_milter_del_header (struct rspamd_milter_session *session,
								   GString *name);

void rspamd_milter_session_unref (struct rspamd_milter_session *session);

struct rspamd_milter_session *rspamd_milter_session_ref (
		struct rspamd_milter_session *session);

/**
 * Converts milter session to HTTP session that is suitable for Rspamd
 * @param session
 * @return
 */
struct rspamd_http_message *rspamd_milter_to_http (
		struct rspamd_milter_session *session);

/**
 * Sends task results to the
 * @param session
 * @param results
 */
void rspamd_milter_send_task_results (struct rspamd_milter_session *session,
									  const ucl_object_t *results,
									  const gchar *new_body,
									  gsize bodylen);

/**
 * Init internal milter context
 * @param spam_header spam header name (must NOT be NULL)
 */
void rspamd_milter_init_library (const struct rspamd_milter_context *ctx);

/**
 * Returns pool for a session
 * @param session
 * @return
 */
rspamd_mempool_t *rspamd_milter_get_session_pool (
		struct rspamd_milter_session *session);

#ifdef  __cplusplus
}
#endif

#endif
