/*-
 * Copyright 2019 Vsevolod Stakhov
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
#ifndef RSPAMD_HTTP_MESSAGE_H
#define RSPAMD_HTTP_MESSAGE_H

#include "config.h"
#include "keypair.h"
#include "keypairs_cache.h"
#include "fstring.h"
#include "ref.h"


#ifdef  __cplusplus
extern "C" {
#endif

struct rspamd_http_connection;

enum rspamd_http_message_type {
	HTTP_REQUEST = 0, HTTP_RESPONSE
};

/**
 * Extract the current message from a connection to deal with separately
 * @param conn
 * @return
 */
struct rspamd_http_message *rspamd_http_connection_steal_msg (
		struct rspamd_http_connection *conn);

/**
 * Copy the current message from a connection to deal with separately
 * @param conn
 * @return
 */
struct rspamd_http_message *rspamd_http_connection_copy_msg (
		struct rspamd_http_message *msg, GError **err);

/**
 * Create new HTTP message
 * @param type request or response
 * @return new http message
 */
struct rspamd_http_message *rspamd_http_new_message (enum rspamd_http_message_type type);

/**
 * Increase refcount number for an HTTP message
 * @param msg message to use
 * @return
 */
struct rspamd_http_message *rspamd_http_message_ref (struct rspamd_http_message *msg);

/**
 * Decrease number of refcounts for http message
 * @param msg
 */
void rspamd_http_message_unref (struct rspamd_http_message *msg);

/**
 * Sets a key for peer
 * @param msg
 * @param pk
 */
void rspamd_http_message_set_peer_key (struct rspamd_http_message *msg,
									   struct rspamd_cryptobox_pubkey *pk);

/**
 * Create HTTP message from URL
 * @param url
 * @return new message or NULL
 */
struct rspamd_http_message *rspamd_http_message_from_url (const gchar *url);

/**
 * Returns body for a message
 * @param msg
 * @param blen pointer where to save body length
 * @return pointer to body start
 */
const gchar *rspamd_http_message_get_body (struct rspamd_http_message *msg,
										   gsize *blen);

/**
 * Set message's body from the string
 * @param msg
 * @param data
 * @param len
 * @return TRUE if a message's body has been set
 */
gboolean rspamd_http_message_set_body (struct rspamd_http_message *msg,
									   const gchar *data, gsize len);

/**
 * Set message's method by name
 * @param msg
 * @param method
 */
void rspamd_http_message_set_method (struct rspamd_http_message *msg,
									 const gchar *method);

/**
 * Maps fd as message's body
 * @param msg
 * @param fd
 * @return TRUE if a message's body has been set
 */
gboolean rspamd_http_message_set_body_from_fd (struct rspamd_http_message *msg,
											   gint fd);

/**
 * Uses rspamd_fstring_t as message's body, string is consumed by this operation
 * @param msg
 * @param fstr
 * @return TRUE if a message's body has been set
 */
gboolean rspamd_http_message_set_body_from_fstring_steal (struct rspamd_http_message *msg,
														  rspamd_fstring_t *fstr);

/**
 * Uses rspamd_fstring_t as message's body, string is copied by this operation
 * @param msg
 * @param fstr
 * @return TRUE if a message's body has been set
 */
gboolean rspamd_http_message_set_body_from_fstring_copy (struct rspamd_http_message *msg,
														 const rspamd_fstring_t *fstr);

/**
 * Appends data to message's body
 * @param msg
 * @param data
 * @param len
 * @return TRUE if a message's body has been set
 */
gboolean rspamd_http_message_append_body (struct rspamd_http_message *msg,
										  const gchar *data, gsize len);

/**
 * Append a header to http message
 * @param rep
 * @param name
 * @param value
 */
void rspamd_http_message_add_header (struct rspamd_http_message *msg,
									 const gchar *name,
									 const gchar *value);

void rspamd_http_message_add_header_len (struct rspamd_http_message *msg,
										 const gchar *name,
										 const gchar *value,
										 gsize len);

void rspamd_http_message_add_header_fstr (struct rspamd_http_message *msg,
										  const gchar *name,
										  rspamd_fstring_t *value);

/**
 * Search for a specified header in message
 * @param msg message
 * @param name name of header
 */
const rspamd_ftok_t *rspamd_http_message_find_header (
		struct rspamd_http_message *msg,
		const gchar *name);

/**
 * Search for a header that has multiple values
 * @param msg
 * @param name
 * @return list of rspamd_ftok_t * with values
 */
GPtrArray *rspamd_http_message_find_header_multiple (
		struct rspamd_http_message *msg,
		const gchar *name);

/**
 * Remove specific header from a message
 * @param msg
 * @param name
 * @return
 */
gboolean rspamd_http_message_remove_header (struct rspamd_http_message *msg,
											const gchar *name);

/**
 * Free HTTP message
 * @param msg
 */
void rspamd_http_message_free (struct rspamd_http_message *msg);

/**
 * Extract arguments from a message's URI contained inside query string decoding
 * them if needed
 * @param msg HTTP request message
 * @return new GHashTable which maps rspamd_ftok_t* to rspamd_ftok_t*
 * (table must be freed by a caller)
 */
GHashTable *rspamd_http_message_parse_query (struct rspamd_http_message *msg);

/**
 * Increase refcount for shared file (if any) to prevent early memory unlinking
 * @param msg
 */
struct rspamd_storage_shmem *rspamd_http_message_shmem_ref (struct rspamd_http_message *msg);

/**
 * Decrease external ref for shmem segment associated with a message
 * @param msg
 */
void rspamd_http_message_shmem_unref (struct rspamd_storage_shmem *p);

/**
 * Returns message's flags
 * @param msg
 * @return
 */
guint rspamd_http_message_get_flags (struct rspamd_http_message *msg);

#ifdef  __cplusplus
}
#endif

#endif
