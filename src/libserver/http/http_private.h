/*-
 * Copyright 2016 Vsevolod Stakhov
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
#ifndef SRC_LIBUTIL_HTTP_PRIVATE_H_
#define SRC_LIBUTIL_HTTP_PRIVATE_H_

#include "http_connection.h"
#include "http_parser.h"
#include "str_util.h"
#include "keypair.h"
#include "keypairs_cache.h"
#include "ref.h"
#include "upstream.h"
#include "khash.h"

#ifdef  __cplusplus
extern "C" {
#endif

/**
 * HTTP header structure
 */
struct rspamd_http_header {
	rspamd_fstring_t *combined;
	rspamd_ftok_t name;
	rspamd_ftok_t value;
	struct rspamd_http_header *prev, *next;
};

KHASH_INIT (rspamd_http_headers_hash, rspamd_ftok_t *,
		struct rspamd_http_header *, 1,
		rspamd_ftok_icase_hash, rspamd_ftok_icase_equal);

/**
 * HTTP message structure, used for requests and replies
 */
struct rspamd_http_message {
	rspamd_fstring_t *url;
	GString *host;
	rspamd_fstring_t *status;
	khash_t (rspamd_http_headers_hash) *headers;

	struct _rspamd_body_buf_s {
		/* Data start */
		const gchar *begin;
		/* Data len */
		gsize len;
		/* Allocated len */
		gsize allocated_len;
		/* Data buffer (used to write data inside) */
		gchar *str;

		/* Internal storage */
		union _rspamd_storage_u {
			rspamd_fstring_t *normal;
			struct _rspamd_storage_shared_s {
				struct rspamd_storage_shmem *name;
				gint shm_fd;
			} shared;
		} c;
	} body_buf;

	struct rspamd_cryptobox_pubkey *peer_key;
	time_t date;
	time_t last_modified;
	unsigned port;
	int type;
	gint code;
	enum http_method method;
	gint flags;
	ref_entry_t ref;
};

struct rspamd_keepalive_hash_key {
	rspamd_inet_addr_t *addr;
	gchar *host;
	GQueue conns;
};

gint32 rspamd_keep_alive_key_hash (struct rspamd_keepalive_hash_key *k);

bool rspamd_keep_alive_key_equal (struct rspamd_keepalive_hash_key *k1,
								  struct rspamd_keepalive_hash_key *k2);

KHASH_INIT (rspamd_keep_alive_hash, struct rspamd_keepalive_hash_key *,
		char, 0, rspamd_keep_alive_key_hash, rspamd_keep_alive_key_equal);

struct rspamd_http_context {
	struct rspamd_http_context_cfg config;
	struct rspamd_keypair_cache *client_kp_cache;
	struct rspamd_cryptobox_keypair *client_kp;
	struct rspamd_keypair_cache *server_kp_cache;
	struct upstream_ctx *ups_ctx;
	struct upstream_list *http_proxies;
	gpointer ssl_ctx;
	gpointer ssl_ctx_noverify;
	struct ev_loop *event_loop;
	ev_timer client_rotate_ev;
	khash_t (rspamd_keep_alive_hash) *keep_alive_hash;
};

#define HTTP_ERROR http_error_quark ()

GQuark http_error_quark (void);

void rspamd_http_message_storage_cleanup (struct rspamd_http_message *msg);

gboolean rspamd_http_message_grow_body (struct rspamd_http_message *msg,
										gsize len);

#ifdef  __cplusplus
}
#endif

#endif /* SRC_LIBUTIL_HTTP_PRIVATE_H_ */
