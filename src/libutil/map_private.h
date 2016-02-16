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
#ifndef SRC_LIBUTIL_MAP_PRIVATE_H_
#define SRC_LIBUTIL_MAP_PRIVATE_H_

#include "config.h"
#include "mem_pool.h"
#include "keypair.h"
#include "unix-std.h"

enum fetch_proto {
	MAP_PROTO_FILE,
	MAP_PROTO_HTTP,
};
struct rspamd_map {
	rspamd_mempool_t *pool;
	struct rspamd_dns_resolver *r;
	gboolean is_signed;
	struct rspamd_cryptobox_pubkey *trusted_pubkey;
	struct rspamd_config *cfg;
	enum fetch_proto protocol;
	map_cb_t read_callback;
	map_fin_cb_t fin_callback;
	void **user_data;
	struct event ev;
	struct timeval tv;
	struct event_base *ev_base;
	void *map_data;
	gchar *uri;
	gchar *description;
	guint32 id;
	guint32 checksum;
	/* Shared lock for temporary disabling of map reading (e.g. when this map is written by UI) */
	gint *locked;
};

/**
 * Data specific to file maps
 */
struct file_map_data {
	const gchar *filename;
	struct stat st;
};

/**
 * Data specific to HTTP maps
 */
struct http_map_data {
	struct addrinfo *addr;
	guint16 port;
	gchar *path;
	gchar *host;
	time_t last_checked;
	gboolean request_sent;
};


struct http_callback_data {
	struct event_base *ev_base;
	struct rspamd_http_connection *conn;
	rspamd_inet_addr_t *addr;
	struct timeval tv;
	struct rspamd_map *map;
	struct http_map_data *data;
	struct map_cb_data cbdata;
	struct rspamd_cryptobox_pubkey *pk;

	enum {
		map_resolve_host2 = 0, /* 2 requests sent */
		map_resolve_host1, /* 1 requests sent */
		map_load_file,
		map_load_pubkey,
		map_load_signature
	} stage;
	gint out_fd;
	gchar *tmpfile;
	gint fd;
};

#endif /* SRC_LIBUTIL_MAP_PRIVATE_H_ */
