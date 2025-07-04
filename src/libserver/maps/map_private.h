/*
 * Copyright 2025 Vsevolod Stakhov
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
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
#include "map.h"
#include "ref.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*rspamd_map_tmp_dtor)(gpointer p);

extern unsigned int rspamd_map_log_id;
#define msg_err_map(...) rspamd_default_log_function(G_LOG_LEVEL_CRITICAL, \
													 "map", map->tag,      \
													 RSPAMD_LOG_FUNC,      \
													 __VA_ARGS__)
#define msg_warn_map(...) rspamd_default_log_function(G_LOG_LEVEL_WARNING, \
													  "map", map->tag,     \
													  RSPAMD_LOG_FUNC,     \
													  __VA_ARGS__)
#define msg_info_map(...) rspamd_default_log_function(G_LOG_LEVEL_INFO, \
													  "map", map->tag,  \
													  RSPAMD_LOG_FUNC,  \
													  __VA_ARGS__)
#define msg_debug_map(...) rspamd_conditional_debug_fast(NULL, NULL,                         \
														 rspamd_map_log_id, "map", map->tag, \
														 RSPAMD_LOG_FUNC,                    \
														 __VA_ARGS__)

enum fetch_proto {
	MAP_PROTO_FILE,
	MAP_PROTO_HTTP,
	MAP_PROTO_HTTPS,
	MAP_PROTO_STATIC
};

static const char *
rspamd_map_fetch_protocol_name(enum fetch_proto proto)
{
	switch (proto) {
	case MAP_PROTO_FILE:
		return "file";
	case MAP_PROTO_HTTP:
		return "http";
	case MAP_PROTO_HTTPS:
		return "https";
	case MAP_PROTO_STATIC:
		return "static";
	default:
		return "unknown";
	}
}

/**
 * Data specific to file maps
 */
struct file_map_data {
	char *filename;
	gboolean need_modify;
	ev_stat st_ev;
};


struct http_map_data;

struct rspamd_http_map_cached_cbdata {
	ev_timer timeout;
	struct ev_loop *event_loop;
	struct rspamd_storage_shmem *shm;
	struct rspamd_map *map;
	struct http_map_data *data;
	uint64_t gen;
	time_t last_checked;
};

struct rspamd_http_map_cache {
	int available;
	gsize len;
	time_t last_modified;
	char shmem_name[256];
};

/**
 * Data specific to HTTP maps
 */
struct http_map_data {
	/* Shared cache data */
	struct rspamd_http_map_cache *cache;
	/* Non-shared for cache owner, used to cleanup cache */
	struct rspamd_http_map_cached_cbdata *cur_cache_cbd;
	char *userinfo;
	char *path;
	char *host;
	char *rest;
	rspamd_fstring_t *etag;
	time_t last_modified;
	time_t last_checked;
	gboolean request_sent;
	uint64_t gen;
	uint16_t port;
};

struct static_map_data {
	unsigned char *data;
	gsize len;
	gboolean processed;
};

union rspamd_map_backend_data {
	struct file_map_data *fd;
	struct http_map_data *hd;
	struct static_map_data *sd;
};


struct rspamd_map;

struct rspamd_map_backend {
	enum fetch_proto protocol;
	gboolean is_signed;
	gboolean is_compressed;
	gboolean is_fallback;
	struct rspamd_map *map;
	struct ev_loop *event_loop;
	uint64_t id;
	struct rspamd_cryptobox_pubkey *trusted_pubkey;
	union rspamd_map_backend_data data;
	char *uri;
	ref_entry_t ref;
};

struct map_periodic_cbdata;

/*
 * Shared between workers
 */
struct rspamd_map_shared_data {
	int loaded;
	int cached;
};

struct rspamd_map {
	struct rspamd_dns_resolver *r;
	struct rspamd_config *cfg;
	GPtrArray *backends;
	struct rspamd_map_backend *fallback_backend;
	map_cb_t read_callback;
	map_fin_cb_t fin_callback;
	map_dtor_t dtor;
	void **user_data;
	struct ev_loop *event_loop;
	struct rspamd_worker *wrk;
	char *description;
	char *name;
	uint32_t id;
	struct map_periodic_cbdata *scheduled_check;
	rspamd_map_tmp_dtor tmp_dtor;
	gpointer tmp_dtor_data;
	rspamd_map_traverse_function traverse_function;
	rspamd_map_on_load_function on_load_function;
	gpointer on_load_ud;
	GDestroyNotify on_load_ud_dtor;
	gpointer lua_map;
	gsize nelts;
	uint64_t digest;
	/* Should we check HTTP or just load cached data */
	ev_tstamp timeout;
	double poll_timeout;
	time_t next_check;
	bool active_http;
	bool non_trivial;  /* E.g. has http backends in active mode */
	bool file_only;    /* No HTTP backends found */
	bool static_only;  /* No need to check */
	bool no_file_read; /* Do not read files */
	bool seen;         /* This map has already been watched or pre-loaded */
	/* Shared lock for temporary disabling of map reading (e.g. when this map is written by UI) */
	struct rspamd_map_shared_data *shared;
	char tag[MEMPOOL_UID_LEN];
};

enum rspamd_map_http_stage {
	http_map_resolve_host2 = 0, /* 2 requests sent */
	http_map_resolve_host1,     /* 1 requests sent */
	http_map_http_conn,         /* http connection */
	http_map_terminated         /* terminated when doing resolving */
};

struct map_periodic_cbdata {
	struct rspamd_map *map;
	struct map_cb_data cbdata;
	ev_timer ev;
	gboolean need_modify;
	gboolean errored;
	unsigned int cur_backend;
	ref_entry_t ref;
};

static const char rspamd_http_file_magic[] =
	{'r', 'm', 'c', 'd', '2', '0', '0', '0'};

struct rspamd_http_file_data {
	unsigned char magic[sizeof(rspamd_http_file_magic)];
	goffset data_off;
	gulong mtime;
	gulong next_check;
	gulong etag_len;
};

struct http_callback_data {
	struct ev_loop *event_loop;
	struct rspamd_http_connection *conn;
	GPtrArray *addrs;
	rspamd_inet_addr_t *addr;
	struct rspamd_map *map;
	struct rspamd_map_backend *bk;
	struct http_map_data *data;
	struct map_periodic_cbdata *periodic;
	struct rspamd_cryptobox_pubkey *pk;
	struct rspamd_storage_shmem *shmem_data;
	gsize data_len;
	gboolean check;
	enum rspamd_map_http_stage stage;
	ev_tstamp timeout;

	ref_entry_t ref;
};

#ifdef __cplusplus
}
#endif

#endif /* SRC_LIBUTIL_MAP_PRIVATE_H_ */
