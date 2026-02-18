/*
 * Copyright 2026 Vsevolod Stakhov
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

#ifndef RSPAMD_FUZZY_STORAGE_INTERNAL_H
#define RSPAMD_FUZZY_STORAGE_INTERNAL_H

#include "config.h"

#include "rspamd.h"
#include "ref.h"
#include "libserver/fuzzy_wire.h"
#include "libutil/hash.h"
#include "contrib/libev/ev.h"
#include "contrib/libucl/khash.h"

#include <string.h>

struct map_cb_data;
struct rspamd_rcl_section;
struct rspamd_rcl_struct_parser;
struct rspamd_control_command;

struct rspamd_main;
struct rspamd_worker;
struct rspamd_dns_resolver;
struct rspamd_radix_map_helper;
struct rspamd_hash_map_helper;
struct rspamd_keypair_cache;
struct rspamd_http_context;
struct rspamd_fuzzy_backend;

struct rspamd_cryptobox_keypair;
struct rspamd_cryptobox_pubkey;

struct fuzzy_tcp_session;

struct fuzzy_global_stat {
	uint64_t fuzzy_hashes;
	uint64_t fuzzy_hashes_expired;
	uint64_t fuzzy_hashes_checked[RSPAMD_FUZZY_EPOCH_MAX];
	uint64_t fuzzy_shingles_checked[RSPAMD_FUZZY_EPOCH_MAX];
	uint64_t fuzzy_hashes_found[RSPAMD_FUZZY_EPOCH_MAX];
	uint64_t invalid_requests;
	uint64_t delayed_hashes;
};

struct fuzzy_key_stat {
	uint64_t checked;
	uint64_t matched;
	uint64_t added;
	uint64_t deleted;
	uint64_t errors;
	struct rspamd_counter_data checked_ctr;
	struct rspamd_counter_data matched_ctr;
	double last_checked_time;
	uint64_t last_checked_count;
	uint64_t last_matched_count;
	struct rspamd_cryptobox_keypair *keypair;
	rspamd_lru_hash_t *last_ips;

	ref_entry_t ref;
};

struct rspamd_leaky_bucket_elt {
	rspamd_inet_addr_t *addr;
	double last;
	double cur;
};

static inline int64_t
fuzzy_kp_hash(const unsigned char *p)
{
	int64_t res;

	memcpy(&res, p, sizeof(res));
	return res;
}

static inline bool
fuzzy_kp_equal(gconstpointer a, gconstpointer b)
{
	const unsigned char *pa = a, *pb = b;

	return (memcmp(pa, pb, RSPAMD_FUZZY_KEYLEN) == 0);
}

enum fuzzy_key_op {
	FUZZY_KEY_READ = 0x1u << 0,
	FUZZY_KEY_WRITE = 0x1u << 1,
	FUZZY_KEY_DELETE = 0x1u << 2,
};

KHASH_SET_INIT_INT(fuzzy_key_ids_set);
KHASH_INIT(fuzzy_key_flag_stat, int, struct fuzzy_key_stat, 1, kh_int_hash_func,
		   kh_int_hash_equal);

struct fuzzy_key {
	char *name;
	struct rspamd_cryptobox_keypair *key;
	struct rspamd_cryptobox_pubkey *pk;
	struct fuzzy_key_stat *stat;
	khash_t(fuzzy_key_flag_stat) * flags_stat;
	khash_t(fuzzy_key_ids_set) * forbidden_ids;
	struct rspamd_leaky_bucket_elt *rl_bucket;
	ucl_object_t *extensions;
	double burst;
	double rate;
	ev_tstamp expire;
	bool expired;
	int flags; /* enum fuzzy_key_op */
	ref_entry_t ref;
};

KHASH_INIT(rspamd_fuzzy_keys_hash,
		   const unsigned char *, struct fuzzy_key *, 1,
		   fuzzy_kp_hash, fuzzy_kp_equal);

struct rspamd_lua_fuzzy_script {
	int cbref;
	struct rspamd_lua_fuzzy_script *next;
};

struct rspamd_fuzzy_storage_ctx {
	uint64_t magic;
	struct ev_loop *event_loop;
	struct rspamd_dns_resolver *resolver;
	struct rspamd_config *cfg;
	struct fuzzy_global_stat stat;
	double expire;
	double sync_timeout;
	double delay;
	double tcp_timeout;
	struct rspamd_radix_map_helper *update_ips;
	struct rspamd_hash_map_helper *update_keys;
	struct rspamd_radix_map_helper *blocked_ips;
	struct rspamd_radix_map_helper *ratelimit_whitelist;
	struct rspamd_radix_map_helper *delay_whitelist;

	const ucl_object_t *update_map;
	const ucl_object_t *update_keys_map;
	const ucl_object_t *delay_whitelist_map;
	const ucl_object_t *blocked_map;
	const ucl_object_t *ratelimit_whitelist_map;
	const ucl_object_t *dynamic_keys_map;

	unsigned int keypair_cache_size;
	ev_timer stat_ev;
	ev_io peer_ev;

	struct rspamd_cryptobox_keypair *default_keypair;
	struct fuzzy_key *default_key;
	khash_t(rspamd_fuzzy_keys_hash) * keys;
	khash_t(rspamd_fuzzy_keys_hash) * dynamic_keys;

	gboolean encrypted_only;
	gboolean read_only;
	gboolean dedicated_update_worker;
	struct rspamd_keypair_cache *keypair_cache;
	struct rspamd_http_context *http_ctx;
	rspamd_lru_hash_t *errors_ips;
	rspamd_lru_hash_t *ratelimit_buckets;
	struct rspamd_fuzzy_backend *backend;
	GArray *updates_pending;
	unsigned int updates_failed;
	unsigned int updates_maxfail;
	int peer_fd;

	unsigned int leaky_bucket_ttl;
	unsigned int leaky_bucket_mask;
	unsigned int max_buckets;
	gboolean ratelimit_log_only;
	double leaky_bucket_burst;
	double leaky_bucket_rate;

	struct rspamd_worker *worker;
	const ucl_object_t *skip_map;
	struct rspamd_hash_map_helper *skip_hashes;
	struct rspamd_lua_fuzzy_script *lua_pre_handlers;
	struct rspamd_lua_fuzzy_script *lua_post_handlers;
	struct rspamd_lua_fuzzy_script *lua_blacklist_handlers;
	khash_t(fuzzy_key_ids_set) * default_forbidden_ids;
	khash_t(fuzzy_key_ids_set) * weak_ids;
};

enum fuzzy_cmd_type {
	CMD_NORMAL,
	CMD_SHINGLE,
	CMD_ENCRYPTED_NORMAL,
	CMD_ENCRYPTED_SHINGLE
};

/* Legacy structure name for compatibility during refactoring */
struct fuzzy_session {
	struct rspamd_worker *worker;
	rspamd_inet_addr_t *addr;
	struct rspamd_fuzzy_storage_ctx *ctx;

	struct rspamd_fuzzy_shingle_cmd cmd;       /* Can handle both shingles and non-shingles */
	union {
		struct rspamd_fuzzy_encrypted_reply v1;
		struct rspamd_fuzzy_encrypted_reply_v2 v2;
	} reply;
	struct fuzzy_key_stat *ip_stat;

	enum rspamd_fuzzy_epoch epoch;
	enum fuzzy_cmd_type cmd_type;
	int fd;
	ev_tstamp timestamp;
	struct ev_io io;
	ref_entry_t ref;
	struct fuzzy_key *key;
	struct rspamd_fuzzy_cmd_extension *extensions;
	unsigned char nm[rspamd_cryptobox_MAX_NMBYTES];

	/* If this is a TCP session, this pointer will be set */
	struct fuzzy_tcp_session *tcp_session;
};

enum rspamd_ratelimit_event_type {
	RATELIMIT_EVENT_NEW,
	RATELIMIT_EVENT_EXISTING,
	RATELIMIT_EVENT_BLACKLIST,
};

struct rspamd_ratelimit_callback_ctx {
	rspamd_inet_addr_t *addr;
	const char *reason;
	enum rspamd_ratelimit_event_type type;

	struct rspamd_leaky_bucket_elt *bucket;
	double max_burst;
	double max_rate;

	struct fuzzy_session *session;
};

struct fuzzy_keymap_ucl_buf {
	rspamd_fstring_t *buf;
	struct rspamd_fuzzy_storage_ctx *ctx;
};

enum rspamd_ratelimit_check_result {
	ratelimit_pass,
	ratelimit_new,
	ratelimit_existing,
};

enum rspamd_ratelimit_check_policy {
	ratelimit_policy_permanent,
	ratelimit_policy_normal,
};

/* Keys/dynamic map */
char *ucl_keymap_read_cb(char *chunk, int len, struct map_cb_data *data, gboolean final);
void ucl_keymap_fin_cb(struct map_cb_data *data, void **target);
void ucl_keymap_dtor_cb(struct map_cb_data *data);

void fuzzy_key_stat_dtor(gpointer p);
void fuzzy_key_stat_unref(gpointer p);
void fuzzy_key_dtor(gpointer p);
void fuzzy_hash_table_dtor(khash_t(rspamd_fuzzy_keys_hash) * hash);

gboolean fuzzy_parse_ids(rspamd_mempool_t *pool, const ucl_object_t *obj,
						 gpointer ud, struct rspamd_rcl_section *section, GError **err);
struct fuzzy_key *fuzzy_add_keypair_from_ucl(struct rspamd_config *cfg, const ucl_object_t *obj,
											 khash_t(rspamd_fuzzy_keys_hash) * target);
gboolean fuzzy_parse_keypair(rspamd_mempool_t *pool, const ucl_object_t *obj,
							 gpointer ud, struct rspamd_rcl_section *section, GError **err);

/* Ratelimit */
void fuzzy_rl_bucket_free(gpointer p);

enum rspamd_ratelimit_check_result rspamd_fuzzy_check_ratelimit_bucket(
	struct rspamd_fuzzy_storage_ctx *ctx,
	rspamd_inet_addr_t *addr,
	ev_tstamp timestamp,
	struct rspamd_leaky_bucket_elt *elt,
	enum rspamd_ratelimit_check_policy policy,
	double max_burst, double max_rate);

gboolean rspamd_fuzzy_check_ratelimit(struct rspamd_fuzzy_storage_ctx *ctx,
									  rspamd_inet_addr_t *addr,
									  struct rspamd_worker *worker,
									  ev_tstamp timestamp);

void rspamd_fuzzy_call_ratelimit_handlers(struct rspamd_fuzzy_storage_ctx *ctx,
										  const struct rspamd_ratelimit_callback_ctx *cb_ctx);
void rspamd_fuzzy_maybe_call_blacklisted(struct rspamd_fuzzy_storage_ctx *ctx,
										 rspamd_inet_addr_t *addr,
										 const char *reason);

gboolean rspamd_fuzzy_check_client(struct rspamd_fuzzy_storage_ctx *ctx,
								   rspamd_inet_addr_t *addr);

ucl_object_t *rspamd_leaky_bucket_to_ucl(struct rspamd_leaky_bucket_elt *p_elt);
void rspamd_fuzzy_maybe_load_ratelimits(struct rspamd_fuzzy_storage_ctx *ctx);
void rspamd_fuzzy_maybe_save_ratelimits(struct rspamd_fuzzy_storage_ctx *ctx);

/* Stats / controller */
ucl_object_t *rspamd_fuzzy_storage_stat_key(const struct fuzzy_key_stat *key_stat);
void rspamd_fuzzy_key_stat_iter(const unsigned char *pk_iter,
								struct fuzzy_key *fuzzy_key,
								ucl_object_t *keys_obj,
								gboolean ip_stat);
ucl_object_t *rspamd_fuzzy_stat_to_ucl(struct rspamd_fuzzy_storage_ctx *ctx, gboolean ip_stat);

gboolean rspamd_fuzzy_storage_stat(struct rspamd_main *rspamd_main,
								   struct rspamd_worker *worker, int fd,
								   int attached_fd,
								   struct rspamd_control_command *cmd,
								   gpointer ud);

#endif
