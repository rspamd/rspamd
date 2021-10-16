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
/***MODULE:fuzzy
 * rspamd module that checks fuzzy checksums for messages
 *
 * Allowed options:
 * - symbol (string): symbol to insert (default: 'R_FUZZY')
 * - max_score (double): maximum score to that weights of hashes would be normalized (default: 0 - no normalization)
 *
 * - fuzzy_map (string): a string that contains map in format { fuzzy_key => [ symbol, weight ] } where fuzzy_key is number of
 *   fuzzy list. This string itself should be in format 1:R_FUZZY_SAMPLE1:10,2:R_FUZZY_SAMPLE2:1 etc, where first number is fuzzy
 *   key, second is symbol to insert and third - weight for normalization
 *
 * - min_length (integer): minimum length (in characters) for text part to be checked for fuzzy hash (default: 0 - no limit)
 * - whitelist (map string): map of ip addresses that should not be checked with this module
 * - servers (string): list of fuzzy servers in format "server1:port,server2:port" - these servers would be used for checking and storing
 *   fuzzy hashes
 */

#include "config.h"
#include "libmime/message.h"
#include "libserver/maps/map.h"
#include "libserver/maps/map_helpers.h"
#include "libmime/images.h"
#include "libserver/worker_util.h"
#include "libserver/mempool_vars_internal.h"
#include "fuzzy_wire.h"
#include "utlist.h"
#include "ottery.h"
#include "lua/lua_common.h"
#include "unix-std.h"
#include "libserver/http/http_private.h"
#include "libserver/http/http_router.h"
#include "libstat/stat_api.h"
#include <math.h>
#include "libutil/libev_helper.h"

#define DEFAULT_SYMBOL "R_FUZZY_HASH"

#define DEFAULT_IO_TIMEOUT 1.0
#define DEFAULT_RETRANSMITS 3
#define DEFAULT_MAX_ERRORS 4
#define DEFAULT_REVIVE_TIME 60
#define DEFAULT_PORT 11335

#define RSPAMD_FUZZY_PLUGIN_VERSION RSPAMD_FUZZY_VERSION

static const gint rspamd_fuzzy_hash_len = 5;
static const gchar *M = "fuzzy check";
struct fuzzy_ctx;

struct fuzzy_mapping {
	guint64 fuzzy_flag;
	const gchar *symbol;
	double weight;
};

struct fuzzy_rule {
	struct upstream_list *servers;
	const gchar *symbol;
	const gchar *algorithm_str;
	const gchar *name;
	const ucl_object_t *ucl_obj;
	enum rspamd_shingle_alg alg;
	GHashTable *mappings;
	GPtrArray *fuzzy_headers;
	GString *hash_key;
	GString *shingles_key;
	gdouble io_timeout;
	struct rspamd_cryptobox_keypair *local_key;
	struct rspamd_cryptobox_pubkey *peer_key;
	double max_score;
	double weight_threshold;
	gboolean read_only;
	gboolean skip_unknown;
	gboolean no_share;
	gboolean no_subject;
	gint learn_condition_cb;
	guint32 retransmits;
	struct rspamd_hash_map_helper *skip_map;
	struct fuzzy_ctx *ctx;
	gint lua_id;
};

struct fuzzy_ctx {
	struct module_ctx ctx;
	rspamd_mempool_t *fuzzy_pool;
	GPtrArray *fuzzy_rules;
	struct rspamd_config *cfg;
	const gchar *default_symbol;
	struct rspamd_radix_map_helper *whitelist;
	struct rspamd_keypair_cache *keypairs_cache;
	guint   max_errors;
	gdouble revive_time;
	gdouble io_timeout;
	gint check_mime_part_ref; /* Lua callback */
	gint process_rule_ref; /* Lua callback */
	gint cleanup_rules_ref;
	guint32 retransmits;
	gboolean enabled;
};

enum fuzzy_result_type {
	FUZZY_RESULT_TXT,
	FUZZY_RESULT_IMG,
	FUZZY_RESULT_CONTENT,
	FUZZY_RESULT_BIN
};

struct fuzzy_client_result {
	const gchar *symbol;
	gchar *option;
	gdouble score;
	gdouble prob;
	enum fuzzy_result_type type;
};

struct fuzzy_client_session {
	GPtrArray *commands;
	GPtrArray *results;
	struct rspamd_task *task;
	struct rspamd_symcache_item *item;
	struct upstream *server;
	struct fuzzy_rule *rule;
	struct ev_loop *event_loop;
	struct rspamd_io_ev ev;
	gint state;
	gint fd;
	guint retransmits;
};

struct fuzzy_learn_session {
	GPtrArray *commands;
	gint *saved;
	struct {
		const gchar *error_message;
		gint error_code;
	} err;
	struct rspamd_http_connection_entry *http_entry;
	struct rspamd_async_session *session;
	struct upstream *server;
	struct fuzzy_rule *rule;
	struct rspamd_task *task;
	struct ev_loop *event_loop;
	struct rspamd_io_ev ev;
	gint fd;
	guint retransmits;
};

#define FUZZY_CMD_FLAG_REPLIED (1 << 0)
#define FUZZY_CMD_FLAG_SENT (1 << 1)
#define FUZZY_CMD_FLAG_IMAGE (1 << 2)
#define FUZZY_CMD_FLAG_CONTENT (1 << 3)

#define FUZZY_CHECK_FLAG_NOIMAGES (1 << 0)
#define FUZZY_CHECK_FLAG_NOATTACHMENTS (1 << 1)
#define FUZZY_CHECK_FLAG_NOTEXT (1 << 2)

struct fuzzy_cmd_io {
	guint32 tag;
	guint32 flags;
	struct iovec io;
	struct rspamd_mime_part *part;
	struct rspamd_fuzzy_cmd cmd;
};


static const char *default_headers = "Subject,Content-Type,Reply-To,X-Mailer";

static void fuzzy_symbol_callback (struct rspamd_task *task,
								   struct rspamd_symcache_item *item,
								   void *unused);

/* Initialization */
gint fuzzy_check_module_init (struct rspamd_config *cfg,
	struct module_ctx **ctx);
gint fuzzy_check_module_config (struct rspamd_config *cfg, bool valdate);
gint fuzzy_check_module_reconfig (struct rspamd_config *cfg);
static gint fuzzy_attach_controller (struct module_ctx *ctx,
	GHashTable *commands);
static gint fuzzy_lua_learn_handler (lua_State *L);
static gint fuzzy_lua_unlearn_handler (lua_State *L);
static gint fuzzy_lua_gen_hashes_handler (lua_State *L);

module_t fuzzy_check_module = {
		"fuzzy_check",
		fuzzy_check_module_init,
		fuzzy_check_module_config,
		fuzzy_check_module_reconfig,
		fuzzy_attach_controller,
		RSPAMD_MODULE_VER,
		(guint)-1,
};

static inline struct fuzzy_ctx *
fuzzy_get_context (struct rspamd_config *cfg)
{
	return (struct fuzzy_ctx *)g_ptr_array_index (cfg->c_modules,
			fuzzy_check_module.ctx_offset);
}

static void
parse_flags (struct fuzzy_rule *rule,
			 struct rspamd_config *cfg,
			 const ucl_object_t *val,
			 gint cb_id)
{
	const ucl_object_t *elt;
	struct fuzzy_mapping *map;
	const gchar *sym = NULL;

	if (val->type == UCL_STRING) {
		msg_err_config (
			"string mappings are deprecated and no longer supported, use new style configuration");
	}
	else if (val->type == UCL_OBJECT) {
		elt = ucl_object_lookup (val, "symbol");
		if (elt == NULL || !ucl_object_tostring_safe (elt, &sym)) {
			sym = ucl_object_key (val);
		}
		if (sym != NULL) {
			map =
				rspamd_mempool_alloc (cfg->cfg_pool,
					sizeof (struct fuzzy_mapping));
			map->symbol = sym;
			elt = ucl_object_lookup (val, "flag");

			if (elt != NULL) {
				map->fuzzy_flag = ucl_obj_toint (elt);

				elt = ucl_object_lookup (val, "max_score");

				if (elt != NULL) {
					map->weight = ucl_obj_todouble (elt);
				}
				else {
					map->weight = rule->max_score;
				}
				/* Add flag to hash table */
				g_hash_table_insert (rule->mappings,
					GINT_TO_POINTER (map->fuzzy_flag), map);
				rspamd_symcache_add_symbol (cfg->cache,
						map->symbol, 0,
						NULL, NULL,
						SYMBOL_TYPE_VIRTUAL | SYMBOL_TYPE_FINE,
						cb_id);
			}
			else {
				msg_err_config ("fuzzy_map parameter has no flag definition");
			}
		}
		else {
			msg_err_config ("fuzzy_map parameter has no symbol definition");
		}
	}
	else {
		msg_err_config ("fuzzy_map parameter is of an unsupported type");
	}
}

static GPtrArray *
parse_fuzzy_headers (struct rspamd_config *cfg, const gchar *str)
{
	gchar **strvec;
	gint num, i;
	GPtrArray *res;

	strvec = g_strsplit_set (str, ",", 0);
	num = g_strv_length (strvec);
	res = g_ptr_array_sized_new (num);

	for (i = 0; i < num; i++) {
		g_strstrip (strvec[i]);
		g_ptr_array_add (res, rspamd_mempool_strdup (
				cfg->cfg_pool, strvec[i]));
	}

	g_strfreev (strvec);

	return res;
}

static double
fuzzy_normalize (gint32 in, double weight)
{
	if (weight == 0) {
		return 0;
	}
#ifdef HAVE_TANH
	return tanh (G_E * (double)in / weight);
#else
	return (in < weight ? in / weight : weight);
#endif
}

static struct fuzzy_rule *
fuzzy_rule_new (const char *default_symbol, rspamd_mempool_t *pool)
{
	struct fuzzy_rule *rule;

	rule = rspamd_mempool_alloc0 (pool, sizeof (struct fuzzy_rule));

	rule->mappings = g_hash_table_new (g_direct_hash, g_direct_equal);
	rule->symbol = default_symbol;
	rspamd_mempool_add_destructor (pool,
		(rspamd_mempool_destruct_t)g_hash_table_unref,
		rule->mappings);
	rule->read_only = FALSE;
	rule->weight_threshold = NAN;

	return rule;
}

static void
fuzzy_free_rule (gpointer r)
{
	struct fuzzy_rule *rule = (struct fuzzy_rule *)r;

	g_string_free (rule->hash_key, TRUE);
	g_string_free (rule->shingles_key, TRUE);

	if (rule->local_key) {
		rspamd_keypair_unref (rule->local_key);
	}

	if (rule->peer_key) {
		rspamd_pubkey_unref (rule->peer_key);
	}
}

static gint
fuzzy_parse_rule (struct rspamd_config *cfg, const ucl_object_t *obj,
		const gchar *name, gint cb_id)
{
	const ucl_object_t *value, *cur;
	struct fuzzy_rule *rule;
	ucl_object_iter_t it = NULL;
	const char *k = NULL, *key_str = NULL, *shingles_key_str = NULL, *lua_script;
	struct fuzzy_ctx *fuzzy_module_ctx = fuzzy_get_context (cfg);

	if (obj->type != UCL_OBJECT) {
		msg_err_config ("invalid rule definition");
		return -1;
	}

	if ((value = ucl_object_lookup_any (obj, "enabled", "enable", NULL)) != NULL) {
		if (!ucl_object_toboolean (value)) {
			msg_info_config ("fuzzy rule %s is disabled by configuration", name);

			return 0;
		}
	}

	rule = fuzzy_rule_new (fuzzy_module_ctx->default_symbol,
			cfg->cfg_pool);
	rule->ucl_obj = obj;
	rule->ctx = fuzzy_module_ctx;
	rule->learn_condition_cb = -1;
	rule->alg = RSPAMD_SHINGLES_OLD;
	rule->skip_map = NULL;

	if ((value = ucl_object_lookup (obj, "skip_hashes")) != NULL) {
		rspamd_map_add_from_ucl (cfg, value,
				"Fuzzy hashes whitelist",
				rspamd_kv_list_read,
				rspamd_kv_list_fin,
				rspamd_kv_list_dtor,
				(void **)&rule->skip_map,
				NULL, RSPAMD_MAP_DEFAULT);
	}

	if ((value = ucl_object_lookup (obj, "headers")) != NULL) {
		it = NULL;
		while ((cur = ucl_object_iterate (value, &it, value->type == UCL_ARRAY))
				!= NULL) {
			GPtrArray *tmp;
			guint i;
			gpointer ptr;

			tmp = parse_fuzzy_headers (cfg, ucl_obj_tostring (cur));

			if (tmp) {
				if (rule->fuzzy_headers) {
					PTR_ARRAY_FOREACH (tmp, i, ptr) {
						g_ptr_array_add (rule->fuzzy_headers, ptr);
					}

					g_ptr_array_free (tmp, TRUE);
				}
				else {
					rule->fuzzy_headers = tmp;
				}
			}
		}
	}
	else {
		rule->fuzzy_headers = parse_fuzzy_headers (cfg, default_headers);
	}

	if (rule->fuzzy_headers != NULL) {
		rspamd_mempool_add_destructor (cfg->cfg_pool,
				(rspamd_mempool_destruct_t) rspamd_ptr_array_free_hard,
				rule->fuzzy_headers);
	}


	if ((value = ucl_object_lookup (obj, "max_score")) != NULL) {
		rule->max_score = ucl_obj_todouble (value);
	}

	if ((value = ucl_object_lookup (obj, "retransmits")) != NULL) {
		rule->retransmits = ucl_obj_toint (value);
	}
	else {
		rule->retransmits = fuzzy_module_ctx->retransmits;
	}

	if ((value = ucl_object_lookup (obj, "timeout")) != NULL) {
		rule->io_timeout = ucl_obj_todouble (value);
	}
	else {
		rule->io_timeout = fuzzy_module_ctx->io_timeout;
	}

	if ((value = ucl_object_lookup (obj,  "symbol")) != NULL) {
		rule->symbol = ucl_obj_tostring (value);
	}

	if (name) {
		rule->name = name;
	}
	else {
		rule->name = rule->symbol;
	}


	if ((value = ucl_object_lookup (obj, "read_only")) != NULL) {
		rule->read_only = ucl_obj_toboolean (value);
	}

	if ((value = ucl_object_lookup (obj, "skip_unknown")) != NULL) {
		rule->skip_unknown = ucl_obj_toboolean (value);
	}

	if ((value = ucl_object_lookup (obj, "no_share")) != NULL) {
		rule->no_share = ucl_obj_toboolean (value);
	}

	if ((value = ucl_object_lookup (obj, "no_subject")) != NULL) {
		rule->no_subject = ucl_obj_toboolean (value);
	}

	if ((value = ucl_object_lookup (obj, "algorithm")) != NULL) {
		rule->algorithm_str = ucl_object_tostring (value);

		if (rule->algorithm_str) {
			if (g_ascii_strcasecmp (rule->algorithm_str, "old") == 0 ||
					g_ascii_strcasecmp (rule->algorithm_str, "siphash") == 0) {
				rule->alg = RSPAMD_SHINGLES_OLD;
			}
			else if (g_ascii_strcasecmp (rule->algorithm_str, "xxhash") == 0) {
				rule->alg = RSPAMD_SHINGLES_XXHASH;
			}
			else if (g_ascii_strcasecmp (rule->algorithm_str, "mumhash") == 0) {
				rule->alg = RSPAMD_SHINGLES_MUMHASH;
			}
			else if (g_ascii_strcasecmp (rule->algorithm_str, "fasthash") == 0 ||
					g_ascii_strcasecmp (rule->algorithm_str, "fast") == 0) {
				rule->alg = RSPAMD_SHINGLES_FAST;
			}
			else {
				msg_warn_config ("unknown algorithm: %s, use siphash by default",
						rule->algorithm_str);
			}
		}
	}

	/* Set a consistent and short string name */
	switch (rule->alg) {
	case RSPAMD_SHINGLES_OLD:
		rule->algorithm_str = "sip";
		break;
	case RSPAMD_SHINGLES_XXHASH:
		rule->algorithm_str = "xx";
		break;
	case RSPAMD_SHINGLES_MUMHASH:
		rule->algorithm_str = "mum";
		break;
	case RSPAMD_SHINGLES_FAST:
		rule->algorithm_str = "fast";
		break;
	}

	if ((value = ucl_object_lookup (obj, "servers")) != NULL) {
		rule->servers = rspamd_upstreams_create (cfg->ups_ctx);
		/* pass max_error and revive_time configuration in upstream for fuzzy storage
		 * it allows to configure error_rate threshold and upstream dead timer
		 */
		rspamd_upstreams_set_limits (rule->servers,
				(gdouble) fuzzy_module_ctx->revive_time, NAN, NAN, NAN,
				(guint) fuzzy_module_ctx->max_errors, 0);

		rspamd_mempool_add_destructor (cfg->cfg_pool,
				(rspamd_mempool_destruct_t)rspamd_upstreams_destroy,
				rule->servers);
		if (!rspamd_upstreams_from_ucl (rule->servers, value, DEFAULT_PORT, NULL)) {
			msg_err_config ("cannot read servers definition");
			return -1;
		}
	}
	if ((value = ucl_object_lookup (obj, "fuzzy_map")) != NULL) {
		it = NULL;
		while ((cur = ucl_object_iterate (value, &it, true)) != NULL) {
			parse_flags (rule, cfg, cur, cb_id);
		}
	}

	if ((value = ucl_object_lookup (obj, "encryption_key")) != NULL) {
		/* Create key from user's input */
		k = ucl_object_tostring (value);

		if (k == NULL || (rule->peer_key =
				rspamd_pubkey_from_base32 (k, 0, RSPAMD_KEYPAIR_KEX,
						RSPAMD_CRYPTOBOX_MODE_25519)) == NULL) {
			msg_err_config ("bad encryption key value: %s",
					k);
			return -1;
		}

		rule->local_key = rspamd_keypair_new (RSPAMD_KEYPAIR_KEX,
				RSPAMD_CRYPTOBOX_MODE_25519);
	}

	if ((value = ucl_object_lookup (obj, "learn_condition")) != NULL) {
		lua_script = ucl_object_tostring (value);

		if (lua_script) {
			if (luaL_dostring (cfg->lua_state, lua_script) != 0) {
				msg_err_config ("cannot execute lua script for fuzzy "
						"learn condition: %s", lua_tostring (cfg->lua_state, -1));
			}
			else {
				if (lua_type (cfg->lua_state, -1) == LUA_TFUNCTION) {
					rule->learn_condition_cb = luaL_ref (cfg->lua_state,
							LUA_REGISTRYINDEX);
					msg_info_config ("loaded learn condition script for fuzzy rule:"
							" %s", rule->name);
				}
				else {
					msg_err_config ("lua script must return "
							"function(task) and not %s",
							lua_typename (cfg->lua_state,
									lua_type (cfg->lua_state, -1)));
				}
			}
		}
	}

	key_str = NULL;
	if ((value = ucl_object_lookup (obj, "fuzzy_key")) != NULL) {
		/* Create key from user's input */
		key_str = ucl_object_tostring (value);
	}

	/* Setup keys */
	if (key_str == NULL) {
		/* Use some default key for all ops */
		key_str = "rspamd";
	}

	rule->hash_key = g_string_sized_new (rspamd_cryptobox_HASHBYTES);
	rspamd_cryptobox_hash (rule->hash_key->str, key_str, strlen (key_str), NULL, 0);
	rule->hash_key->len = rspamd_cryptobox_HASHKEYBYTES;

	shingles_key_str = NULL;
	if ((value = ucl_object_lookup (obj, "fuzzy_shingles_key")) != NULL) {
		shingles_key_str = ucl_object_tostring (value);
	}
	if (shingles_key_str == NULL) {
		shingles_key_str = "rspamd";
	}

	rule->shingles_key = g_string_sized_new (rspamd_cryptobox_HASHBYTES);
	rspamd_cryptobox_hash (rule->shingles_key->str, shingles_key_str,
			strlen (shingles_key_str), NULL, 0);
	rule->shingles_key->len = 16;

	if (rspamd_upstreams_count (rule->servers) == 0) {
		msg_err_config ("no servers defined for fuzzy rule with name: %s",
			rule->name);
		return -1;
	}
	else {
		g_ptr_array_add (fuzzy_module_ctx->fuzzy_rules, rule);

		if (rule->symbol != fuzzy_module_ctx->default_symbol) {
			rspamd_symcache_add_symbol (cfg->cache, rule->symbol,
					0,
					NULL, NULL,
					SYMBOL_TYPE_VIRTUAL | SYMBOL_TYPE_FINE,
					cb_id);
		}

		msg_info_config ("added fuzzy rule %s, key: %*xs, "
				"shingles_key: %*xs, algorithm: %s",
				rule->symbol,
				6, rule->hash_key->str,
				6, rule->shingles_key->str,
				rule->algorithm_str);
	}

	if ((value = ucl_object_lookup (obj,  "weight_threshold")) != NULL) {
		rule->weight_threshold = ucl_object_todouble (value);
	}

	/*
	 * Process rule in Lua
	 */
	gint err_idx, ret;
	lua_State *L = (lua_State *)cfg->lua_state;

	lua_pushcfunction (L, &rspamd_lua_traceback);
	err_idx = lua_gettop (L);
	lua_rawgeti (L, LUA_REGISTRYINDEX, fuzzy_module_ctx->process_rule_ref);
	ucl_object_push_lua (L, obj, true);

	if ((ret = lua_pcall (L, 1, 1, err_idx)) != 0) {
		msg_err_config ("call to process_rule lua "
						"script failed (%d): %s", ret, lua_tostring (L, -1));

		rule->lua_id = -1;
	}
	else {
		rule->lua_id = lua_tonumber (L, -1);
	}

	lua_settop (L, err_idx - 1);

	rspamd_mempool_add_destructor (cfg->cfg_pool, fuzzy_free_rule,
			rule);

	return 0;
}

gint
fuzzy_check_module_init (struct rspamd_config *cfg, struct module_ctx **ctx)
{
	struct fuzzy_ctx *fuzzy_module_ctx;

	fuzzy_module_ctx = rspamd_mempool_alloc0 (cfg->cfg_pool,
			sizeof (struct fuzzy_ctx));

	fuzzy_module_ctx->fuzzy_pool = rspamd_mempool_new (rspamd_mempool_suggest_size (),
			NULL, 0);
	/* TODO: this should match rules count actually */
	fuzzy_module_ctx->keypairs_cache = rspamd_keypair_cache_new (32);
	fuzzy_module_ctx->fuzzy_rules = g_ptr_array_new ();
	fuzzy_module_ctx->cfg = cfg;
	fuzzy_module_ctx->process_rule_ref = -1;
	fuzzy_module_ctx->check_mime_part_ref = -1;
	fuzzy_module_ctx->cleanup_rules_ref = -1;

	rspamd_mempool_add_destructor (cfg->cfg_pool,
			(rspamd_mempool_destruct_t)rspamd_mempool_delete,
			fuzzy_module_ctx->fuzzy_pool);
	rspamd_mempool_add_destructor (cfg->cfg_pool,
			(rspamd_mempool_destruct_t)rspamd_keypair_cache_destroy,
			fuzzy_module_ctx->keypairs_cache);
	rspamd_mempool_add_destructor (cfg->cfg_pool,
			(rspamd_mempool_destruct_t)rspamd_ptr_array_free_hard,
			fuzzy_module_ctx->fuzzy_rules);

	*ctx = (struct module_ctx *)fuzzy_module_ctx;

	rspamd_rcl_add_doc_by_path (cfg,
			NULL,
			"Fuzzy check plugin",
			"fuzzy_check",
			UCL_OBJECT,
			NULL,
			0,
			NULL,
			0);

	rspamd_rcl_add_doc_by_path (cfg,
			"fuzzy_check",
			"Default symbol",
			"symbol",
			UCL_STRING,
			NULL,
			0,
			NULL,
			0);
	rspamd_rcl_add_doc_by_path (cfg,
			"fuzzy_check",
			"Minimum number of *words* to check a text part",
			"min_length",
			UCL_INT,
			NULL,
			0,
			NULL,
			0);
	rspamd_rcl_add_doc_by_path (cfg,
			"fuzzy_check",
			"Minimum number of *bytes* to check a non-text part",
			"min_bytes",
			UCL_INT,
			NULL,
			0,
			NULL,
			0);
	rspamd_rcl_add_doc_by_path (cfg,
			"fuzzy_check",
			"Multiplier for bytes limit when checking for text parts",
			"text_multiplier",
			UCL_FLOAT,
			NULL,
			0,
			NULL,
			0);
	rspamd_rcl_add_doc_by_path (cfg,
			"fuzzy_check",
			"Minimum height in pixels for embedded images to check using fuzzy storage",
			"min_height",
			UCL_INT,
			NULL,
			0,
			NULL,
			0);
	rspamd_rcl_add_doc_by_path (cfg,
			"fuzzy_check",
			"Minimum width in pixels for embedded images to check using fuzzy storage",
			"min_width",
			UCL_INT,
			NULL,
			0,
			NULL,
			0);
	rspamd_rcl_add_doc_by_path (cfg,
			"fuzzy_check",
			"Timeout for waiting reply from a fuzzy server",
			"timeout",
			UCL_TIME,
			NULL,
			0,
			NULL,
			0);
	rspamd_rcl_add_doc_by_path (cfg,
			"fuzzy_check",
			"Maximum number of retransmits for a single request",
			"retransmits",
			UCL_INT,
			NULL,
			0,
			NULL,
			0);
	rspamd_rcl_add_doc_by_path (cfg,
			"fuzzy_check",
			"Maximum number of upstream errors, affects error rate threshold",
			"max_errors",
			UCL_INT,
			NULL,
			0,
			NULL,
			0);
	rspamd_rcl_add_doc_by_path (cfg,
			"fuzzy_check",
			"Time to lapse before re-resolve faulty upstream",
			"revive_time",
			UCL_FLOAT,
			NULL,
			0,
			NULL,
			0);
	rspamd_rcl_add_doc_by_path (cfg,
			"fuzzy_check",
			"Whitelisted IPs map",
			"whitelist",
			UCL_STRING,
			NULL,
			0,
			NULL,
			0);
	/* Rules doc strings */
	rspamd_rcl_add_doc_by_path (cfg,
			"fuzzy_check",
			"Fuzzy check rule",
			"rule",
			UCL_OBJECT,
			NULL,
			0,
			NULL,
			0);
	rspamd_rcl_add_doc_by_path (cfg,
			"fuzzy_check.rule",
			"Headers that are used to make a separate hash",
			"headers",
			UCL_ARRAY,
			NULL,
			0,
			NULL,
			0);
	rspamd_rcl_add_doc_by_path (cfg,
			"fuzzy_check.rule",
			"Whitelisted hashes map",
			"skip_hashes",
			UCL_STRING,
			NULL,
			0,
			NULL,
			0);
	rspamd_rcl_add_doc_by_path (cfg,
			"fuzzy_check.rule",
			"Set of mime types (in form type/subtype, or type/*, or *) to check with fuzzy",
			"mime_types",
			UCL_ARRAY,
			NULL,
			0,
			NULL,
			0);
	rspamd_rcl_add_doc_by_path (cfg,
			"fuzzy_check.rule",
			"Maximum value for fuzzy hash when weight of symbol is exactly 1.0 (if value is higher then score is still 1.0)",
			"max_score",
			UCL_INT,
			NULL,
			0,
			NULL,
			0);
	rspamd_rcl_add_doc_by_path (cfg,
			"fuzzy_check.rule",
			"List of servers to check (or learn)",
			"servers",
			UCL_STRING,
			NULL,
			0,
			NULL,
			0);
	rspamd_rcl_add_doc_by_path (cfg,
			"fuzzy_check.rule",
			"If true then never try to learn this fuzzy storage",
			"read_only",
			UCL_BOOLEAN,
			NULL,
			0,
			NULL,
			0);
	rspamd_rcl_add_doc_by_path (cfg,
			"fuzzy_check.rule",
			"If true then ignore unknown flags and not add the default fuzzy symbol",
			"skip_unknown",
			UCL_BOOLEAN,
			NULL,
			0,
			NULL,
			0);
	rspamd_rcl_add_doc_by_path (cfg,
			"fuzzy_check.rule",
			"Default symbol for rule (if no flags defined or matched)",
			"symbol",
			UCL_STRING,
			NULL,
			0,
			NULL,
			0);
	rspamd_rcl_add_doc_by_path (cfg,
			"fuzzy_check.rule",
			"Base32 value for the protocol encryption public key",
			"encryption_key",
			UCL_STRING,
			NULL,
			0,
			NULL,
			0);
	rspamd_rcl_add_doc_by_path (cfg,
			"fuzzy_check.rule",
			"Base32 value for the hashing key (for private storages)",
			"fuzzy_key",
			UCL_STRING,
			NULL,
			0,
			NULL,
			0);
	rspamd_rcl_add_doc_by_path (cfg,
			"fuzzy_check.rule",
			"Base32 value for the shingles hashing key (for private storages)",
			"fuzzy_shingles_key",
			UCL_STRING,
			NULL,
			0,
			NULL,
			0);
	rspamd_rcl_add_doc_by_path (cfg,
			"fuzzy_check.rule",
			"Lua script that returns boolean function to check if this task "
						"should be considered when learning fuzzy storage",
			"learn_condition",
			UCL_STRING,
			NULL,
			0,
			NULL,
			0);
	rspamd_rcl_add_doc_by_path (cfg,
			"fuzzy_check.rule",
			"Map of SYMBOL -> data for flags configuration",
			"fuzzy_map",
			UCL_OBJECT,
			NULL,
			0,
			NULL,
			0);
	rspamd_rcl_add_doc_by_path (cfg,
			"fuzzy_check.rule",
			"Use direct hash for short texts",
			"short_text_direct_hash",
			UCL_BOOLEAN,
			NULL,
			0,
			"true",
			0);
	rspamd_rcl_add_doc_by_path (cfg,
			"fuzzy_check.rule",
			"Override module default min bytes for this rule",
			"min_bytes",
			UCL_INT,
			NULL,
			0,
			NULL,
			0);
	/* Fuzzy map doc strings */
	rspamd_rcl_add_doc_by_path (cfg,
			"fuzzy_check.rule.fuzzy_map",
			"Maximum score for this flag",
			"max_score",
			UCL_INT,
			NULL,
			0,
			NULL,
			0);
	rspamd_rcl_add_doc_by_path (cfg,
			"fuzzy_check.rule.fuzzy_map",
			"Flag number",
			"flag",
			UCL_INT,
			NULL,
			0,
			NULL,
			0);
	rspamd_rcl_add_doc_by_path (cfg,
			"fuzzy_check.rule",
			"Do no use subject to distinguish short text hashes",
			"no_subject",
			UCL_BOOLEAN,
			NULL,
			0,
			"false",
			0);
	rspamd_rcl_add_doc_by_path (cfg,
			"fuzzy_check.rule",
			"Disable sharing message stats with the fuzzy server",
			"no_share",
			UCL_BOOLEAN,
			NULL,
			0,
			"false",
			0);

	return 0;
}

gint
fuzzy_check_module_config (struct rspamd_config *cfg, bool validate)
{
	const ucl_object_t *value, *cur, *elt;
	ucl_object_iter_t it;
	gint res = TRUE, cb_id, nrules = 0;
	lua_State *L = cfg->lua_state;
	struct fuzzy_ctx *fuzzy_module_ctx = fuzzy_get_context (cfg);

	if (!rspamd_config_is_module_enabled (cfg, "fuzzy_check")) {
		return TRUE;
	}

	fuzzy_module_ctx->enabled = TRUE;
	fuzzy_module_ctx->check_mime_part_ref = -1;
	fuzzy_module_ctx->process_rule_ref = -1;
	fuzzy_module_ctx->cleanup_rules_ref = -1;

	/* Interact with lua_fuzzy */
	if (luaL_dostring (L, "return require \"lua_fuzzy\"") != 0) {
		msg_err_config ("cannot require lua_fuzzy: %s",
				lua_tostring (L, -1));
		fuzzy_module_ctx->enabled = FALSE;
	}
	else {
#if LUA_VERSION_NUM >= 504
		lua_settop(L, -2);
#endif
		if (lua_type (L, -1) != LUA_TTABLE) {
			msg_err_config ("lua fuzzy must return "
							"table and not %s",
					lua_typename (L, lua_type (L, -1)));
			fuzzy_module_ctx->enabled = FALSE;
		}
		else {
			lua_pushstring (L, "process_rule");
			lua_gettable (L, -2);

			if (lua_type (L, -1) != LUA_TFUNCTION) {
				msg_err_config ("process_rule must return "
								"function and not %s",
						lua_typename (L, lua_type (L, -1)));
				fuzzy_module_ctx->enabled = FALSE;
			}
			else {
				fuzzy_module_ctx->process_rule_ref = luaL_ref (L, LUA_REGISTRYINDEX);
			}

			lua_pushstring (L, "check_mime_part");
			lua_gettable (L, -2);

			if (lua_type (L, -1) != LUA_TFUNCTION) {
				msg_err_config ("check_mime_part must return "
								"function and not %s",
						lua_typename (L, lua_type (L, -1)));
				fuzzy_module_ctx->enabled = FALSE;
			}
			else {
				fuzzy_module_ctx->check_mime_part_ref = luaL_ref (L, LUA_REGISTRYINDEX);
			}

			lua_pushstring (L, "cleanup_rules");
			lua_gettable (L, -2);

			if (lua_type (L, -1) != LUA_TFUNCTION) {
				msg_err_config ("cleanup_rules must return "
								"function and not %s",
						lua_typename (L, lua_type (L, -1)));
				fuzzy_module_ctx->enabled = FALSE;
			}
			else {
				fuzzy_module_ctx->cleanup_rules_ref = luaL_ref (L, LUA_REGISTRYINDEX);
			}
		}
	}

	lua_settop (L, 0);

	if (!fuzzy_module_ctx->enabled) {
		return TRUE;
	}

	if ((value =
		rspamd_config_get_module_opt (cfg, "fuzzy_check", "symbol")) != NULL) {
		fuzzy_module_ctx->default_symbol = ucl_obj_tostring (value);
	}
	else {
		fuzzy_module_ctx->default_symbol = DEFAULT_SYMBOL;
	}

	if ((value =
		rspamd_config_get_module_opt (cfg, "fuzzy_check", "timeout")) != NULL) {
		fuzzy_module_ctx->io_timeout = ucl_obj_todouble (value);
	}
	else {
		fuzzy_module_ctx->io_timeout = DEFAULT_IO_TIMEOUT;
	}

	if ((value =
				 rspamd_config_get_module_opt (cfg,
						 "fuzzy_check",
						 "retransmits")) != NULL) {
		fuzzy_module_ctx->retransmits = ucl_obj_toint (value);
	}
	else {
		fuzzy_module_ctx->retransmits = DEFAULT_RETRANSMITS;
	}

	if ((value =
		rspamd_config_get_module_opt (cfg, "fuzzy_check",
		"max_errors")) != NULL) {
		fuzzy_module_ctx->max_errors = ucl_obj_toint (value);
	}
	else {
		fuzzy_module_ctx->max_errors = DEFAULT_MAX_ERRORS;
	}

	if ((value =
		rspamd_config_get_module_opt (cfg, "fuzzy_check",
		"revive_time")) != NULL) {
		fuzzy_module_ctx->revive_time = ucl_obj_todouble (value);
	}
	else {
		fuzzy_module_ctx->revive_time = DEFAULT_REVIVE_TIME;
	}

	if ((value =
		rspamd_config_get_module_opt (cfg, "fuzzy_check",
		"whitelist")) != NULL) {
		rspamd_config_radix_from_ucl (cfg, value, "Fuzzy whitelist",
				&fuzzy_module_ctx->whitelist,
				NULL,
				NULL, "fuzzy ip whitelist");
	}
	else {
		fuzzy_module_ctx->whitelist = NULL;
	}

	if ((value =
		rspamd_config_get_module_opt (cfg, "fuzzy_check", "rule")) != NULL) {

		cb_id = rspamd_symcache_add_symbol (cfg->cache,
				"FUZZY_CALLBACK", 0, fuzzy_symbol_callback, NULL,
				SYMBOL_TYPE_CALLBACK | SYMBOL_TYPE_FINE,
				-1);
		rspamd_config_add_symbol (cfg,
				"FUZZY_CALLBACK",
				0.0,
				"Fuzzy check callback",
				"fuzzy",
				RSPAMD_SYMBOL_FLAG_IGNORE_METRIC,
				1,
				1);

		/*
		 * Here we can have 2 possibilities:
		 *
		 * unnamed rules:
		 *
		 * rule {
		 * ...
		 * }
		 * rule {
		 * ...
		 * }
		 *
		 * - or - named rules:
		 *
		 * rule {
		 * 	"rule1": {
		 * 	...
		 * 	}
		 * 	"rule2": {
		 * 	...
		 * 	}
		 * }
		 *
		 * So, for each element, we check, if there 'servers' key. If 'servers' is
		 * presented, then we treat it as unnamed rule, otherwise we treat it as
		 * named rule.
		 */
		LL_FOREACH (value, cur) {

			if (ucl_object_lookup (cur, "servers")) {
				/* Unnamed rule */
				fuzzy_parse_rule (cfg, cur, NULL, cb_id);
				nrules ++;
			}
			else {
				/* Named rule */
				it = NULL;

				while ((elt = ucl_object_iterate (cur, &it, true)) != NULL) {
					fuzzy_parse_rule (cfg, elt, ucl_object_key (elt), cb_id);
					nrules ++;
				}
			}
		}

		/* We want that to check bad mime attachments */
		rspamd_symcache_add_delayed_dependency (cfg->cache,
				"FUZZY_CALLBACK", "MIME_TYPES_CALLBACK");
	}

	if (fuzzy_module_ctx->fuzzy_rules == NULL) {
		msg_warn_config ("fuzzy module is enabled but no rules are defined");
	}

	msg_info_config ("init internal fuzzy_check module, %d rules loaded",
			nrules);

	/* Register global methods */
	lua_getglobal (L, "rspamd_plugins");

	if (lua_type (L, -1) == LUA_TTABLE) {
		lua_pushstring (L, "fuzzy_check");
		lua_createtable (L, 0, 3);
		/* Set methods */
		lua_pushstring (L, "unlearn");
		lua_pushcfunction (L, fuzzy_lua_unlearn_handler);
		lua_settable (L, -3);
		lua_pushstring (L, "learn");
		lua_pushcfunction (L, fuzzy_lua_learn_handler);
		lua_settable (L, -3);
		lua_pushstring (L, "gen_hashes");
		lua_pushcfunction (L, fuzzy_lua_gen_hashes_handler);
		lua_settable (L, -3);
		/* Finish fuzzy_check key */
		lua_settable (L, -3);
	}

	lua_settop (L, 0);

	return res;
}

gint
fuzzy_check_module_reconfig (struct rspamd_config *cfg)
{
	struct fuzzy_ctx *fuzzy_module_ctx = fuzzy_get_context (cfg);

	if (fuzzy_module_ctx->cleanup_rules_ref != -1) {
		/* Sync lua_fuzzy rules */
		gint err_idx, ret;
		lua_State *L = (lua_State *)cfg->lua_state;

		lua_pushcfunction (L, &rspamd_lua_traceback);
		err_idx = lua_gettop (L);
		lua_rawgeti (L, LUA_REGISTRYINDEX, fuzzy_module_ctx->cleanup_rules_ref);

		if ((ret = lua_pcall (L, 0, 0, err_idx)) != 0) {
			msg_err_config ("call to cleanup_rules lua "
							"script failed (%d): %s", ret, lua_tostring (L, -1));
		}

		luaL_unref (cfg->lua_state, LUA_REGISTRYINDEX,
				fuzzy_module_ctx->cleanup_rules_ref);
		lua_settop (L, 0);
	}

	if (fuzzy_module_ctx->check_mime_part_ref != -1) {
		luaL_unref (cfg->lua_state, LUA_REGISTRYINDEX,
				fuzzy_module_ctx->check_mime_part_ref);
	}

	if (fuzzy_module_ctx->process_rule_ref != -1) {
		luaL_unref (cfg->lua_state, LUA_REGISTRYINDEX,
				fuzzy_module_ctx->process_rule_ref);
	}

	return fuzzy_check_module_config (cfg, false);
}

/* Finalize IO */
static void
fuzzy_io_fin (void *ud)
{
	struct fuzzy_client_session *session = ud;

	if (session->commands) {
		g_ptr_array_free (session->commands, TRUE);
	}

	if (session->results) {
		g_ptr_array_free (session->results, TRUE);
	}

	rspamd_ev_watcher_stop (session->event_loop, &session->ev);
	close (session->fd);
}

static GArray *
fuzzy_preprocess_words (struct rspamd_mime_text_part *part, rspamd_mempool_t *pool)
{
	return part->utf_words;
}

static void
fuzzy_encrypt_cmd (struct fuzzy_rule *rule,
		struct rspamd_fuzzy_encrypted_req_hdr *hdr,
		guchar *data, gsize datalen)
{
	const guchar *pk;
	guint pklen;

	g_assert (hdr != NULL);
	g_assert (data != NULL);
	g_assert (rule != NULL);

	/* Encrypt data */
	memcpy (hdr->magic,
			fuzzy_encrypted_magic,
			sizeof (hdr->magic));
	ottery_rand_bytes (hdr->nonce, sizeof (hdr->nonce));
	pk = rspamd_keypair_component (rule->local_key,
			RSPAMD_KEYPAIR_COMPONENT_PK, &pklen);
	memcpy (hdr->pubkey, pk, MIN (pklen, sizeof (hdr->pubkey)));
	pk = rspamd_pubkey_get_pk (rule->peer_key, &pklen);
	memcpy (hdr->key_id, pk, MIN (sizeof (hdr->key_id), pklen));
	rspamd_keypair_cache_process (rule->ctx->keypairs_cache,
			rule->local_key, rule->peer_key);
	rspamd_cryptobox_encrypt_nm_inplace (data, datalen,
			hdr->nonce, rspamd_pubkey_get_nm (rule->peer_key, rule->local_key),
			hdr->mac,
			rspamd_pubkey_alg (rule->peer_key));
}

static struct fuzzy_cmd_io *
fuzzy_cmd_stat (struct fuzzy_rule *rule,
		int c,
		gint flag,
		guint32 weight,
		rspamd_mempool_t *pool)
{
	struct rspamd_fuzzy_cmd *cmd;
	struct rspamd_fuzzy_encrypted_cmd *enccmd = NULL;
	struct fuzzy_cmd_io *io;

	if (rule->peer_key) {
		enccmd = rspamd_mempool_alloc0 (pool, sizeof (*enccmd));
		cmd = &enccmd->cmd;
	}
	else {
		cmd = rspamd_mempool_alloc0 (pool, sizeof (*cmd));
	}

	cmd->cmd = c;
	cmd->version = RSPAMD_FUZZY_PLUGIN_VERSION;
	cmd->shingles_count = 0;
	cmd->tag = ottery_rand_uint32 ();

	io = rspamd_mempool_alloc (pool, sizeof (*io));
	io->flags = 0;
	io->tag = cmd->tag;
	memcpy (&io->cmd, cmd, sizeof (io->cmd));

	if (rule->peer_key && enccmd) {
		fuzzy_encrypt_cmd (rule, &enccmd->hdr, (guchar *)cmd, sizeof (*cmd));
		io->io.iov_base = enccmd;
		io->io.iov_len = sizeof (*enccmd);
	}
	else {
		io->io.iov_base = cmd;
		io->io.iov_len = sizeof (*cmd);
	}

	return io;
}

static struct fuzzy_cmd_io *
fuzzy_cmd_hash (struct fuzzy_rule *rule,
		int c,
		const rspamd_ftok_t *hash,
		gint flag,
		guint32 weight,
		rspamd_mempool_t *pool)
{
	struct rspamd_fuzzy_cmd *cmd;
	struct rspamd_fuzzy_encrypted_cmd *enccmd = NULL;
	struct fuzzy_cmd_io *io;

	if (rule->peer_key) {
		enccmd = rspamd_mempool_alloc0 (pool, sizeof (*enccmd));
		cmd = &enccmd->cmd;
	}
	else {
		cmd = rspamd_mempool_alloc0 (pool, sizeof (*cmd));
	}

	if (hash->len == sizeof (cmd->digest) * 2) {
		/* It is hex encoding */
		if (rspamd_decode_hex_buf (hash->begin, hash->len, cmd->digest,
				sizeof (cmd->digest)) == -1) {
			msg_err_pool ("cannot decode hash, wrong encoding");
			return NULL;
		}
	}
	else {
		msg_err_pool ("cannot decode hash, wrong length: %z", hash->len);
		return NULL;
	}

	cmd->cmd = c;
	cmd->version = RSPAMD_FUZZY_PLUGIN_VERSION;
	cmd->shingles_count = 0;
	cmd->tag = ottery_rand_uint32 ();

	io = rspamd_mempool_alloc (pool, sizeof (*io));
	io->flags = 0;
	io->tag = cmd->tag;

	memcpy (&io->cmd, cmd, sizeof (io->cmd));

	if (rule->peer_key && enccmd) {
		fuzzy_encrypt_cmd (rule, &enccmd->hdr, (guchar *)cmd, sizeof (*cmd));
		io->io.iov_base = enccmd;
		io->io.iov_len = sizeof (*enccmd);
	}
	else {
		io->io.iov_base = cmd;
		io->io.iov_len = sizeof (*cmd);
	}

	return io;
}

struct rspamd_cached_shingles {
	struct rspamd_shingle *sh;
	guchar digest[rspamd_cryptobox_HASHBYTES];
	guint additional_length;
	guchar *additional_data;
};


static struct rspamd_cached_shingles *
fuzzy_cmd_get_cached (struct fuzzy_rule *rule,
					  struct rspamd_task *task,
					  struct rspamd_mime_part *mp)
{
	gchar key[32];
	gint key_part;
	struct rspamd_cached_shingles **cached;

	memcpy (&key_part, rule->shingles_key->str, sizeof (key_part));
	rspamd_snprintf (key, sizeof (key), "%s%d", rule->algorithm_str,
			key_part);

	cached = (struct rspamd_cached_shingles **)rspamd_mempool_get_variable (
			task->task_pool, key);

	if (cached && cached[mp->part_number]) {
		return cached[mp->part_number];
	}

	return NULL;
}

static void
fuzzy_cmd_set_cached (struct fuzzy_rule *rule,
					  struct rspamd_task *task,
					  struct rspamd_mime_part *mp,
					  struct rspamd_cached_shingles *data)
{
	gchar key[32];
	gint key_part;
	struct rspamd_cached_shingles **cached;

	memcpy (&key_part, rule->shingles_key->str, sizeof (key_part));
	rspamd_snprintf (key, sizeof (key), "%s%d", rule->algorithm_str,
			key_part);

	cached = (struct rspamd_cached_shingles **)rspamd_mempool_get_variable (
			task->task_pool, key);

	if (cached) {
		cached[mp->part_number] = data;
	}
	else {
		cached = rspamd_mempool_alloc0 (task->task_pool, sizeof (*cached) *
				(MESSAGE_FIELD (task, parts)->len + 1));
		cached[mp->part_number] = data;

		rspamd_mempool_set_variable (task->task_pool, key, cached, NULL);
	}


}

static gboolean
fuzzy_rule_check_mimepart (struct rspamd_task *task,
						   struct fuzzy_rule *rule,
						   struct rspamd_mime_part *part,
						   gboolean *need_check,
						   gboolean *fuzzy_check)
{
	lua_State *L = (lua_State *)task->cfg->lua_state;

	gint old_top = lua_gettop (L);

	if (rule->lua_id != -1 && rule->ctx->check_mime_part_ref != -1) {
		gint err_idx, ret;

		struct rspamd_task **ptask;
		struct rspamd_mime_part **ppart;

		lua_pushcfunction (L, &rspamd_lua_traceback);
		err_idx = lua_gettop (L);
		lua_rawgeti (L, LUA_REGISTRYINDEX, rule->ctx->check_mime_part_ref);

		ptask = lua_newuserdata (L, sizeof (*ptask));
		*ptask = task;
		rspamd_lua_setclass (L, "rspamd{task}", -1);

		ppart = lua_newuserdata (L, sizeof (*ppart));
		*ppart = part;
		rspamd_lua_setclass (L, "rspamd{mimepart}", -1);

		lua_pushnumber (L, rule->lua_id);

		if ((ret = lua_pcall (L, 3, 2, err_idx)) != 0) {
			msg_err_task ("call to check_mime_part lua "
							"script failed (%d): %s", ret, lua_tostring (L, -1));

			ret = FALSE;
		}
		else {
			ret = TRUE;
			*need_check = lua_toboolean (L, -2);
			*fuzzy_check = lua_toboolean (L, -1);
		}

		lua_settop (L, old_top);

		return ret;
	}

	return FALSE;
}

#define MAX_FUZZY_DOMAIN 64

static guint
fuzzy_cmd_extension_length (struct rspamd_task *task,
							struct fuzzy_rule *rule)
{
	guint total = 0;

	if (rule->no_share) {
		return 0;
	}

	/* From domain */
	if (MESSAGE_FIELD (task, from_mime) && MESSAGE_FIELD (task, from_mime)->len > 0) {
		struct rspamd_email_address *addr = g_ptr_array_index (MESSAGE_FIELD (task,
				from_mime), 0);

		if (addr->domain_len > 0) {
			total += 2; /* 2 bytes: type + length */
			total += MIN (MAX_FUZZY_DOMAIN, addr->domain_len);
		}
	}

	if (task->from_addr && rspamd_inet_address_get_af (task->from_addr) == AF_INET) {
		total += sizeof (struct in_addr) + 1;
	}
	else if (task->from_addr&& rspamd_inet_address_get_af (task->from_addr) == AF_INET6) {
		total += sizeof (struct in6_addr) + 1;
	}

	return total;
}

static guint
fuzzy_cmd_write_extensions (struct rspamd_task *task,
							struct fuzzy_rule *rule,
							guchar *dest,
							gsize available)
{
	guint written = 0;

	if (rule->no_share) {
		return 0;
	}

	if (MESSAGE_FIELD (task, from_mime) && MESSAGE_FIELD (task, from_mime)->len > 0) {
		struct rspamd_email_address *addr = g_ptr_array_index (MESSAGE_FIELD (task,
				from_mime), 0);
		guint to_write = MIN (MAX_FUZZY_DOMAIN, addr->domain_len) + 2;

		if (to_write > 0 && to_write <= available) {
			*dest++ = RSPAMD_FUZZY_EXT_SOURCE_DOMAIN;
			*dest++ = to_write - 2;

			if (addr->domain_len < MAX_FUZZY_DOMAIN) {
				memcpy (dest, addr->domain, addr->domain_len);
				dest += addr->domain_len;
			}
			else {
				/* Trim from left */
				memcpy (dest,
						addr->domain + (addr->domain_len - MAX_FUZZY_DOMAIN),
						MAX_FUZZY_DOMAIN);
				dest += MAX_FUZZY_DOMAIN;
			}

			available -= to_write;
			written += to_write;
		}
	}

	if (task->from_addr && rspamd_inet_address_get_af (task->from_addr) == AF_INET) {
		if (available >= sizeof (struct in_addr) + 1) {
			guint klen;
			guchar *inet_data = rspamd_inet_address_get_hash_key (task->from_addr, &klen);

			*dest++ = RSPAMD_FUZZY_EXT_SOURCE_IP4;

			memcpy (dest, inet_data, klen);
			dest += klen;

			available -= klen + 1;
			written += klen + 1;
		}
	}
	else if (task->from_addr && rspamd_inet_address_get_af (task->from_addr) == AF_INET6) {
		if (available >= sizeof (struct in6_addr) + 1) {
			guint klen;
			guchar *inet_data = rspamd_inet_address_get_hash_key (task->from_addr, &klen);

			*dest++ = RSPAMD_FUZZY_EXT_SOURCE_IP6;

			memcpy (dest, inet_data, klen);
			dest += klen;

			available -= klen + 1;
			written += klen + 1;
		}
	}

	return written;
}

/*
 * Create fuzzy command from a text part
 */
static struct fuzzy_cmd_io *
fuzzy_cmd_from_text_part (struct rspamd_task *task,
						  struct fuzzy_rule *rule,
						  int c,
						  gint flag,
						  guint32 weight,
						  gboolean short_text,
						  struct rspamd_mime_text_part *part,
						  struct rspamd_mime_part *mp)
{
	struct rspamd_fuzzy_shingle_cmd *shcmd = NULL;
	struct rspamd_fuzzy_cmd *cmd = NULL;
	struct rspamd_fuzzy_encrypted_shingle_cmd *encshcmd = NULL;
	struct rspamd_fuzzy_encrypted_cmd *enccmd = NULL;
	struct rspamd_cached_shingles *cached = NULL;
	struct rspamd_shingle *sh = NULL;
	guint i;
	rspamd_cryptobox_hash_state_t st;
	rspamd_stat_token_t *word;
	GArray *words;
	struct fuzzy_cmd_io *io;
	guint additional_length;
	guchar *additional_data;

	cached = fuzzy_cmd_get_cached (rule, task, mp);

	/*
	 * Important note:
	 *
	 * We assume that fuzzy io is a consistent memory layout to fit into
	 * iov structure of size 1
	 *
	 * However, there are 4 possibilities:
	 * 1) non encrypted, non shingle command - just one cmd
	 * 2) encrypted, non shingle command - encryption hdr + cmd
	 * 3) non encrypted, shingle command - cmd + shingle
	 * 4) encrypted, shingle command - encryption hdr + cmd + shingle
	 *
	 * Extensions are always at the end, but since we also have caching (sigh, meh...)
	 * then we have one piece that looks like cmd (+ shingle) + extensions
	 * To encrypt it optionally we take this memory and prepend encryption header
	 *
	 * In case of cached version we do the same: allocate, copy from cached (including extra)
	 * and optionally encrypt.
	 *
	 * However, there should be no extensions in case of unencrypted connection
	 * (for sanity + privacy).
	 */
	if (cached) {
		additional_length = cached->additional_length;
		additional_data = cached->additional_data;

		/* Copy cached */
		if (short_text) {
			enccmd = rspamd_mempool_alloc0 (task->task_pool,
					sizeof (*enccmd) + additional_length);
			cmd = &enccmd->cmd;
			memcpy (cmd->digest, cached->digest,
					sizeof (cached->digest));
			cmd->shingles_count = 0;
			memcpy (((guchar *)enccmd) + sizeof (*enccmd), additional_data,
					additional_length);
		}
		else if (cached->sh) {
			encshcmd = rspamd_mempool_alloc0 (task->task_pool,
					additional_length + sizeof (*encshcmd));
			shcmd = &encshcmd->cmd;
			memcpy (&shcmd->sgl, cached->sh, sizeof (struct rspamd_shingle));
			memcpy (shcmd->basic.digest, cached->digest,
					sizeof (cached->digest));
			memcpy (((guchar *)encshcmd) + sizeof (*encshcmd), additional_data,
					additional_length);
			shcmd->basic.shingles_count = RSPAMD_SHINGLE_SIZE;
		}
		else {
			return NULL;
		}
	}
	else {
		additional_length = fuzzy_cmd_extension_length (task, rule);
		cached = rspamd_mempool_alloc0 (task->task_pool, sizeof (*cached) +
				additional_length);
		/*
		 * Allocate extensions and never touch it except copying to avoid
		 * occasional encryption
		 */
		cached->additional_length = additional_length;
		cached->additional_data = ((guchar *)cached) + sizeof (*cached);

		if (additional_length > 0) {
			fuzzy_cmd_write_extensions (task, rule, cached->additional_data,
					additional_length);
		}

		if (short_text) {
			enccmd = rspamd_mempool_alloc0 (task->task_pool,
					sizeof (*enccmd) + additional_length);
			cmd = &enccmd->cmd;
			rspamd_cryptobox_hash_init (&st, rule->hash_key->str,
					rule->hash_key->len);

			rspamd_cryptobox_hash_update (&st, part->utf_stripped_content->data,
					part->utf_stripped_content->len);

			if (!rule->no_subject && (MESSAGE_FIELD (task, subject))) {
				/* We also include subject */
				rspamd_cryptobox_hash_update (&st, MESSAGE_FIELD (task, subject),
						strlen (MESSAGE_FIELD (task, subject)));
			}

			rspamd_cryptobox_hash_final (&st, cmd->digest);
			memcpy (cached->digest, cmd->digest, sizeof (cached->digest));
			cached->sh = NULL;

			additional_data = ((guchar *)enccmd) + sizeof (*enccmd);
			memcpy (additional_data, cached->additional_data, additional_length);
		}
		else {
			encshcmd = rspamd_mempool_alloc0 (task->task_pool,
					sizeof (*encshcmd) + additional_length);
			shcmd = &encshcmd->cmd;

			/*
			 * Generate hash from all words in the part
			 */
			rspamd_cryptobox_hash_init (&st, rule->hash_key->str, rule->hash_key->len);
			words = fuzzy_preprocess_words (part, task->task_pool);

			for (i = 0; i < words->len; i ++) {
				word = &g_array_index (words, rspamd_stat_token_t, i);

				if (!((word->flags & RSPAMD_STAT_TOKEN_FLAG_SKIPPED)
					  || word->stemmed.len == 0)) {
					rspamd_cryptobox_hash_update (&st, word->stemmed.begin,
							word->stemmed.len);
				}
			}

			rspamd_cryptobox_hash_final (&st, shcmd->basic.digest);

			msg_debug_task ("loading shingles of type %s with key %*xs",
					rule->algorithm_str,
					16, rule->shingles_key->str);
			sh = rspamd_shingles_from_text (words,
					rule->shingles_key->str, task->task_pool,
					rspamd_shingles_default_filter, NULL,
					rule->alg);
			if (sh != NULL) {
				memcpy (&shcmd->sgl, sh, sizeof (shcmd->sgl));
				shcmd->basic.shingles_count = RSPAMD_SHINGLE_SIZE;
			}
			else {
				/* No shingles, no check */
				return NULL;
			}

			cached->sh = sh;
			memcpy (cached->digest, shcmd->basic.digest, sizeof (cached->digest));
			additional_data = ((guchar *)encshcmd) + sizeof (*encshcmd);
			memcpy (additional_data, cached->additional_data, additional_length);
		}

		/*
		 * We always save encrypted command as it can handle both
		 * encrypted and unencrypted requests.
		 *
		 * Since it is copied when obtained from the cache, it is safe to use
		 * it this way.
		 */
		fuzzy_cmd_set_cached (rule, task, mp, cached);
	}

	io = rspamd_mempool_alloc (task->task_pool, sizeof (*io));
	io->part = mp;

	if (!short_text) {
		shcmd->basic.tag = ottery_rand_uint32 ();
		shcmd->basic.cmd = c;
		shcmd->basic.version = RSPAMD_FUZZY_PLUGIN_VERSION;

		if (c != FUZZY_CHECK) {
			shcmd->basic.flag = flag;
			shcmd->basic.value = weight;
		}
		io->tag = shcmd->basic.tag;
		memcpy (&io->cmd, &shcmd->basic, sizeof (io->cmd));
	}
	else {
		cmd->tag = ottery_rand_uint32 ();
		cmd->cmd = c;
		cmd->version = RSPAMD_FUZZY_PLUGIN_VERSION;

		if (c != FUZZY_CHECK) {
			cmd->flag = flag;
			cmd->value = weight;
		}
		io->tag = cmd->tag;
		memcpy (&io->cmd, cmd, sizeof (io->cmd));
	}

	io->flags = 0;


	if (rule->peer_key) {
		/* Encrypt data */
		if (!short_text) {
			fuzzy_encrypt_cmd (rule, &encshcmd->hdr, (guchar *) shcmd,
					sizeof (*shcmd) + additional_length);
			io->io.iov_base = encshcmd;
			io->io.iov_len = sizeof (*encshcmd) + additional_length;
		}
		else {
			fuzzy_encrypt_cmd (rule, &enccmd->hdr, (guchar *)cmd,
					sizeof (*cmd) + additional_length);
			io->io.iov_base = enccmd;
			io->io.iov_len = sizeof (*enccmd) + additional_length;
		}
	}
	else {

		if (!short_text) {
			io->io.iov_base = shcmd;
			io->io.iov_len = sizeof (*shcmd) + additional_length;
		}
		else {
			io->io.iov_base = cmd;
			io->io.iov_len = sizeof (*cmd) + additional_length;
		}
	}

	return io;
}

#if 0
static struct fuzzy_cmd_io *
fuzzy_cmd_from_image_part (struct fuzzy_rule *rule,
						   int c,
						   gint flag,
						   guint32 weight,
						   struct rspamd_task *task,
						   struct rspamd_image *img,
						   struct rspamd_mime_part *mp)
{
	struct rspamd_fuzzy_shingle_cmd *shcmd;
	struct rspamd_fuzzy_encrypted_shingle_cmd *encshcmd;
	struct fuzzy_cmd_io *io;
	struct rspamd_shingle *sh;
	struct rspamd_cached_shingles *cached;

	cached = fuzzy_cmd_get_cached (rule, task, mp);

	if (cached) {
		/* Copy cached */
		encshcmd = rspamd_mempool_alloc0 (task->task_pool, sizeof (*encshcmd));
		shcmd = &encshcmd->cmd;
		memcpy (&shcmd->sgl, cached->sh, sizeof (struct rspamd_shingle));
		memcpy (shcmd->basic.digest, cached->digest,
				sizeof (cached->digest));
		shcmd->basic.shingles_count = RSPAMD_SHINGLE_SIZE;
	}
	else {
		encshcmd = rspamd_mempool_alloc0 (task->task_pool, sizeof (*encshcmd));
		shcmd = &encshcmd->cmd;

		/*
		 * Generate shingles
		 */
		sh = rspamd_shingles_from_image (img->dct,
				rule->shingles_key->str, task->task_pool,
				rspamd_shingles_default_filter, NULL,
				rule->alg);
		if (sh != NULL) {
			memcpy (&shcmd->sgl, sh->hashes, sizeof (shcmd->sgl));
			shcmd->basic.shingles_count = RSPAMD_SHINGLE_SIZE;
#if 0
			for (unsigned int i = 0; i < RSPAMD_SHINGLE_SIZE; i ++) {
				msg_err ("shingle %d: %L", i, sh->hashes[i]);
			}
#endif
		}

		rspamd_cryptobox_hash (shcmd->basic.digest,
				(const guchar *)img->dct, RSPAMD_DCT_LEN / NBBY,
				rule->hash_key->str, rule->hash_key->len);

		msg_debug_task ("loading shingles of type %s with key %*xs",
				rule->algorithm_str,
				16, rule->shingles_key->str);

		/*
		 * We always save encrypted command as it can handle both
		 * encrypted and unencrypted requests.
		 *
		 * Since it is copied when obtained from the cache, it is safe to use
		 * it this way.
		 */
		cached = rspamd_mempool_alloc (task->task_pool, sizeof (*cached));
		cached->sh = sh;
		memcpy (cached->digest, shcmd->basic.digest, sizeof (cached->digest));
		fuzzy_cmd_set_cached (rule, task, mp, cached);
	}

	shcmd->basic.tag = ottery_rand_uint32 ();
	shcmd->basic.cmd = c;
	shcmd->basic.version = RSPAMD_FUZZY_PLUGIN_VERSION;

	if (c != FUZZY_CHECK) {
		shcmd->basic.flag = flag;
		shcmd->basic.value = weight;
	}

	io = rspamd_mempool_alloc (task->task_pool, sizeof (*io));
	io->part = mp;
	io->tag = shcmd->basic.tag;
	io->flags = FUZZY_CMD_FLAG_IMAGE;
	memcpy (&io->cmd, &shcmd->basic, sizeof (io->cmd));

	if (rule->peer_key) {
		/* Encrypt data */
		fuzzy_encrypt_cmd (rule, &encshcmd->hdr, (guchar *) shcmd, sizeof (*shcmd));
		io->io.iov_base = encshcmd;
		io->io.iov_len = sizeof (*encshcmd);
	}
	else {
		io->io.iov_base = shcmd;
		io->io.iov_len = sizeof (*shcmd);
	}

	return io;
}
#endif

static struct fuzzy_cmd_io *
fuzzy_cmd_from_data_part (struct fuzzy_rule *rule,
						  int c,
						  gint flag,
						  guint32 weight,
						  struct rspamd_task *task,
						  guchar digest[rspamd_cryptobox_HASHBYTES],
						  struct rspamd_mime_part *mp)
{
	struct rspamd_fuzzy_cmd *cmd;
	struct rspamd_fuzzy_encrypted_cmd *enccmd = NULL;
	struct fuzzy_cmd_io *io;
	guint additional_length;
	guchar *additional_data;

	additional_length = fuzzy_cmd_extension_length (task, rule);

	if (rule->peer_key) {
		enccmd = rspamd_mempool_alloc0 (task->task_pool,
				sizeof (*enccmd) + additional_length);
		cmd = &enccmd->cmd;
		additional_data = ((guchar *)enccmd) + sizeof (*enccmd);
	}
	else {
		cmd = rspamd_mempool_alloc0 (task->task_pool,
				sizeof (*cmd) + additional_length);
		additional_data = ((guchar *)cmd) + sizeof (*cmd);
	}

	cmd->cmd = c;
	cmd->version = RSPAMD_FUZZY_PLUGIN_VERSION;
	if (c != FUZZY_CHECK) {
		cmd->flag = flag;
		cmd->value = weight;
	}
	cmd->shingles_count = 0;
	cmd->tag = ottery_rand_uint32 ();
	memcpy (cmd->digest, digest, sizeof (cmd->digest));

	io = rspamd_mempool_alloc (task->task_pool, sizeof (*io));
	io->flags = 0;
	io->tag = cmd->tag;
	io->part = mp;
	memcpy (&io->cmd, cmd, sizeof (io->cmd));

	if (additional_length > 0) {
		fuzzy_cmd_write_extensions (task, rule, additional_data,
				additional_length);
	}

	if (rule->peer_key) {
		g_assert (enccmd != NULL);
		fuzzy_encrypt_cmd (rule, &enccmd->hdr, (guchar *)cmd,
				sizeof (*cmd) + additional_length);
		io->io.iov_base = enccmd;
		io->io.iov_len = sizeof (*enccmd) + additional_length;
	}
	else {
		io->io.iov_base = cmd;
		io->io.iov_len = sizeof (*cmd) + additional_length;
	}

	return io;
}

static gboolean
fuzzy_cmd_to_wire (gint fd, struct iovec *io)
{
	struct msghdr msg;

	memset (&msg, 0, sizeof (msg));
	msg.msg_iov = io;
	msg.msg_iovlen = 1;

	while (sendmsg (fd, &msg, 0) == -1) {
		if (errno == EINTR) {
			continue;
		}
		return FALSE;
	}

	return TRUE;
}

static gboolean
fuzzy_cmd_vector_to_wire (gint fd, GPtrArray *v)
{
	guint i;
	gboolean all_sent = TRUE, all_replied = TRUE;
	struct fuzzy_cmd_io *io;
	gboolean processed = FALSE;

	/* First try to resend unsent commands */
	for (i = 0; i < v->len; i ++) {
		io = g_ptr_array_index (v, i);

		if (io->flags & FUZZY_CMD_FLAG_REPLIED) {
			continue;
		}

		all_replied = FALSE;

		if (!(io->flags & FUZZY_CMD_FLAG_SENT)) {
			if (!fuzzy_cmd_to_wire (fd, &io->io)) {
				return FALSE;
			}
			processed = TRUE;
			io->flags |= FUZZY_CMD_FLAG_SENT;
			all_sent = FALSE;
		}
	}

	if (all_sent && !all_replied) {
		/* Now try to resend each command in the vector */
		for (i = 0; i < v->len; i++) {
			io = g_ptr_array_index (v, i);

			if (!(io->flags & FUZZY_CMD_FLAG_REPLIED)) {
				io->flags &= ~FUZZY_CMD_FLAG_SENT;
			}
		}

		return fuzzy_cmd_vector_to_wire (fd, v);
	}

	return processed;
}

/*
 * Read replies one-by-one and remove them from req array
 */
static const struct rspamd_fuzzy_reply *
fuzzy_process_reply (guchar **pos, gint *r, GPtrArray *req,
		struct fuzzy_rule *rule, struct rspamd_fuzzy_cmd **pcmd,
		struct fuzzy_cmd_io **pio)
{
	guchar *p = *pos;
	gint remain = *r;
	guint i, required_size;
	struct fuzzy_cmd_io *io;
	const struct rspamd_fuzzy_reply *rep;
	struct rspamd_fuzzy_encrypted_reply encrep;
	gboolean found = FALSE;

	if (rule->peer_key) {
		required_size = sizeof (encrep);
	}
	else {
		required_size = sizeof (*rep);
	}

	if (remain <= 0 || (guint)remain < required_size) {
		return NULL;
	}

	if (rule->peer_key) {
		memcpy (&encrep, p, sizeof (encrep));
		*pos += required_size;
		*r -= required_size;

		/* Try to decrypt reply */
		rspamd_keypair_cache_process (rule->ctx->keypairs_cache,
				rule->local_key, rule->peer_key);

		if (!rspamd_cryptobox_decrypt_nm_inplace ((guchar *)&encrep.rep,
				sizeof (encrep.rep),
				encrep.hdr.nonce,
				rspamd_pubkey_get_nm (rule->peer_key, rule->local_key),
				encrep.hdr.mac,
				rspamd_pubkey_alg (rule->peer_key))) {
			msg_info ("cannot decrypt reply");
			return NULL;
		}

		/* Copy decrypted over the input wire */
		memcpy (p, &encrep.rep, sizeof (encrep.rep));
	}
	else {

		*pos += required_size;
		*r -= required_size;
	}

	rep = (const struct rspamd_fuzzy_reply *) p;
	/*
	 * Search for tag
	 */
	for (i = 0; i < req->len; i ++) {
		io = g_ptr_array_index (req, i);

		if (io->tag == rep->v1.tag) {
			if (!(io->flags & FUZZY_CMD_FLAG_REPLIED)) {
				io->flags |= FUZZY_CMD_FLAG_REPLIED;

				if (pcmd) {
					*pcmd = &io->cmd;
				}

				if (pio) {
					*pio = io;
				}

				return rep;
			}
			found = TRUE;
		}
	}

	if (!found) {
		msg_info ("unexpected tag: %ud", rep->v1.tag);
	}

	return NULL;
}

static void
fuzzy_insert_result (struct fuzzy_client_session *session,
		const struct rspamd_fuzzy_reply *rep,
		struct rspamd_fuzzy_cmd *cmd,
		struct fuzzy_cmd_io *io,
		guint flag)
{
	const gchar *symbol;
	struct fuzzy_mapping *map;
	struct rspamd_task *task = session->task;
	double weight;
	double nval;
	guchar buf[2048];
	const gchar *type = "bin";
	struct fuzzy_client_result *res;
	gboolean is_fuzzy = FALSE;
	gchar hexbuf[rspamd_cryptobox_HASHBYTES * 2 + 1];
	/* Discriminate scores for small images */
	static const guint short_image_limit = 32 * 1024;

	/* Get mapping by flag */
	if ((map =
			g_hash_table_lookup (session->rule->mappings,
					GINT_TO_POINTER (rep->v1.flag))) == NULL) {
		/* Default symbol and default weight */
		symbol = session->rule->symbol;
		weight = session->rule->max_score;
	}
	else {
		/* Get symbol and weight from map */
		symbol = map->symbol;
		weight = map->weight;
	}

	res = rspamd_mempool_alloc0 (task->task_pool, sizeof (*res));
	res->prob = rep->v1.prob;
	res->symbol = symbol;
	/*
	 * Hash is assumed to be found if probability is more than 0.5
	 * In that case `value` means number of matches
	 * Otherwise `value` means error code
	 */

	nval = fuzzy_normalize (rep->v1.value, weight);

	if (io) {
		if ((io->flags & FUZZY_CMD_FLAG_IMAGE)) {
			if (!io->part || io->part->parsed_data.len <= short_image_limit) {
				nval *= rspamd_normalize_probability (rep->v1.prob, 0.5);
			}

			type = "img";
			res->type = FUZZY_RESULT_IMG;
		}
		else {
			/* Calc real probability */
			nval *= sqrtf (rep->v1.prob);

			if (cmd->shingles_count > 0) {
				type = "txt";
				res->type = FUZZY_RESULT_TXT;
			}
			else {
				if (io->flags & FUZZY_CMD_FLAG_CONTENT) {
					type = "content";
					res->type = FUZZY_RESULT_CONTENT;
				}
				else {
					res->type = FUZZY_RESULT_BIN;
				}
			}
		}
	}

	res->score = nval;

	if (memcmp (rep->digest, cmd->digest, sizeof (rep->digest)) != 0) {
		is_fuzzy = TRUE;
	}

	if (map != NULL || !session->rule->skip_unknown) {
		GList *fuzzy_var;
		rspamd_fstring_t *hex_result;
		gchar timebuf[64];
		struct tm tm_split;

		if (session->rule->skip_map) {
			rspamd_encode_hex_buf (cmd->digest, sizeof (cmd->digest),
				hexbuf, sizeof (hexbuf) - 1);
			hexbuf[sizeof (hexbuf) - 1] = '\0';
			if (rspamd_match_hash_map (session->rule->skip_map, hexbuf,
					sizeof (hexbuf) - 1)) {
				return;
			}
		}

		rspamd_encode_hex_buf (rep->digest, sizeof (rep->digest),
				hexbuf, sizeof (hexbuf) - 1);
		hexbuf[sizeof (hexbuf) - 1] = '\0';

		rspamd_gmtime (rep->ts, &tm_split);
		rspamd_snprintf (timebuf, sizeof (timebuf), "%02d.%02d.%4d %02d:%02d:%02d GMT",
				tm_split.tm_mday,
				tm_split.tm_mon + 1,
				tm_split.tm_year + 1900,
				tm_split.tm_hour, tm_split.tm_min, tm_split.tm_sec);

		if (is_fuzzy) {
			msg_info_task (
					"found fuzzy hash(%s) %s (%*xs requested) with weight: "
					"%.2f, probability %.2f, in list: %s:%d%s; added on %s",
					type,
					hexbuf,
					(gint) sizeof (cmd->digest), cmd->digest,
					nval,
					(gdouble) rep->v1.prob,
					symbol,
					rep->v1.flag,
					map == NULL ? "(unknown)" : "",
					timebuf);
		}
		else {
			msg_info_task (
					"found exact fuzzy hash(%s) %s with weight: "
					"%.2f, probability %.2f, in list: %s:%d%s; added on %s",
					type,
					hexbuf,
					nval,
					(gdouble) rep->v1.prob,
					symbol,
					rep->v1.flag,
					map == NULL ? "(unknown)" : "",
					timebuf);
		}

		rspamd_snprintf (buf,
				sizeof (buf),
				"%d:%*s:%.2f:%s",
				rep->v1.flag,
				(gint)MIN(rspamd_fuzzy_hash_len * 2, sizeof (rep->digest) * 2), hexbuf,
				rep->v1.prob,
				type);
		res->option = rspamd_mempool_strdup (task->task_pool, buf);
		g_ptr_array_add (session->results, res);

		/* Store hex string in pool variable */
		hex_result = rspamd_mempool_alloc (task->task_pool,
				sizeof (rspamd_fstring_t) + sizeof (hexbuf));
		memcpy (hex_result->str, hexbuf, sizeof (hexbuf));
		hex_result->len = sizeof (hexbuf) - 1;
		hex_result->allocated = (gsize)-1;
		fuzzy_var = rspamd_mempool_get_variable (task->task_pool,
				RSPAMD_MEMPOOL_FUZZY_RESULT);

		if (fuzzy_var == NULL) {
			fuzzy_var = g_list_prepend (NULL, hex_result);
			rspamd_mempool_set_variable (task->task_pool,
					RSPAMD_MEMPOOL_FUZZY_RESULT, fuzzy_var,
					(rspamd_mempool_destruct_t)g_list_free);
		}
		else {
			/* Not very efficient, but we don't really use it intensively */
			fuzzy_var = g_list_append (fuzzy_var, hex_result);
		}
	}
}

static gint
fuzzy_check_try_read (struct fuzzy_client_session *session)
{
	struct rspamd_task *task;
	const struct rspamd_fuzzy_reply *rep;
	struct rspamd_fuzzy_cmd *cmd = NULL;
	struct fuzzy_cmd_io *io = NULL;
	gint r, ret;
	guchar buf[2048], *p;

	task = session->task;

	if ((r = read (session->fd, buf, sizeof (buf) - 1)) == -1) {
		if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
			return 0;
		}
		else {
			return -1;
		}
	}
	else {
		p = buf;

		ret = 0;

		while ((rep = fuzzy_process_reply (&p, &r,
				session->commands, session->rule, &cmd, &io)) != NULL) {
			if (rep->v1.prob > 0.5) {
				if (cmd->cmd == FUZZY_CHECK) {
					fuzzy_insert_result (session, rep, cmd, io, rep->v1.flag);
				}
				else if (cmd->cmd == FUZZY_STAT) {
					/* Just set pool variable to extract it in further */
					struct rspamd_fuzzy_stat_entry *pval;
					GList *res;

					pval = rspamd_mempool_alloc (task->task_pool, sizeof (*pval));
					pval->fuzzy_cnt = rep->v1.flag;
					pval->name = session->rule->name;

					res = rspamd_mempool_get_variable (task->task_pool, "fuzzy_stat");

					if (res == NULL) {
						res = g_list_append (NULL, pval);
						rspamd_mempool_set_variable (task->task_pool, "fuzzy_stat",
								res, (rspamd_mempool_destruct_t)g_list_free);
					}
					else {
						res = g_list_append (res, pval);
					}
				}
			}
			else if (rep->v1.value == 403) {
				rspamd_task_insert_result (task, "FUZZY_BLOCKED", 0.0,
						session->rule->name);
			}
			else if (rep->v1.value == 401) {
				if (cmd->cmd != FUZZY_CHECK) {
					msg_info_task (
							"fuzzy check error for %d: skipped by server",
							rep->v1.flag);
				}
			}
			else if (rep->v1.value != 0) {
				msg_info_task (
						"fuzzy check error for %d: unknown error (%d)",
						rep->v1.flag,
						rep->v1.value);
			}

			ret = 1;
		}
	}

	return ret;
}

static void
fuzzy_insert_metric_results (struct rspamd_task *task, struct fuzzy_rule *rule,
		GPtrArray *results)
{
	struct fuzzy_client_result *res;
	guint i;
	gboolean seen_text_hash = FALSE,
			seen_img_hash = FALSE,
			seen_text_part = FALSE,
			seen_long_text = FALSE;
	gdouble prob_txt = 0.0, mult;
	struct rspamd_mime_text_part *tp;

	/* About 5 words */
	static const unsigned int text_length_cutoff = 25;

	PTR_ARRAY_FOREACH (results, i, res) {
		if (res->type == FUZZY_RESULT_TXT) {
			seen_text_hash = TRUE;
			prob_txt = MAX (prob_txt, res->prob);
		}
		else if (res->type == FUZZY_RESULT_IMG) {
			seen_img_hash = TRUE;
		}
	}

	if (task->message) {
		PTR_ARRAY_FOREACH (MESSAGE_FIELD (task, text_parts), i, tp) {
			if (!IS_TEXT_PART_EMPTY (tp) && tp->utf_words != NULL && tp->utf_words->len > 0) {
				seen_text_part = TRUE;

				if (tp->utf_stripped_text.magic == UTEXT_MAGIC) {
					if (utext_isLengthExpensive (&tp->utf_stripped_text)) {
						seen_long_text =
								utext_nativeLength (&tp->utf_stripped_text) >
								text_length_cutoff;
					}
					else {
						/* Cannot directly calculate length */
						seen_long_text =
								(tp->utf_stripped_content->len / 2) >
								text_length_cutoff;
					}
				}
			}
		}
	}

	PTR_ARRAY_FOREACH (results, i, res) {
		mult = 1.0;

		if (res->type == FUZZY_RESULT_IMG) {
			if (!seen_text_hash) {
				if (seen_long_text) {
					mult *= 0.25;
				}
				else if (seen_text_part) {
					/* We have some short text + image */
					mult *= 0.9;
				}
				/* Otherwise apply full score */
			}
			else if (prob_txt < 0.75) {
				/* Penalize sole image without matching text */
				if (prob_txt > 0.5) {
					mult *= prob_txt;
				}
				else {
					mult *= 0.5; /* cutoff */
				}
			}
		}
		else if (res->type == FUZZY_RESULT_TXT) {
			if (seen_img_hash) {
				/* Slightly increase score */
				mult = 1.1;
			}
		}

		gdouble weight = res->score * mult;

		if (!isnan (rule->weight_threshold)) {
			if (weight >= rule->weight_threshold) {
				rspamd_task_insert_result_single (task, res->symbol,
						weight, res->option);
			}
			else {
				msg_info_task ("%s is not added: weight=%.4f below threshold",
						res->symbol, weight);
			}
		}
		else {
			rspamd_task_insert_result_single (task, res->symbol,
					weight, res->option);
		}
	}
}

static gboolean
fuzzy_check_session_is_completed (struct fuzzy_client_session *session)
{
	struct fuzzy_cmd_io *io;
	guint nreplied = 0, i;

	rspamd_upstream_ok (session->server);

	for (i = 0; i < session->commands->len; i++) {
		io = g_ptr_array_index (session->commands, i);

		if (io->flags & FUZZY_CMD_FLAG_REPLIED) {
			nreplied++;
		}
	}

	if (nreplied == session->commands->len) {
		fuzzy_insert_metric_results (session->task, session->rule, session->results);

		if (session->item) {
			rspamd_symcache_item_async_dec_check (session->task, session->item, M);
		}

		rspamd_session_remove_event (session->task->s, fuzzy_io_fin, session);

		return TRUE;
	}

	return FALSE;
}

/* Fuzzy check timeout callback */
static void
fuzzy_check_timer_callback (gint fd, short what, void *arg)
{
	struct fuzzy_client_session *session = arg;
	struct rspamd_task *task;

	task = session->task;

	/* We might be here because of other checks being slow */
	if (fuzzy_check_try_read (session) > 0) {
		if (fuzzy_check_session_is_completed (session)) {
			return;
		}
	}

	if (session->retransmits >= session->rule->retransmits) {
		msg_err_task ("got IO timeout with server %s(%s), after %d/%d retransmits",
				rspamd_upstream_name (session->server),
				rspamd_inet_address_to_string_pretty (
						rspamd_upstream_addr_cur (session->server)),
				session->retransmits,
				session->rule->retransmits);
		rspamd_upstream_fail (session->server, TRUE, "timeout");

		if (session->item) {
			rspamd_symcache_item_async_dec_check (session->task, session->item, M);
		}
		rspamd_session_remove_event (session->task->s, fuzzy_io_fin, session);
	}
	else {
		/* Plan write event */
		rspamd_ev_watcher_reschedule (session->event_loop,
				&session->ev, EV_READ|EV_WRITE);
		session->retransmits ++;
	}
}

/* Fuzzy check callback */
static void
fuzzy_check_io_callback (gint fd, short what, void *arg)
{
	struct fuzzy_client_session *session = arg;
	struct rspamd_task *task;
	gint r;

	enum {
		return_error = 0,
		return_want_more,
		return_finished
	} ret = return_error;

	task = session->task;

	if ((what & EV_READ) || session->state == 1) {
		/* Try to read reply */
		r = fuzzy_check_try_read (session);

		switch (r) {
		case 0:
			if (what & EV_READ) {
				ret = return_want_more;
			}
			else {
				if (what & EV_WRITE) {
					/* Retransmit attempt */
					if (!fuzzy_cmd_vector_to_wire (fd, session->commands)) {
						ret = return_error;
					}
					else {
						session->state = 1;
						ret = return_want_more;
					}
				}
				else {
					/* It is actually time out */
					fuzzy_check_timer_callback(fd, what, arg);
					return;
				}
			}
			break;
		case 1:
			ret = return_finished;
			break;
		default:
			ret = return_error;
			break;
		}
	}
	else if (what & EV_WRITE) {
		if (!fuzzy_cmd_vector_to_wire (fd, session->commands)) {
			ret = return_error;
		}
		else {
			session->state = 1;
			ret = return_want_more;
		}
	}
	else {
		fuzzy_check_timer_callback (fd, what, arg);
		return;
	}

	if (ret == return_want_more) {
		/* Processed write, switch to reading */
		rspamd_ev_watcher_reschedule (session->event_loop,
				&session->ev, EV_READ);
	}
	else if (ret == return_error) {
		/* Error state */
		msg_err_task ("got error on IO with server %s(%s), on %s, %d, %s",
			rspamd_upstream_name (session->server),
				rspamd_inet_address_to_string_pretty (
						rspamd_upstream_addr_cur (session->server)),
			session->state == 1 ? "read" : "write",
			errno,
			strerror (errno));
		rspamd_upstream_fail (session->server, TRUE, strerror (errno));

		if (session->item) {
			rspamd_symcache_item_async_dec_check (session->task, session->item, M);
		}

		rspamd_session_remove_event (session->task->s, fuzzy_io_fin, session);
	}
	else {
		/* Read something from network */
		if (!fuzzy_check_session_is_completed (session)) {
			/* Need to read more */
			rspamd_ev_watcher_reschedule (session->event_loop,
					&session->ev, EV_READ);
		}
	}
}


static void
fuzzy_lua_fin (void *ud)
{
	struct fuzzy_learn_session *session = ud;

	(*session->saved)--;

	rspamd_ev_watcher_stop (session->event_loop, &session->ev);
	close (session->fd);
}

/* Controller IO */

static void
fuzzy_controller_timer_callback (gint fd, short what, void *arg)
{
	struct fuzzy_learn_session *session = arg;
	struct rspamd_task *task;

	task = session->task;

	if (session->retransmits >= session->rule->retransmits) {
		rspamd_upstream_fail (session->server, TRUE, "timeout");
		msg_err_task_check ("got IO timeout with server %s(%s), "
							"after %d/%d retransmits",
				rspamd_upstream_name (session->server),
				rspamd_inet_address_to_string_pretty (
						rspamd_upstream_addr_cur (session->server)),
				session->retransmits,
				session->rule->retransmits);

		if (session->session) {
			rspamd_session_remove_event (session->session, fuzzy_lua_fin,
					session);
		}
		else {
			if (session->http_entry) {
				rspamd_controller_send_error (session->http_entry,
						500, "IO timeout with fuzzy storage");
			}

			if (*session->saved > 0 ) {
				(*session->saved)--;
				if (*session->saved == 0) {
					if (session->http_entry) {
						rspamd_task_free (session->task);
					}

					session->task = NULL;
				}
			}

			if (session->http_entry) {
				rspamd_http_connection_unref (session->http_entry->conn);
			}

			rspamd_ev_watcher_stop (session->event_loop,
					&session->ev);
			close (session->fd);
		}
	}
	else {
		/* Plan write event */
		rspamd_ev_watcher_reschedule (session->event_loop,
				&session->ev, EV_READ|EV_WRITE);
		session->retransmits ++;
	}
}

static void
fuzzy_controller_io_callback (gint fd, short what, void *arg)
{
	struct fuzzy_learn_session *session = arg;
	const struct rspamd_fuzzy_reply *rep;
	struct fuzzy_mapping *map;
	struct rspamd_task *task;
	guchar buf[2048], *p;
	struct fuzzy_cmd_io *io;
	struct rspamd_fuzzy_cmd *cmd = NULL;
	const gchar *symbol, *ftype;
	gint r;
	enum {
		return_error = 0,
		return_want_more,
		return_finished
	} ret = return_want_more;
	guint i, nreplied;
	const gchar *op = "process";

	task = session->task;

	if (what & EV_READ) {
		if ((r = read (fd, buf, sizeof (buf) - 1)) == -1) {
			if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
				rspamd_ev_watcher_reschedule (session->event_loop,
						&session->ev, EV_READ);
				return;
			}

			msg_info_task ("cannot process fuzzy hash for message: %s",
					strerror (errno));
			session->err.error_message = "read socket error";
			session->err.error_code = errno;

			ret = return_error;
		}
		else {
			p = buf;
			ret = return_want_more;

			while ((rep = fuzzy_process_reply (&p, &r,
					session->commands, session->rule, &cmd, &io)) != NULL) {
				if ((map =
						g_hash_table_lookup (session->rule->mappings,
								GINT_TO_POINTER (rep->v1.flag))) == NULL) {
					/* Default symbol and default weight */
					symbol = session->rule->symbol;

				}
				else {
					/* Get symbol and weight from map */
					symbol = map->symbol;
				}

				ftype = "bin";

				if (io) {
					if ((io->flags & FUZZY_CMD_FLAG_IMAGE)) {
						ftype = "img";
					}
					else if (io->flags & FUZZY_CMD_FLAG_CONTENT) {
						ftype = "content";
					}
					else if (cmd->shingles_count > 0) {
						ftype = "txt";
					}

					if (io->cmd.cmd == FUZZY_WRITE) {
						op = "added";
					}
					else if (io->cmd.cmd == FUZZY_DEL) {
						op = "deleted";
					}
				}

				if (rep->v1.prob > 0.5) {
					msg_info_task ("%s fuzzy hash (%s) %*xs, list: %s:%d for "
							"message <%s>",
							op,
							ftype,
							(gint)sizeof (rep->digest), rep->digest,
							symbol,
							rep->v1.flag,
							MESSAGE_FIELD_CHECK (session->task, message_id));
				}
				else {
					if (rep->v1.value == 401) {
						msg_info_task (
								"fuzzy hash (%s) for message cannot be %s"
										"<%s>, %*xs, "
										"list %s:%d, skipped by server",
								ftype,
								op,
								MESSAGE_FIELD_CHECK (session->task, message_id),
								(gint)sizeof (rep->digest), rep->digest,
								symbol,
								rep->v1.flag);

						session->err.error_message = "fuzzy hash is skipped";
						session->err.error_code = rep->v1.value;
					}
					else {
						msg_info_task (
								"fuzzy hash (%s) for message cannot be %s"
										"<%s>, %*xs, "
										"list %s:%d, error: %d",
								ftype,
								op,
								MESSAGE_FIELD_CHECK (session->task, message_id),
								(gint)sizeof (rep->digest), rep->digest,
								symbol,
								rep->v1.flag,
								rep->v1.value);

						session->err.error_message = "process fuzzy error";
						session->err.error_code = rep->v1.value;
					}

					ret = return_finished;
				}
			}

			nreplied = 0;

			for (i = 0; i < session->commands->len; i++) {
				io = g_ptr_array_index (session->commands, i);

				if (io->flags & FUZZY_CMD_FLAG_REPLIED) {
					nreplied++;
				}
			}

			if (nreplied == session->commands->len) {
				ret = return_finished;
			}
		}
	}
	else if (what & EV_WRITE) {
			/* Send commands to storage */
			if (!fuzzy_cmd_vector_to_wire (fd, session->commands)) {
				session->err.error_message = "write socket error";
				session->err.error_code = errno;
				ret = return_error;
			}
		}
	else {
		fuzzy_controller_timer_callback (fd, what, arg);

		return;
	}

	if (ret == return_want_more) {
		rspamd_ev_watcher_reschedule (session->event_loop,
				&session->ev, EV_READ);

		return;
	}
	else if (ret == return_error) {
		msg_err_task ("got error in IO with server %s(%s), %d, %s",
				rspamd_upstream_name (session->server),
				rspamd_inet_address_to_string_pretty (
						rspamd_upstream_addr_cur (session->server)),
				errno, strerror (errno));
		rspamd_upstream_fail (session->server, FALSE, strerror (errno));
	}

	/*
	 * XXX: actually, we check merely a single reply, which is not correct...
	 * XXX: when we send a command, we do not check if *all* commands have been
	 * written
	 * XXX: please, please, change this code some day
	 */

	if (session->session == NULL) {
		(*session->saved)--;

		if (session->http_entry) {
			rspamd_http_connection_unref (session->http_entry->conn);
		}

		rspamd_ev_watcher_stop (session->event_loop, &session->ev);
		close (session->fd);

		if (*session->saved == 0) {
			goto cleanup;
		}
	}
	else {
		/* Lua handler */
		rspamd_session_remove_event (session->session, fuzzy_lua_fin, session);
	}

	return;

cleanup:
	/*
	 * When we send learn commands to fuzzy storages, this code is executed
	 * *once* when we have queried all storages. We also don't know which
	 * storage has been failed.
	 *
	 * Therefore, we cleanup sessions earlier and actually this code is wrong.
	 */

	if (session->err.error_code != 0) {
		if (session->http_entry) {
			rspamd_controller_send_error (session->http_entry,
					session->err.error_code, session->err.error_message);
		}
	}
	else {
		rspamd_upstream_ok (session->server);

		if (session->http_entry) {
			ucl_object_t *reply, *hashes;
			gchar hexbuf[rspamd_cryptobox_HASHBYTES * 2 + 1];

			reply = ucl_object_typed_new (UCL_OBJECT);

			ucl_object_insert_key (reply, ucl_object_frombool (true),
					"success", 0, false);
			hashes = ucl_object_typed_new (UCL_ARRAY);

			for (i = 0; i < session->commands->len; i ++) {
				io = g_ptr_array_index (session->commands, i);

				rspamd_snprintf (hexbuf, sizeof (hexbuf), "%*xs",
						(gint)sizeof (io->cmd.digest), io->cmd.digest);
				ucl_array_append (hashes, ucl_object_fromstring (hexbuf));
			}

			ucl_object_insert_key (reply, hashes, "hashes", 0, false);
			rspamd_controller_send_ucl (session->http_entry, reply);
			ucl_object_unref (reply);
		}
	}

	if (session->task != NULL) {
		if (session->http_entry) {
			rspamd_task_free (session->task);
		}

		session->task = NULL;
	}

}

static GPtrArray *
fuzzy_generate_commands (struct rspamd_task *task, struct fuzzy_rule *rule,
		gint c, gint flag, guint32 value, guint flags)
{
	struct rspamd_mime_text_part *part;
	struct rspamd_mime_part *mime_part;
	struct rspamd_image *image;
	struct fuzzy_cmd_io *io, *cur;
	guint i, j;
	GPtrArray *res = NULL;
	gboolean check_part, fuzzy_check;

	if (c == FUZZY_STAT) {
		res = g_ptr_array_sized_new (1);

		io = fuzzy_cmd_stat (rule, c, flag, value, task->task_pool);
		if (io) {
			g_ptr_array_add (res, io);
		}

		goto end;
	}

	if (task->message == NULL) {
		goto end;
	}

	res = g_ptr_array_sized_new (MESSAGE_FIELD (task, parts)->len + 1);

	PTR_ARRAY_FOREACH (MESSAGE_FIELD (task, parts), i, mime_part) {
		check_part = FALSE;
		fuzzy_check = FALSE;

		if (fuzzy_rule_check_mimepart (task, rule, mime_part, &check_part,
				&fuzzy_check)) {
			io = NULL;

			if (check_part) {
				if (mime_part->part_type == RSPAMD_MIME_PART_TEXT &&
					!(flags & FUZZY_CHECK_FLAG_NOTEXT)) {
					part = mime_part->specific.txt;

					io = fuzzy_cmd_from_text_part (task, rule,
							c,
							flag,
							value,
							!fuzzy_check,
							part,
							mime_part);
				}
				else if (mime_part->part_type == RSPAMD_MIME_PART_IMAGE &&
					!(flags & FUZZY_CHECK_FLAG_NOIMAGES)) {
					image = mime_part->specific.img;

					io = fuzzy_cmd_from_data_part (rule, c, flag, value,
							task,
							image->parent->digest,
							mime_part);
					io->flags |= FUZZY_CMD_FLAG_IMAGE;
				}
				else if (mime_part->part_type == RSPAMD_MIME_PART_CUSTOM_LUA) {
					const struct rspamd_lua_specific_part *lua_spec;

					lua_spec = &mime_part->specific.lua_specific;

					if (lua_spec->type == RSPAMD_LUA_PART_TABLE) {
						lua_State *L = (lua_State *)task->cfg->lua_state;
						gint old_top;

						old_top = lua_gettop (L);
						/* Push table */
						lua_rawgeti (L, LUA_REGISTRYINDEX, lua_spec->cbref);
						lua_pushstring (L, "fuzzy_hashes");
						lua_gettable (L, -2);

						if (lua_type (L, -1) == LUA_TTABLE) {
							gint tbl_pos = lua_gettop (L);

							for (lua_pushnil (L); lua_next (L, tbl_pos);
									lua_pop (L, 1)) {
								const gchar *h = NULL;
								gsize hlen = 0;

								if (lua_isstring (L, -1)) {
									h = lua_tolstring (L, -1, &hlen);
								}
								else if (lua_type (L, -1) == LUA_TUSERDATA) {
									struct rspamd_lua_text *t;

									t = lua_check_text (L, -1);

									if (t) {
										h = t->start;
										hlen = t->len;
									}
 								}

								if (hlen == rspamd_cryptobox_HASHBYTES) {
									io = fuzzy_cmd_from_data_part (rule, c,
											flag, value,
											task,
											(guchar *)h,
											mime_part);

									if (io) {
										io->flags |= FUZZY_CMD_FLAG_CONTENT;
										g_ptr_array_add (res, io);
									}
								}
							}
						}

						lua_settop (L, old_top);

						/*
						 * Add part itself as well
						 */
						io = fuzzy_cmd_from_data_part (rule, c,
								flag, value,
								task,
								mime_part->digest,
								mime_part);
					}
				}
				else {
					io = fuzzy_cmd_from_data_part (rule, c, flag, value,
							task,
							mime_part->digest, mime_part);
				}

				if (io) {
					gboolean skip_existing = FALSE;

					PTR_ARRAY_FOREACH (res, j, cur) {
						if (memcmp (cur->cmd.digest, io->cmd.digest,
								sizeof (io->cmd.digest)) == 0) {
							skip_existing = TRUE;
							break;
						}
					}

					if (!skip_existing) {
						g_ptr_array_add (res, io);
					}
				}
			}
		}
	}

end:
	if (res && res->len == 0) {
		g_ptr_array_free (res, TRUE);

		return NULL;
	}

	return res;
}


static inline void
register_fuzzy_client_call (struct rspamd_task *task,
	struct fuzzy_rule *rule,
	GPtrArray *commands)
{
	struct fuzzy_client_session *session;
	struct upstream *selected;
	rspamd_inet_addr_t *addr;
	gint sock;

	if (!rspamd_session_blocked (task->s)) {
		/* Get upstream */
		selected = rspamd_upstream_get (rule->servers, RSPAMD_UPSTREAM_ROUND_ROBIN,
				NULL, 0);
		if (selected) {
			addr = rspamd_upstream_addr_next (selected);
			if ((sock = rspamd_inet_address_connect (addr, SOCK_DGRAM, TRUE)) == -1) {
				msg_warn_task ("cannot connect to %s(%s), %d, %s",
						rspamd_upstream_name (selected),
						rspamd_inet_address_to_string_pretty (addr),
						errno,
						strerror (errno));
				rspamd_upstream_fail (selected, TRUE, strerror (errno));
				g_ptr_array_free (commands, TRUE);
			} else {
				/* Create session for a socket */
				session =
						rspamd_mempool_alloc0 (task->task_pool,
								sizeof (struct fuzzy_client_session));
				session->state = 0;
				session->commands = commands;
				session->task = task;
				session->fd = sock;
				session->server = selected;
				session->rule = rule;
				session->results = g_ptr_array_sized_new (32);
				session->event_loop = task->event_loop;

				rspamd_ev_watcher_init (&session->ev,
						sock,
						EV_WRITE,
						fuzzy_check_io_callback,
						session);
				rspamd_ev_watcher_start (session->event_loop, &session->ev,
						rule->io_timeout);

				rspamd_session_add_event (task->s, fuzzy_io_fin, session, M);
				session->item = rspamd_symcache_get_cur_item (task);

				if (session->item) {
					rspamd_symcache_item_async_inc (task, session->item, M);
				}
			}
		}
	}
}

/* This callback is called when we check message in fuzzy hashes storage */
static void
fuzzy_symbol_callback (struct rspamd_task *task,
					   struct rspamd_symcache_item *item,
					   void *unused)
{
	struct fuzzy_rule *rule;
	guint i;
	GPtrArray *commands;
	struct fuzzy_ctx *fuzzy_module_ctx = fuzzy_get_context (task->cfg);

	if (!fuzzy_module_ctx->enabled) {
		rspamd_symcache_finalize_item (task, item);

		return;
	}

	/* Check whitelist */
	if (fuzzy_module_ctx->whitelist) {
		if (rspamd_match_radix_map_addr (fuzzy_module_ctx->whitelist,
				task->from_addr) != NULL) {
			msg_info_task ("<%s>, address %s is whitelisted, skip fuzzy check",
					MESSAGE_FIELD (task, message_id),
					rspamd_inet_address_to_string (task->from_addr));
			rspamd_symcache_finalize_item (task, item);

			return;
		}
	}

	rspamd_symcache_item_async_inc (task, item, M);

	PTR_ARRAY_FOREACH (fuzzy_module_ctx->fuzzy_rules, i, rule) {
		commands = fuzzy_generate_commands (task, rule, FUZZY_CHECK, 0, 0, 0);

		if (commands != NULL) {
			register_fuzzy_client_call (task, rule, commands);
		}
	}

	rspamd_symcache_item_async_dec_check (task, item, M);
}

void
fuzzy_stat_command (struct rspamd_task *task)
{
	struct fuzzy_rule *rule;
	guint i;
	GPtrArray *commands;
	struct fuzzy_ctx *fuzzy_module_ctx = fuzzy_get_context (task->cfg);

	if (!fuzzy_module_ctx->enabled) {
		return;
	}

	PTR_ARRAY_FOREACH (fuzzy_module_ctx->fuzzy_rules, i, rule) {
		commands = fuzzy_generate_commands (task, rule, FUZZY_STAT, 0, 0, 0);
		if (commands != NULL) {
			register_fuzzy_client_call (task, rule, commands);
		}
	}
}

static inline gint
register_fuzzy_controller_call (struct rspamd_http_connection_entry *entry,
	struct fuzzy_rule *rule,
	struct rspamd_task *task,
	GPtrArray *commands,
	gint *saved)
{
	struct fuzzy_learn_session *s;
	struct upstream *selected;
	rspamd_inet_addr_t *addr;
	struct rspamd_controller_session *session = entry->ud;
	gint sock;
	gint ret = -1;

	/* Get upstream */

	while ((selected = rspamd_upstream_get_forced (rule->servers,
			RSPAMD_UPSTREAM_SEQUENTIAL, NULL, 0))) {
		/* Create UDP socket */
		addr = rspamd_upstream_addr_next (selected);

		if ((sock = rspamd_inet_address_connect (addr,
				SOCK_DGRAM, TRUE)) == -1) {
			msg_warn_task ("cannot connect to fuzzy storage %s (%s rule): %s",
					rspamd_inet_address_to_string_pretty (addr),
					rule->name,
					strerror (errno));
			rspamd_upstream_fail (selected, TRUE, strerror (errno));
		}
		else {
			s =
				rspamd_mempool_alloc0 (session->pool,
					sizeof (struct fuzzy_learn_session));

			s->task = task;
			s->commands = commands;
			s->http_entry = entry;
			s->server = selected;
			s->saved = saved;
			s->fd = sock;
			s->rule = rule;
			s->event_loop = task->event_loop;
			/* We ref connection to avoid freeing before we process fuzzy rule */
			rspamd_http_connection_ref (entry->conn);

			rspamd_ev_watcher_init (&s->ev,
					sock,
					EV_WRITE,
					fuzzy_controller_io_callback,
					s);
			rspamd_ev_watcher_start (s->event_loop, &s->ev, rule->io_timeout);

			(*saved)++;
			ret = 1;
		}
	}

	return ret;
}

static void
fuzzy_process_handler (struct rspamd_http_connection_entry *conn_ent,
	struct rspamd_http_message *msg, gint cmd, gint value, gint flag,
	struct fuzzy_ctx *ctx, gboolean is_hash, guint flags)
{
	struct fuzzy_rule *rule;
	struct rspamd_controller_session *session = conn_ent->ud;
	struct rspamd_task *task, **ptask;
	gboolean processed = FALSE, skip = FALSE;
	gint res = 0;
	guint i;
	GPtrArray *commands;
	lua_State *L;
	gint r, *saved, rules = 0, err_idx;
	struct fuzzy_ctx *fuzzy_module_ctx;

	/* Prepare task */
	task = rspamd_task_new (session->wrk, session->cfg, NULL,
			session->lang_det, conn_ent->rt->event_loop, FALSE);
	task->cfg = ctx->cfg;
	saved = rspamd_mempool_alloc0 (session->pool, sizeof (gint));
	fuzzy_module_ctx = fuzzy_get_context (ctx->cfg);

	if (!is_hash) {
		/* Allocate message from string */
		/* XXX: what about encrypted messages ? */
		task->msg.begin = msg->body_buf.begin;
		task->msg.len = msg->body_buf.len;

		r = rspamd_message_parse (task);

		if (r == -1) {
			msg_warn_task ("<%s>: cannot process message for fuzzy",
					MESSAGE_FIELD (task, message_id));
			rspamd_task_free (task);
			rspamd_controller_send_error (conn_ent, 400,
					"Message processing error");

			return;
		}

		rspamd_message_process (task);
	}

	PTR_ARRAY_FOREACH (fuzzy_module_ctx->fuzzy_rules, i, rule) {
		if (rule->read_only) {
			continue;
		}

		/* Check for flag */
		if (g_hash_table_lookup (rule->mappings,
				GINT_TO_POINTER (flag)) == NULL) {
			msg_info_task ("skip rule %s as it has no flag %d defined"
					" false", rule->name, flag);
			continue;
		}

		/* Check learn condition */
		if (rule->learn_condition_cb != -1) {
			skip = FALSE;
			L = session->cfg->lua_state;
			lua_pushcfunction (L, &rspamd_lua_traceback);
			err_idx = lua_gettop (L);

			lua_rawgeti (L, LUA_REGISTRYINDEX, rule->learn_condition_cb);
			ptask = lua_newuserdata (L, sizeof (struct rspamd_task *));
			*ptask = task;
			rspamd_lua_setclass (L, "rspamd{task}", -1);

			if (lua_pcall (L, 1, LUA_MULTRET, err_idx) != 0) {
				msg_err_task ("call to fuzzy learn condition failed: %s",
						lua_tostring (L, -1));
			}
			else {
				if (lua_gettop (L) > err_idx + 1) {
					/* 2 return values */
					skip = !(lua_toboolean (L, err_idx + 1));

					if (lua_isnumber (L, err_idx + 2)) {
						msg_info_task ("learn condition changed flag from %d to "
								"%d", flag,
								(gint)lua_tonumber (L, err_idx + 2));
						flag = lua_tonumber (L, err_idx + 2);
					}
				}
				else {
					if (lua_isboolean (L, err_idx + 1)) {
						skip = !(lua_toboolean (L, err_idx + 1));
					}
					else {
						msg_warn_task ("set skip for rule %s as its condition "
								"callback returned"
								" a valid boolean", rule->name);
						skip = TRUE;
					}
				}
			}

			/* Result + error function */
			lua_settop (L, err_idx - 1);

			if (skip) {
				msg_info_task ("skip rule %s by condition callback",
						rule->name);
				continue;
			}
		}

		rules ++;

		res = 0;

		if (is_hash) {
			GPtrArray *args;
			const rspamd_ftok_t *arg;
			guint j;

			args = rspamd_http_message_find_header_multiple (msg, "Hash");

			if (args) {
				struct fuzzy_cmd_io *io;
				commands = g_ptr_array_sized_new (args->len);

				for (j = 0; j < args->len; j ++) {
					arg = g_ptr_array_index (args, j);
					io = fuzzy_cmd_hash (rule, cmd, arg, flag, value,
							task->task_pool);

					if (io) {
						g_ptr_array_add (commands, io);
					}
				}

				res = register_fuzzy_controller_call (conn_ent,
						rule,
						task,
						commands,
						saved);
				rspamd_mempool_add_destructor (task->task_pool,
						rspamd_ptr_array_free_hard, commands);
				g_ptr_array_free (args, TRUE);
			}
			else {
				rspamd_controller_send_error (conn_ent, 400,
						"No hash defined");
				rspamd_task_free (task);
				return;
			}
		}
		else {
			commands = fuzzy_generate_commands (task, rule, cmd, flag, value,
					flags);
			if (commands != NULL) {
				res = register_fuzzy_controller_call (conn_ent,
						rule,
						task,
						commands,
						saved);
				rspamd_mempool_add_destructor (task->task_pool,
						rspamd_ptr_array_free_hard, commands);
			}
		}

		if (res > 0) {
			processed = TRUE;
		}
	}

	if (res == -1) {
		if (!processed) {
			msg_warn_task ("cannot send fuzzy request: %s",
					strerror (errno));
			rspamd_controller_send_error (conn_ent, 400, "Message sending error");
			rspamd_task_free (task);

			return;
		}
		else {
			/* Some rules failed and some rules are OK */
			msg_warn_task ("some rules are not processed, but we still sent this request");
		}
	}
	else if (!processed) {
		if (rules) {
			msg_warn_task ("no content to generate fuzzy");
			rspamd_controller_send_error (conn_ent, 404,
				"No content to generate fuzzy for flag %d", flag);
		}
		else {
			if (skip) {
				rspamd_controller_send_error (conn_ent, 403,
						"Message is conditionally skipped for flag %d", flag);
			}
			else {
				msg_warn_task ("no fuzzy rules found for flag %d", flag);
				rspamd_controller_send_error (conn_ent, 404,
						"No fuzzy rules matched for flag %d", flag);
			}
		}
		rspamd_task_free (task);
	}
}

static int
fuzzy_controller_handler (struct rspamd_http_connection_entry *conn_ent,
	struct rspamd_http_message *msg, struct module_ctx *ctx, gint cmd,
	gboolean is_hash)
{
	const rspamd_ftok_t *arg;
	glong value = 1, flag = 0, send_flags = 0;
	struct fuzzy_ctx *fuzzy_module_ctx = (struct fuzzy_ctx *)ctx;

	if (!fuzzy_module_ctx->enabled) {
		msg_err ("fuzzy_check module is not enabled");
		rspamd_controller_send_error (conn_ent, 500, "Module disabled");
		return 0;
	}

	if (fuzzy_module_ctx->fuzzy_rules == NULL) {
		msg_err ("fuzzy_check module has no rules defined");
		rspamd_controller_send_error (conn_ent, 500, "Module has no rules");
		return 0;
	}

	/* Get size */
	arg = rspamd_http_message_find_header (msg, "Weight");
	if (arg) {
		errno = 0;

		if (!rspamd_strtol (arg->begin, arg->len, &value)) {
			msg_info ("error converting numeric argument %T", arg);
		}
	}

	arg = rspamd_http_message_find_header (msg, "Flag");
	if (arg) {
		errno = 0;

		if (!rspamd_strtol (arg->begin, arg->len, &flag)) {
			msg_info ("error converting numeric argument %T", arg);
			flag = 0;
		}
	}
	else {
		flag = 0;
		arg = rspamd_http_message_find_header (msg, "Symbol");

		/* Search flag by symbol */
		if (arg) {
			struct fuzzy_rule *rule;
			guint i;
			GHashTableIter it;
			gpointer k, v;
			struct fuzzy_mapping *map;

			PTR_ARRAY_FOREACH (fuzzy_module_ctx->fuzzy_rules, i, rule) {
				if (flag != 0) {
					break;
				}

				g_hash_table_iter_init (&it, rule->mappings);

				while (g_hash_table_iter_next (&it, &k, &v)) {
					map = v;

					if (strlen (map->symbol) == arg->len &&
							rspamd_lc_cmp (map->symbol, arg->begin, arg->len) == 0) {
						flag = map->fuzzy_flag;
						break;
					}
				}
			}
		}
	}

	if (flag == 0) {
		msg_err ("no flag defined to learn fuzzy");
		rspamd_controller_send_error (conn_ent, 404, "Unknown or missing flag");
		return 0;
	}

	arg = rspamd_http_message_find_header (msg, "Skip-Images");
	if (arg) {
		send_flags |= FUZZY_CHECK_FLAG_NOIMAGES;
	}

	arg = rspamd_http_message_find_header (msg, "Skip-Attachments");
	if (arg) {
		send_flags |= FUZZY_CHECK_FLAG_NOATTACHMENTS;
	}

	arg = rspamd_http_message_find_header (msg, "Skip-Text");
	if (arg) {
		send_flags |= FUZZY_CHECK_FLAG_NOTEXT;
	}

	fuzzy_process_handler (conn_ent, msg, cmd, value, flag,
		(struct fuzzy_ctx *)ctx, is_hash, send_flags);

	return 0;
}

static inline gint
fuzzy_check_send_lua_learn (struct fuzzy_rule *rule,
	struct rspamd_task *task,
	GPtrArray *commands,
	gint *saved)
{
	struct fuzzy_learn_session *s;
	struct upstream *selected;
	rspamd_inet_addr_t *addr;
	gint sock;
	gint ret = -1;

	/* Get upstream */
	if (!rspamd_session_blocked (task->s)) {
		while ((selected = rspamd_upstream_get (rule->servers,
				RSPAMD_UPSTREAM_SEQUENTIAL, NULL, 0))) {
			/* Create UDP socket */
			addr = rspamd_upstream_addr_next (selected);

			if ((sock = rspamd_inet_address_connect (addr,
					SOCK_DGRAM, TRUE)) == -1) {
				rspamd_upstream_fail (selected, TRUE, strerror (errno));
			} else {
				s =
						rspamd_mempool_alloc0 (task->task_pool,
								sizeof (struct fuzzy_learn_session));
				s->task = task;
				s->commands = commands;
				s->http_entry = NULL;
				s->server = selected;
				s->saved = saved;
				s->fd = sock;
				s->rule = rule;
				s->session = task->s;
				s->event_loop = task->event_loop;

				rspamd_ev_watcher_init (&s->ev,
						sock,
						EV_WRITE,
						fuzzy_controller_io_callback,
						s);
				rspamd_ev_watcher_start (s->event_loop, &s->ev,
						rule->io_timeout);

				rspamd_session_add_event (task->s,
						fuzzy_lua_fin,
						s,
						M);

				(*saved)++;
				ret = 1;
			}
		}
	}

	return ret;
}

static gboolean
fuzzy_check_lua_process_learn (struct rspamd_task *task,
		gint cmd, gint value, gint flag, guint send_flags)
{
	struct fuzzy_rule *rule;
	gboolean processed = FALSE, res = TRUE;
	guint i;
	GPtrArray *commands;
	gint *saved, rules = 0;
	struct fuzzy_ctx *fuzzy_module_ctx = fuzzy_get_context (task->cfg);

	saved = rspamd_mempool_alloc0 (task->task_pool, sizeof (gint));

	PTR_ARRAY_FOREACH (fuzzy_module_ctx->fuzzy_rules, i, rule) {
		if (!res) {
			break;
		}
		if (rule->read_only) {
			continue;
		}

		/* Check for flag */
		if (g_hash_table_lookup (rule->mappings,
				GINT_TO_POINTER (flag)) == NULL) {
			msg_info_task ("skip rule %s as it has no flag %d defined"
					" false", rule->name, flag);
			continue;
		}

		rules ++;

		res = 0;
		commands = fuzzy_generate_commands (task, rule, cmd, flag,
				value, send_flags);

		if (commands != NULL) {
			res = fuzzy_check_send_lua_learn (rule, task, commands,
					saved);
			rspamd_mempool_add_destructor (task->task_pool,
					rspamd_ptr_array_free_hard, commands);
		}

		if (res) {
			processed = TRUE;
		}
	}

	if (res == -1) {
		msg_warn_task ("cannot send fuzzy request: %s",
				strerror (errno));
	}
	else if (!processed) {
		if (rules) {
			msg_warn_task ("no content to generate fuzzy");

			return FALSE;
		}
		else {
			msg_warn_task ("no fuzzy rules found for flag %d", flag);
			return FALSE;
		}
	}

	return TRUE;
}

static gint
fuzzy_lua_learn_handler (lua_State *L)
{
	struct rspamd_task *task = lua_check_task (L, 1);

	if (task == NULL) {
		return luaL_error(L, "invalid arguments");
	}

	guint flag = 0, weight = 1, send_flags = 0;
	const gchar *symbol;
	struct fuzzy_ctx *fuzzy_module_ctx = fuzzy_get_context (task->cfg);

	if (lua_type (L, 2) == LUA_TNUMBER) {
		flag = lua_tointeger (L, 2);
	}
	else if (lua_type (L, 2) == LUA_TSTRING) {
		struct fuzzy_rule *rule;
		guint i;
		GHashTableIter it;
		gpointer k, v;
		struct fuzzy_mapping *map;

		symbol = lua_tostring (L, 2);

		PTR_ARRAY_FOREACH (fuzzy_module_ctx->fuzzy_rules, i, rule) {
			if (flag != 0) {
				break;
			}

			g_hash_table_iter_init (&it, rule->mappings);

			while (g_hash_table_iter_next (&it, &k, &v)) {
				map = v;

				if (g_ascii_strcasecmp (symbol, map->symbol) == 0) {
					flag = map->fuzzy_flag;
					break;
				}
			}
		}
	}

	if (flag == 0) {
		return luaL_error (L, "bad flag");
	}

	if (lua_type (L, 3) == LUA_TNUMBER) {
		weight = lua_tonumber (L, 3);
	}

	if (lua_type (L, 4) == LUA_TTABLE) {
		const gchar *sf;

		for (lua_pushnil (L); lua_next (L, -2); lua_pop (L, 1)) {
			sf = lua_tostring (L, -1);

			if (sf) {
				if (g_ascii_strcasecmp (sf, "noimages") == 0) {
					send_flags |= FUZZY_CHECK_FLAG_NOIMAGES;
				}
				else if (g_ascii_strcasecmp (sf, "noattachments") == 0) {
					send_flags |= FUZZY_CHECK_FLAG_NOATTACHMENTS;
				}
				else if (g_ascii_strcasecmp (sf, "notext") == 0) {
					send_flags |= FUZZY_CHECK_FLAG_NOTEXT;
				}
			}
		}
	}

	lua_pushboolean (L,
			fuzzy_check_lua_process_learn (task, FUZZY_WRITE, weight, flag,
					send_flags));
	return 1;
}

static gint
fuzzy_lua_unlearn_handler (lua_State *L)
{
	struct rspamd_task *task = lua_check_task (L, 1);
	if (task == NULL) {
		return luaL_error(L, "invalid arguments");
	}

	guint flag = 0, weight = 1.0, send_flags = 0;
	const gchar *symbol;
	struct fuzzy_ctx *fuzzy_module_ctx = fuzzy_get_context (task->cfg);

	if (lua_type (L, 2) == LUA_TNUMBER) {
		flag = lua_tonumber (L, 1);
	}
	else if (lua_type (L, 2) == LUA_TSTRING) {
		struct fuzzy_rule *rule;
		guint i;
		GHashTableIter it;
		gpointer k, v;
		struct fuzzy_mapping *map;

		symbol = lua_tostring (L, 2);

		PTR_ARRAY_FOREACH (fuzzy_module_ctx->fuzzy_rules, i, rule) {

			if (flag != 0) {
				break;
			}

			g_hash_table_iter_init (&it, rule->mappings);

			while (g_hash_table_iter_next (&it, &k, &v)) {
				map = v;

				if (g_ascii_strcasecmp (symbol, map->symbol) == 0) {
					flag = map->fuzzy_flag;
					break;
				}
			}
		}
	}

	if (flag == 0) {
		return luaL_error (L, "bad flag");
	}

	if (lua_type (L, 3) == LUA_TNUMBER) {
		weight = lua_tonumber (L, 3);
	}

	if (lua_type (L, 4) == LUA_TTABLE) {
		const gchar *sf;

		for (lua_pushnil (L); lua_next (L, -2); lua_pop (L, 1)) {
			sf = lua_tostring (L, -1);

			if (sf) {
				if (g_ascii_strcasecmp (sf, "noimages") == 0) {
					send_flags |= FUZZY_CHECK_FLAG_NOIMAGES;
				}
				else if (g_ascii_strcasecmp (sf, "noattachments") == 0) {
					send_flags |= FUZZY_CHECK_FLAG_NOATTACHMENTS;
				}
				else if (g_ascii_strcasecmp (sf, "notext") == 0) {
					send_flags |= FUZZY_CHECK_FLAG_NOTEXT;
				}
			}
		}
	}

	lua_pushboolean (L,
			fuzzy_check_lua_process_learn (task, FUZZY_DEL, weight, flag,
					send_flags));

	return 1;
}

static gint
fuzzy_lua_gen_hashes_handler (lua_State *L)
{
	struct rspamd_task *task = lua_check_task (L, 1);

	if (task == NULL) {
		return luaL_error(L, "invalid arguments");
	}

	guint flag = 0, weight = 1, send_flags = 0;
	const gchar *symbol;
	struct fuzzy_ctx *fuzzy_module_ctx = fuzzy_get_context (task->cfg);
	struct fuzzy_rule *rule;
	GPtrArray *commands;
	gint cmd = FUZZY_WRITE;
	gint i;

	if (lua_type (L, 2) == LUA_TNUMBER) {
		flag = lua_tonumber (L, 2);
	}
	else if (lua_type (L, 2) == LUA_TSTRING) {
		struct fuzzy_rule *rule;
		guint i;
		GHashTableIter it;
		gpointer k, v;
		struct fuzzy_mapping *map;

		symbol = lua_tostring (L, 2);

		PTR_ARRAY_FOREACH (fuzzy_module_ctx->fuzzy_rules, i, rule) {
			if (flag != 0) {
				break;
			}

			g_hash_table_iter_init (&it, rule->mappings);

			while (g_hash_table_iter_next (&it, &k, &v)) {
				map = v;

				if (g_ascii_strcasecmp (symbol, map->symbol) == 0) {
					flag = map->fuzzy_flag;
					break;
				}
			}
		}
	}

	if (flag == 0) {
		return luaL_error (L, "bad flag");
	}

	if (lua_type (L, 3) == LUA_TNUMBER) {
		weight = lua_tonumber (L, 3);
	}

	/* Flags */
	if (lua_type (L, 4) == LUA_TTABLE) {
		const gchar *sf;

		for (lua_pushnil (L); lua_next (L, -2); lua_pop (L, 1)) {
			sf = lua_tostring (L, -1);

			if (sf) {
				if (g_ascii_strcasecmp (sf, "noimages") == 0) {
					send_flags |= FUZZY_CHECK_FLAG_NOIMAGES;
				}
				else if (g_ascii_strcasecmp (sf, "noattachments") == 0) {
					send_flags |= FUZZY_CHECK_FLAG_NOATTACHMENTS;
				}
				else if (g_ascii_strcasecmp (sf, "notext") == 0) {
					send_flags |= FUZZY_CHECK_FLAG_NOTEXT;
				}
			}
		}
	}

	/* Type */
	if (lua_type (L, 5) == LUA_TSTRING) {
		const gchar *cmd_name = lua_tostring (L, 5);

		if (strcmp (cmd_name, "add") == 0 || strcmp (cmd_name, "write") == 0) {
			cmd = FUZZY_WRITE;
		}
		else if (strcmp (cmd_name, "delete") == 0 || strcmp (cmd_name, "remove") == 0) {
			cmd = FUZZY_DEL;
		}
		else {
			return luaL_error (L, "invalid command: %s", cmd_name);
		}
	}

	lua_createtable (L, 0, fuzzy_module_ctx->fuzzy_rules->len);

	PTR_ARRAY_FOREACH (fuzzy_module_ctx->fuzzy_rules, i, rule) {
		if (rule->read_only) {
			continue;
		}

		/* Check for flag */
		if (g_hash_table_lookup (rule->mappings,
				GINT_TO_POINTER (flag)) == NULL) {
			msg_info_task ("skip rule %s as it has no flag %d defined"
						   " false", rule->name, flag);
			continue;
		}

		commands = fuzzy_generate_commands (task, rule, cmd, flag,
				weight, send_flags);

		if (commands != NULL) {
			struct fuzzy_cmd_io *io;
			gint j;

			lua_pushstring (L, rule->name);
			lua_createtable (L, commands->len, 0);

			PTR_ARRAY_FOREACH (commands, j, io) {
				lua_pushlstring (L, io->io.iov_base, io->io.iov_len);
				lua_rawseti (L, -2, j + 1);
			}

			lua_settable (L, -3); /* ret[rule->name] = {raw_fuzzy1, ..., raw_fuzzyn} */

			g_ptr_array_free (commands, TRUE);
		}
	}


	return 1;
}

static gboolean
fuzzy_add_handler (struct rspamd_http_connection_entry *conn_ent,
	struct rspamd_http_message *msg, struct module_ctx *ctx)
{
	return fuzzy_controller_handler (conn_ent, msg,
			   ctx, FUZZY_WRITE, FALSE);
}

static gboolean
fuzzy_delete_handler (struct rspamd_http_connection_entry *conn_ent,
	struct rspamd_http_message *msg, struct module_ctx *ctx)
{
	return fuzzy_controller_handler (conn_ent, msg,
			   ctx, FUZZY_DEL, FALSE);
}

static gboolean
fuzzy_deletehash_handler (struct rspamd_http_connection_entry *conn_ent,
	struct rspamd_http_message *msg, struct module_ctx *ctx)
{
	return fuzzy_controller_handler (conn_ent, msg,
			   ctx, FUZZY_DEL, TRUE);
}

static int
fuzzy_attach_controller (struct module_ctx *ctx, GHashTable *commands)
{
	struct fuzzy_ctx *fctx = (struct fuzzy_ctx *)ctx;
	struct rspamd_custom_controller_command *cmd;

	cmd = rspamd_mempool_alloc (fctx->fuzzy_pool, sizeof (*cmd));
	cmd->privilleged = TRUE;
	cmd->require_message = TRUE;
	cmd->handler = fuzzy_add_handler;
	cmd->ctx = ctx;
	g_hash_table_insert (commands, "/fuzzyadd", cmd);

	cmd = rspamd_mempool_alloc (fctx->fuzzy_pool, sizeof (*cmd));
	cmd->privilleged = TRUE;
	cmd->require_message = TRUE;
	cmd->handler = fuzzy_delete_handler;
	cmd->ctx = ctx;
	g_hash_table_insert (commands, "/fuzzydel", cmd);

	cmd = rspamd_mempool_alloc (fctx->fuzzy_pool, sizeof (*cmd));
	cmd->privilleged = TRUE;
	cmd->require_message = FALSE;
	cmd->handler = fuzzy_deletehash_handler;
	cmd->ctx = ctx;
	g_hash_table_insert (commands, "/fuzzydelhash", cmd);

	return 0;
}
