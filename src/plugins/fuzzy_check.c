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
#include "libutil/map.h"
#include "libmime/images.h"
#include "libserver/worker_util.h"
#include "fuzzy_storage.h"
#include "utlist.h"
#include "cryptobox.h"
#include "ottery.h"
#include "keypair.h"
#include "lua/lua_common.h"
#include "unix-std.h"
#include "libutil/http_private.h"
#include <math.h>

#define DEFAULT_SYMBOL "R_FUZZY_HASH"
#define DEFAULT_UPSTREAM_ERROR_TIME 10
#define DEFAULT_UPSTREAM_DEAD_TIME 300
#define DEFAULT_UPSTREAM_MAXERRORS 10

#define DEFAULT_IO_TIMEOUT 500
#define DEFAULT_RETRANSMITS 3
#define DEFAULT_PORT 11335

#define RSPAMD_FUZZY_PLUGIN_VERSION RSPAMD_FUZZY_VERSION

static const gint rspamd_fuzzy_hash_len = 5;

struct fuzzy_mapping {
	guint64 fuzzy_flag;
	const gchar *symbol;
	double weight;
};

struct fuzzy_mime_type {
	GPatternSpec *type;
	GPatternSpec *subtype;
};

struct fuzzy_rule {
	struct upstream_list *servers;
	const gchar *symbol;
	const gchar *algorithm_str;
	const gchar *name;
	enum rspamd_shingle_alg alg;
	GHashTable *mappings;
	GList *mime_types;
	GList *fuzzy_headers;
	GString *hash_key;
	GString *shingles_key;
	struct rspamd_cryptobox_keypair *local_key;
	struct rspamd_cryptobox_pubkey *peer_key;
	double max_score;
	gboolean read_only;
	gboolean skip_unknown;
	gint learn_condition_cb;
};

struct fuzzy_ctx {
	struct module_ctx ctx;
	rspamd_mempool_t *fuzzy_pool;
	GList *fuzzy_rules;
	struct rspamd_config *cfg;
	const gchar *default_symbol;
	guint32 min_hash_len;
	radix_compressed_t *whitelist;
	struct rspamd_keypair_cache *keypairs_cache;
	guint32 min_bytes;
	guint32 min_height;
	guint32 min_width;
	guint32 io_timeout;
	guint32 retransmits;
	gboolean enabled;
};

struct fuzzy_client_session {
	GPtrArray *commands;
	struct rspamd_task *task;
	struct upstream *server;
	rspamd_inet_addr_t *addr;
	struct fuzzy_rule *rule;
	struct event ev;
	struct event timev;
	struct timeval tv;
	gint state;
	gint fd;
	guint retransmits;
};

struct fuzzy_learn_session {
	GPtrArray *commands;
	gint *saved;
	GError **err;
	struct rspamd_http_connection_entry *http_entry;
	struct upstream *server;
	rspamd_inet_addr_t *addr;
	struct fuzzy_rule *rule;
	struct rspamd_task *task;
	struct event ev;
	struct event timev;
	struct timeval tv;
	gint fd;
	guint retransmits;
};

#define FUZZY_CMD_FLAG_REPLIED (1 << 0)
#define FUZZY_CMD_FLAG_SENT (1 << 1)

struct fuzzy_cmd_io {
	guint32 tag;
	guint32 flags;
	struct rspamd_fuzzy_cmd cmd;
	struct iovec io;
};

static struct fuzzy_ctx *fuzzy_module_ctx = NULL;
static const char *default_headers = "Subject,Content-Type,Reply-To,X-Mailer";

static void fuzzy_symbol_callback (struct rspamd_task *task, void *unused);

/* Initialization */
gint fuzzy_check_module_init (struct rspamd_config *cfg,
	struct module_ctx **ctx);
gint fuzzy_check_module_config (struct rspamd_config *cfg);
gint fuzzy_check_module_reconfig (struct rspamd_config *cfg);
static gint fuzzy_attach_controller (struct module_ctx *ctx,
	GHashTable *commands);

module_t fuzzy_check_module = {
	"fuzzy_check",
	fuzzy_check_module_init,
	fuzzy_check_module_config,
	fuzzy_check_module_reconfig,
	fuzzy_attach_controller,
	RSPAMD_MODULE_VER
};

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
				rspamd_mempool_alloc (fuzzy_module_ctx->fuzzy_pool,
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
				rspamd_symbols_cache_add_symbol (cfg->cache,
						map->symbol, 0,
						NULL, NULL,
						SYMBOL_TYPE_VIRTUAL|SYMBOL_TYPE_FINE,
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

static GList *
parse_mime_types (const gchar *str)
{
	gchar **strvec, *p;
	gint num, i;
	struct fuzzy_mime_type *type;
	GList *res = NULL;

	strvec = g_strsplit_set (str, ",", 0);
	num = g_strv_length (strvec);
	for (i = 0; i < num; i++) {
		g_strstrip (strvec[i]);
		if ((p = strchr (strvec[i], '/')) != NULL) {
			*p = 0;
			type = rspamd_mempool_alloc (fuzzy_module_ctx->fuzzy_pool,
					sizeof (struct fuzzy_mime_type));
			type->type = g_pattern_spec_new (strvec[i]);
			type->subtype = g_pattern_spec_new (p + 1);
			*p = '/';
			res = g_list_prepend (res, type);
		}
		else {
			type = rspamd_mempool_alloc (fuzzy_module_ctx->fuzzy_pool,
							sizeof (struct fuzzy_mime_type));
			type->type = g_pattern_spec_new (strvec[i]);
			type->subtype = NULL;
			res = g_list_prepend (res, type);
		}
	}

	g_strfreev (strvec);

	return res;
}

static GList *
parse_fuzzy_headers (const gchar *str)
{
	gchar **strvec;
	gint num, i;
	GList *res = NULL;

	strvec = g_strsplit_set (str, ",", 0);
	num = g_strv_length (strvec);
	for (i = 0; i < num; i++) {
		g_strstrip (strvec[i]);
		res = g_list_prepend (res,
				rspamd_mempool_strdup (fuzzy_module_ctx->fuzzy_pool, strvec[i]));
	}

	g_strfreev (strvec);

	return res;
}

static gboolean
fuzzy_check_content_type (struct fuzzy_rule *rule, GMimeContentType *type)
{
	struct fuzzy_mime_type *ft;
	GList *cur;

	cur = rule->mime_types;
	while (cur) {
		ft = cur->data;
		if (ft->type) {

			if (g_pattern_match_string (ft->type, type->type)) {
				if (ft->subtype) {
					if (g_pattern_match_string (ft->subtype, type->subtype)) {
						return TRUE;
					}
				}
				else {
					return TRUE;
				}
			}
		}

		cur = g_list_next (cur);
	}

	return FALSE;
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

	if (obj->type != UCL_OBJECT) {
		msg_err_config ("invalid rule definition");
		return -1;
	}

	rule = fuzzy_rule_new (fuzzy_module_ctx->default_symbol,
			fuzzy_module_ctx->fuzzy_pool);
	rule->learn_condition_cb = -1;
	rule->alg = RSPAMD_SHINGLES_OLD;

	if ((value = ucl_object_lookup (obj, "mime_types")) != NULL) {
		it = NULL;
		while ((cur = ucl_object_iterate (value, &it, value->type == UCL_ARRAY))
				!= NULL) {
			rule->mime_types = g_list_concat (rule->mime_types,
					parse_mime_types (ucl_obj_tostring (cur)));
		}
	}

	if (rule->mime_types != NULL) {
		rspamd_mempool_add_destructor (fuzzy_module_ctx->fuzzy_pool,
			(rspamd_mempool_destruct_t)g_list_free, rule->mime_types);
	}

	if ((value = ucl_object_lookup (obj, "headers")) != NULL) {
		it = NULL;
		while ((cur = ucl_object_iterate (value, &it, value->type == UCL_ARRAY))
				!= NULL) {
			rule->fuzzy_headers = g_list_concat (rule->fuzzy_headers,
					parse_fuzzy_headers (ucl_obj_tostring (cur)));
		}
	}
	else {
		rule->fuzzy_headers = g_list_concat (rule->fuzzy_headers,
				parse_fuzzy_headers (default_headers));
	}

	if (rule->fuzzy_headers != NULL) {
		rspamd_mempool_add_destructor (fuzzy_module_ctx->fuzzy_pool,
				(rspamd_mempool_destruct_t) g_list_free, rule->fuzzy_headers);
	}


	if ((value = ucl_object_lookup (obj, "max_score")) != NULL) {
		rule->max_score = ucl_obj_todouble (value);
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
				msg_warn_config ("unknown algorithm: %s, use siphash by default");
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

		rspamd_mempool_add_destructor (fuzzy_module_ctx->fuzzy_pool,
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
		fuzzy_module_ctx->fuzzy_rules = g_list_prepend (
			fuzzy_module_ctx->fuzzy_rules,
			rule);
		if (rule->symbol != fuzzy_module_ctx->default_symbol) {
			rspamd_symbols_cache_add_symbol (cfg->cache, rule->symbol,
					0,
					NULL, NULL,
					SYMBOL_TYPE_VIRTUAL|SYMBOL_TYPE_FINE,
					cb_id);
		}

		msg_info_config ("added fuzzy rule %s, key: %*xs, "
				"shingles_key: %*xs, algorithm: %s",
				rule->symbol,
				6, rule->hash_key->str,
				6, rule->shingles_key->str,
				rule->algorithm_str);
	}

	rspamd_mempool_add_destructor (fuzzy_module_ctx->fuzzy_pool, fuzzy_free_rule,
			rule);

	return 0;
}

gint
fuzzy_check_module_init (struct rspamd_config *cfg, struct module_ctx **ctx)
{
	fuzzy_module_ctx = g_malloc0 (sizeof (struct fuzzy_ctx));

	fuzzy_module_ctx->fuzzy_pool = rspamd_mempool_new (rspamd_mempool_suggest_size (), NULL);
	fuzzy_module_ctx->cfg = cfg;
	/* TODO: this should match rules count actually */
	fuzzy_module_ctx->keypairs_cache = rspamd_keypair_cache_new (32);

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

	return 0;
}

gint
fuzzy_check_module_config (struct rspamd_config *cfg)
{
	const ucl_object_t *value, *cur, *elt;
	ucl_object_iter_t it;
	gint res = TRUE, cb_id, nrules = 0;

	if (!rspamd_config_is_module_enabled (cfg, "fuzzy_check")) {
		return TRUE;
	}

	fuzzy_module_ctx->enabled = TRUE;

	if ((value =
		rspamd_config_get_module_opt (cfg, "fuzzy_check", "symbol")) != NULL) {
		fuzzy_module_ctx->default_symbol = ucl_obj_tostring (value);
	}
	else {
		fuzzy_module_ctx->default_symbol = DEFAULT_SYMBOL;
	}

	if ((value =
		rspamd_config_get_module_opt (cfg, "fuzzy_check",
		"min_length")) != NULL) {
		fuzzy_module_ctx->min_hash_len = ucl_obj_toint (value);
	}
	else {
		fuzzy_module_ctx->min_hash_len = 0;
	}
	if ((value =
		rspamd_config_get_module_opt (cfg, "fuzzy_check",
		"min_bytes")) != NULL) {
		fuzzy_module_ctx->min_bytes = ucl_obj_toint (value);
	}
	else {
		fuzzy_module_ctx->min_bytes = 0;
	}
	if ((value =
		rspamd_config_get_module_opt (cfg, "fuzzy_check",
		"min_height")) != NULL) {
		fuzzy_module_ctx->min_height = ucl_obj_toint (value);
	}
	else {
		fuzzy_module_ctx->min_height = 0;
	}
	if ((value =
		rspamd_config_get_module_opt (cfg, "fuzzy_check",
		"min_width")) != NULL) {
		fuzzy_module_ctx->min_width = ucl_obj_toint (value);
	}
	else {
		fuzzy_module_ctx->min_width = 0;
	}
	if ((value =
		rspamd_config_get_module_opt (cfg, "fuzzy_check", "timeout")) != NULL) {
		fuzzy_module_ctx->io_timeout = ucl_obj_todouble (value) * 1000;
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
		"whitelist")) != NULL) {
		rspamd_config_radix_from_ucl (cfg, value, "Fuzzy whitelist",
				&fuzzy_module_ctx->whitelist, NULL);
	}
	else {
		fuzzy_module_ctx->whitelist = NULL;
	}

	if ((value =
		rspamd_config_get_module_opt (cfg, "fuzzy_check", "rule")) != NULL) {

		cb_id = rspamd_symbols_cache_add_symbol (cfg->cache,
					"FUZZY_CALLBACK", 0, fuzzy_symbol_callback, NULL,
					SYMBOL_TYPE_CALLBACK|SYMBOL_TYPE_FINE,
					-1);

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
	}

	if (fuzzy_module_ctx->fuzzy_rules == NULL) {
		msg_warn_config ("fuzzy module is enabled but no rules are defined");
	}

	msg_info_config ("init internal fuzzy_check module, %d rules loaded",
			nrules);

	return res;
}

gint
fuzzy_check_module_reconfig (struct rspamd_config *cfg)
{
	struct module_ctx saved_ctx;

	saved_ctx = fuzzy_module_ctx->ctx;
	rspamd_mempool_delete (fuzzy_module_ctx->fuzzy_pool);
	rspamd_keypair_cache_destroy (fuzzy_module_ctx->keypairs_cache);
	memset (fuzzy_module_ctx, 0, sizeof (*fuzzy_module_ctx));
	fuzzy_module_ctx->ctx = saved_ctx;
	fuzzy_module_ctx->fuzzy_pool = rspamd_mempool_new (rspamd_mempool_suggest_size (), NULL);
	fuzzy_module_ctx->cfg = cfg;
	fuzzy_module_ctx->keypairs_cache = rspamd_keypair_cache_new (32);

	return fuzzy_check_module_config (cfg);
}

/* Finalize IO */
static void
fuzzy_io_fin (void *ud)
{
	struct fuzzy_client_session *session = ud;

	if (session->commands) {
		g_ptr_array_free (session->commands, TRUE);
	}

	event_del (&session->ev);
	event_del (&session->timev);
	close (session->fd);
}

static GArray *
fuzzy_preprocess_words (struct rspamd_mime_text_part *part, rspamd_mempool_t *pool)
{
	return part->normalized_words;
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
	rspamd_keypair_cache_process (fuzzy_module_ctx->keypairs_cache,
			rule->local_key, rule->peer_key);
	rspamd_cryptobox_encrypt_nm_inplace (data, datalen,
			hdr->nonce, rspamd_pubkey_get_nm (rule->peer_key), hdr->mac,
			rspamd_pubkey_alg (rule->peer_key));
}

static struct fuzzy_cmd_io *
fuzzy_cmd_from_task_meta (struct fuzzy_rule *rule,
		int c,
		gint flag,
		guint32 weight,
		rspamd_mempool_t *pool,
		struct rspamd_task *task)
{
	struct rspamd_fuzzy_cmd *cmd;
	struct rspamd_fuzzy_encrypted_cmd *enccmd;
	struct fuzzy_cmd_io *io;
	rspamd_cryptobox_hash_state_t st;

	GHashTableIter it;
	gpointer k, v;
	struct rspamd_url *u;
	struct raw_header *rh;
	GList *cur;

	if (rule->peer_key) {
		enccmd = rspamd_mempool_alloc0 (pool, sizeof (*enccmd));
		cmd = &enccmd->cmd;
	}
	else {
		cmd = rspamd_mempool_alloc0 (pool, sizeof (*cmd));
	}

	cmd->cmd = c;
	cmd->version = RSPAMD_FUZZY_PLUGIN_VERSION;
	if (c != FUZZY_CHECK) {
		cmd->flag = flag;
		cmd->value = weight;
	}
	cmd->shingles_count = 0;
	cmd->tag = ottery_rand_uint32 ();
	/* Use blake2b for digest */
	rspamd_cryptobox_hash_init (&st, rule->hash_key->str, rule->hash_key->len);
	/* Hash URL's */
	g_hash_table_iter_init (&it, task->urls);

	while (g_hash_table_iter_next (&it, &k, &v)) {
		u = v;
		if (u->hostlen > 0) {
			rspamd_cryptobox_hash_update (&st, u->host, u->hostlen);
		}
		if (u->datalen > 0) {
			rspamd_cryptobox_hash_update (&st, u->data, u->datalen);
		}
	}
	/* Now get some headers to iterate on */

	cur = rule->fuzzy_headers;

	while (cur) {
		rh = g_hash_table_lookup (task->raw_headers, cur->data);

		while (rh) {
			if (rh->decoded) {
				rspamd_cryptobox_hash_update (&st, rh->decoded,
						strlen (rh->decoded));
			}

			rh = rh->next;
		}
		cur = g_list_next (cur);
	}

	rspamd_cryptobox_hash_final (&st, cmd->digest);

	io = rspamd_mempool_alloc (pool, sizeof (*io));
	io->flags = 0;
	io->tag = cmd->tag;
	memcpy (&io->cmd, cmd, sizeof (io->cmd));

	if (rule->peer_key) {
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
fuzzy_cmd_stat (struct fuzzy_rule *rule,
		int c,
		gint flag,
		guint32 weight,
		rspamd_mempool_t *pool)
{
	struct rspamd_fuzzy_cmd *cmd;
	struct rspamd_fuzzy_encrypted_cmd *enccmd;
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

	if (rule->peer_key) {
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

static void *
fuzzy_cmd_get_cached (struct fuzzy_rule *rule,
		rspamd_mempool_t *pool,
		struct rspamd_mime_text_part *part)
{
	gchar key[32];
	gint key_part;

	memcpy (&key_part, rule->shingles_key->str, sizeof (key_part));
	rspamd_snprintf (key, sizeof (key), "%p%s%d", part, rule->algorithm_str,
			key_part);

	return rspamd_mempool_get_variable (pool, key);
}

static void
fuzzy_cmd_set_cached (struct fuzzy_rule *rule,
		rspamd_mempool_t *pool,
		struct rspamd_mime_text_part *part,
		struct rspamd_fuzzy_encrypted_shingle_cmd *data)
{
	gchar key[32];
	gint key_part;

	memcpy (&key_part, rule->shingles_key->str, sizeof (key_part));
	rspamd_snprintf (key, sizeof (key), "%p%s%d", part, rule->algorithm_str,
			key_part);
	/* Key is copied */
	rspamd_mempool_set_variable (pool, key, data, NULL);
}

/*
 * Create fuzzy command from a text part
 */
static struct fuzzy_cmd_io *
fuzzy_cmd_from_text_part (struct fuzzy_rule *rule,
		int c,
		gint flag,
		guint32 weight,
		rspamd_mempool_t *pool,
		struct rspamd_mime_text_part *part)
{
	struct rspamd_fuzzy_shingle_cmd *shcmd;
	struct rspamd_fuzzy_encrypted_shingle_cmd *encshcmd, *cached;
	struct rspamd_shingle *sh;
	guint i;
	rspamd_cryptobox_hash_state_t st;
	rspamd_ftok_t *word;
	GArray *words;
	struct fuzzy_cmd_io *io;

	cached = fuzzy_cmd_get_cached (rule, pool, part);

	if (cached) {
		/* Copy cached */
		encshcmd = rspamd_mempool_alloc (pool, sizeof (*encshcmd));
		memcpy (encshcmd, cached, sizeof (*encshcmd));
		shcmd = &encshcmd->cmd;
	}
	else {
		encshcmd = rspamd_mempool_alloc0 (pool, sizeof (*encshcmd));
		shcmd = &encshcmd->cmd;

		/*
		 * Generate hash from all words in the part
		 */
		rspamd_cryptobox_hash_init (&st, rule->hash_key->str, rule->hash_key->len);
		words = fuzzy_preprocess_words (part, pool);

		for (i = 0; i < words->len; i ++) {
			word = &g_array_index (words, rspamd_ftok_t, i);
			rspamd_cryptobox_hash_update (&st, word->begin, word->len);
		}
		rspamd_cryptobox_hash_final (&st, shcmd->basic.digest);

		msg_debug_pool ("loading shingles of type %s with key %*xs",
				rule->algorithm_str,
				16, rule->shingles_key->str);
		sh = rspamd_shingles_generate (words,
				rule->shingles_key->str, pool,
				rspamd_shingles_default_filter, NULL,
				rule->alg);
		if (sh != NULL) {
			memcpy (&shcmd->sgl, sh, sizeof (shcmd->sgl));
			shcmd->basic.shingles_count = RSPAMD_SHINGLE_SIZE;
		}

		/*
		 * We always save encrypted command as it can handle both
		 * encrypted and unencrypted requests.
		 *
		 * Since it is copied when obtained from the cache, it is safe to use
		 * it this way.
		 */
		fuzzy_cmd_set_cached (rule, pool, part, encshcmd);
	}

	shcmd->basic.tag = ottery_rand_uint32 ();
	shcmd->basic.cmd = c;
	shcmd->basic.version = RSPAMD_FUZZY_PLUGIN_VERSION;

	if (c != FUZZY_CHECK) {
		shcmd->basic.flag = flag;
		shcmd->basic.value = weight;
	}

	io = rspamd_mempool_alloc (pool, sizeof (*io));
	io->tag = shcmd->basic.tag;
	io->flags = 0;
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

static struct fuzzy_cmd_io *
fuzzy_cmd_from_data_part (struct fuzzy_rule *rule,
		int c,
		gint flag,
		guint32 weight,
		rspamd_mempool_t *pool,
		guchar digest[rspamd_cryptobox_HASHBYTES])
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
	if (c != FUZZY_CHECK) {
		cmd->flag = flag;
		cmd->value = weight;
	}
	cmd->shingles_count = 0;
	cmd->tag = ottery_rand_uint32 ();
	memcpy (cmd->digest, digest, sizeof (cmd->digest));

	io = rspamd_mempool_alloc (pool, sizeof (*io));
	io->flags = 0;
	io->tag = cmd->tag;
	memcpy (&io->cmd, cmd, sizeof (io->cmd));

	if (rule->peer_key) {
		g_assert (enccmd != NULL);
		fuzzy_encrypt_cmd (rule, &enccmd->hdr, (guchar *) cmd, sizeof (*cmd));
		io->io.iov_base = enccmd;
		io->io.iov_len = sizeof (*enccmd);
	}
	else {
		io->io.iov_base = cmd;
		io->io.iov_len = sizeof (*cmd);
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
		struct fuzzy_rule *rule, struct rspamd_fuzzy_cmd **pcmd)
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
		rspamd_keypair_cache_process (fuzzy_module_ctx->keypairs_cache,
				rule->local_key, rule->peer_key);

		if (!rspamd_cryptobox_decrypt_nm_inplace ((guchar *)&encrep.rep,
				sizeof (encrep.rep),
				encrep.hdr.nonce,
				rspamd_pubkey_get_nm (rule->peer_key),
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

		if (io->tag == rep->tag) {
			if (!(io->flags & FUZZY_CMD_FLAG_REPLIED)) {
				io->flags |= FUZZY_CMD_FLAG_REPLIED;

				if (pcmd) {
					*pcmd = &io->cmd;
				}

				return rep;
			}
			found = TRUE;
		}
	}

	if (!found) {
		msg_info ("unexpected tag: %ud", rep->tag);
	}

	return NULL;
}

static void
fuzzy_insert_result (struct fuzzy_client_session *session,
		const struct rspamd_fuzzy_reply *rep,
		struct rspamd_fuzzy_cmd *cmd, guint flag)
{
	const gchar *symbol;
	struct fuzzy_mapping *map;
	struct rspamd_task *task = session->task;
	double nval;
	guchar buf[2048];

	/* Get mapping by flag */
	if ((map =
			g_hash_table_lookup (session->rule->mappings,
					GINT_TO_POINTER (rep->flag))) == NULL) {
		/* Default symbol and default weight */
		symbol = session->rule->symbol;

	}
	else {
		/* Get symbol and weight from map */
		symbol = map->symbol;
	}


	/*
	 * Hash is assumed to be found if probability is more than 0.5
	 * In that case `value` means number of matches
	 * Otherwise `value` means error code
	 */

	nval = fuzzy_normalize (rep->value,
			session->rule->max_score);
	nval *= rep->prob;
	msg_info_task (
			"found fuzzy hash %*xs with weight: "
			"%.2f, in list: %s:%d%s",
			rspamd_fuzzy_hash_len, cmd->digest,
			nval,
			symbol,
			rep->flag,
			map == NULL ? "(unknown)" : "");
	if (map != NULL || !session->rule->skip_unknown) {
		rspamd_snprintf (buf,
				sizeof (buf),
				"%d:%*xs:%.2f",
				rep->flag,
				rspamd_fuzzy_hash_len, cmd->digest,
				rep->prob,
				nval);
		rspamd_task_insert_result_single (session->task,
				symbol,
				nval,
				g_list_prepend (NULL,
						rspamd_mempool_strdup (
								session->task->task_pool,
								buf)));
	}
}

static gint
fuzzy_check_try_read (struct fuzzy_client_session *session)
{
	struct rspamd_task *task;
	const struct rspamd_fuzzy_reply *rep;
	struct rspamd_fuzzy_cmd *cmd = NULL;
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
				session->commands, session->rule, &cmd)) != NULL) {
			if (rep->prob > 0.5) {
				if (cmd->cmd == FUZZY_CHECK) {
					fuzzy_insert_result (session, rep, cmd, rep->flag);
				}
				else if (cmd->cmd == FUZZY_STAT) {
					/* Just set pool variable to extract it in further */
					struct rspamd_fuzzy_stat_entry *pval;
					GList *res;

					pval = rspamd_mempool_alloc (task->task_pool, sizeof (*pval));
					pval->fuzzy_cnt = rep->flag;
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
			else if (rep->value == 403) {
				msg_info_task (
						"fuzzy check error for %d: forbidden",
						rep->flag);
			}
			else if (rep->value != 0) {
				msg_info_task (
						"fuzzy check error for %d: unknown error (%d)",
						rep->flag,
						rep->value);
			}

			ret = 1;
		}
	}

	return ret;
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
		rspamd_session_remove_event (session->task->s, fuzzy_io_fin, session);

		return TRUE;
	}

	return FALSE;
}

/* Fuzzy check callback */
static void
fuzzy_check_io_callback (gint fd, short what, void *arg)
{
	struct fuzzy_client_session *session = arg;
	struct rspamd_task *task;
	struct event_base *ev_base;
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
			ret = return_want_more;
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
		/* Should not happen */
		g_assert (0);
	}

	if (ret == return_want_more) {
		/* Processed write, switch to reading */
		ev_base = event_get_base (&session->ev);
		event_del (&session->ev);
		event_set (&session->ev, fd, EV_READ,
				fuzzy_check_io_callback, session);
		event_base_set (ev_base, &session->ev);
		event_add (&session->ev, NULL);
	}
	else if (ret == return_error) {
		/* Error state */
		msg_err_task ("got error on IO with server %s(%s), on %s, %d, %s",
			rspamd_upstream_name (session->server),
			rspamd_inet_address_to_string (session->addr),
			session->state == 1 ? "read" : "write",
			errno,
			strerror (errno));
		rspamd_upstream_fail (session->server);
		rspamd_session_remove_event (session->task->s, fuzzy_io_fin, session);
	}
	else {
		/* Read something from network */
		if (!fuzzy_check_session_is_completed (session)) {
			/* Need to read more */
			ev_base = event_get_base (&session->ev);
			event_del (&session->ev);
			event_set (&session->ev, session->fd, EV_READ,
					fuzzy_check_io_callback, session);
			event_base_set (ev_base, &session->ev);
			event_add (&session->ev, NULL);
		}
	}
}

/* Fuzzy check timeout callback */
static void
fuzzy_check_timer_callback (gint fd, short what, void *arg)
{
	struct fuzzy_client_session *session = arg;
	struct rspamd_task *task;
	struct event_base *ev_base;

	task = session->task;

	/* We might be here because of other checks being slow */
	if (fuzzy_check_try_read (session) > 0) {
		if (fuzzy_check_session_is_completed (session)) {
			return;
		}
	}

	if (session->retransmits >= fuzzy_module_ctx->retransmits) {
		msg_err_task ("got IO timeout with server %s(%s), after %d retransmits",
				rspamd_upstream_name (session->server),
				rspamd_inet_address_to_string (session->addr),
				session->retransmits);
		rspamd_upstream_fail (session->server);
		rspamd_session_remove_event (session->task->s, fuzzy_io_fin, session);
	}
	else {
		/* Plan write event */
		ev_base = event_get_base (&session->ev);
		event_del (&session->ev);
		event_set (&session->ev, fd, EV_WRITE|EV_READ,
				fuzzy_check_io_callback, session);
		event_base_set (ev_base, &session->ev);
		event_add (&session->ev, NULL);

		/* Plan new retransmit timer */
		ev_base = event_get_base (&session->timev);
		event_del (&session->timev);
		event_base_set (ev_base, &session->timev);
		event_add (&session->timev, &session->tv);
		session->retransmits ++;
	}
}

/* Controller IO */
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
	const gchar *symbol;
	struct event_base *ev_base;
	gint r;
	enum {
		return_error = 0,
		return_want_more,
		return_finished
	} ret = return_want_more;
	guint i, nreplied;

	task = session->task;

	if (what & EV_READ) {
		if ((r = read (fd, buf, sizeof (buf) - 1)) == -1) {
			if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
				event_add (&session->ev, NULL);
				return;
			}

			msg_info_task ("cannot process fuzzy hash for message <%s>: %s",
					session->task->message_id, strerror (errno));
			if (*(session->err) == NULL) {
				g_set_error (session->err,
						g_quark_from_static_string ("fuzzy check"),
						errno, "read socket error: %s", strerror (errno));
			}
			ret = return_error;
		}
		else {
			p = buf;
			ret = return_want_more;

			while ((rep = fuzzy_process_reply (&p, &r,
					session->commands, session->rule, &cmd)) != NULL) {
				if ((map =
						g_hash_table_lookup (session->rule->mappings,
								GINT_TO_POINTER (rep->flag))) == NULL) {
					/* Default symbol and default weight */
					symbol = session->rule->symbol;

				}
				else {
					/* Get symbol and weight from map */
					symbol = map->symbol;
				}

				if (rep->prob > 0.5) {
					msg_info_task ("processed fuzzy hash %*xs, list: %s:%d for "
									"message <%s>",
							rspamd_fuzzy_hash_len, cmd->digest,
							symbol,
							rep->flag,
							session->task->message_id);
				}
				else {
					msg_info_task ("cannot process fuzzy hash for message "
							"<%s>, %*xs, "
							"list %s:%d, error: %d",
							session->task->message_id,
							rspamd_fuzzy_hash_len, cmd->digest,
							symbol,
							rep->flag,
							rep->value);
					if (*(session->err) == NULL) {
						g_set_error (session->err,
							g_quark_from_static_string ("fuzzy check"),
							rep->value, "process fuzzy error");
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
				if (*(session->err) == NULL) {
					g_set_error (session->err,
						g_quark_from_static_string ("fuzzy check"),
						errno, "write socket error: %s", strerror (errno));
				}
				ret = return_error;
			}
		}
	else {
		g_assert (0);
	}

	if (ret == return_want_more) {
		ev_base = event_get_base (&session->ev);
		event_del (&session->ev);
		event_set (&session->ev, fd, EV_READ,
				fuzzy_controller_io_callback, session);
		event_base_set (ev_base, &session->ev);
		event_add (&session->ev, NULL);

		return;
	}
	else if (ret == return_error) {
		msg_err_task ("got error in IO with server %s(%s), %d, %s",
				rspamd_upstream_name (session->server),
				rspamd_inet_address_to_string (session->addr),
				errno, strerror (errno));
		rspamd_upstream_fail (session->server);
	}

	/*
	 * XXX: actually, we check merely a single reply, which is not correct...
	 * XXX: when we send a command, we do not check if *all* commands have been
	 * written
	 * XXX: please, please, change this code some day
	 */
	(*session->saved)--;
	rspamd_http_connection_unref (session->http_entry->conn);
	event_del (&session->ev);
	event_del (&session->timev);
	close (session->fd);

	if (*session->saved == 0) {
		goto cleanup;
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

	if (*(session->err) != NULL) {
		rspamd_controller_send_error (session->http_entry,
				(*session->err)->code, (*session->err)->message);
		g_error_free (*session->err);
	}
	else {
		rspamd_upstream_ok (session->server);
		rspamd_controller_send_string (session->http_entry,
				"{\"success\":true}");
	}

	if (session->task != NULL) {
		rspamd_task_free (session->task);
		session->task = NULL;
	}

}

static void
fuzzy_controller_timer_callback (gint fd, short what, void *arg)
{
	struct fuzzy_learn_session *session = arg;
	struct rspamd_task *task;
	struct event_base *ev_base;

	task = session->task;

	if (session->retransmits >= fuzzy_module_ctx->retransmits) {
		rspamd_upstream_fail (session->server);
		rspamd_controller_send_error (session->http_entry,
				500, "IO timeout with fuzzy storage");
		msg_err_task ("got IO timeout with server %s(%s), after %d retransmits",
				rspamd_upstream_name (session->server),
				rspamd_inet_address_to_string (session->addr),
				session->retransmits);

		if (*session->saved > 0 ) {
			(*session->saved)--;
			if (*session->saved == 0) {
				rspamd_task_free (session->task);
				session->task = NULL;
			}
		}

		rspamd_http_connection_unref (session->http_entry->conn);
		event_del (&session->ev);
		event_del (&session->timev);
		close (session->fd);
	}
	else {
		/* Plan write event */
		ev_base = event_get_base (&session->ev);
		event_del (&session->ev);
		event_set (&session->ev, fd, EV_WRITE|EV_READ,
				fuzzy_controller_io_callback, session);
		event_base_set (ev_base, &session->ev);
		event_add (&session->ev, NULL);

		/* Plan new retransmit timer */
		ev_base = event_get_base (&session->timev);
		event_del (&session->timev);
		event_base_set (ev_base, &session->timev);
		event_add (&session->timev, &session->tv);
		session->retransmits ++;
	}
}

static GPtrArray *
fuzzy_generate_commands (struct rspamd_task *task, struct fuzzy_rule *rule,
		gint c, gint flag, guint32 value)
{
	struct rspamd_mime_text_part *part;
	struct rspamd_mime_part *mime_part;
	struct rspamd_image *image;
	struct fuzzy_cmd_io *io;
	guint i;
	GPtrArray *res;

	res = g_ptr_array_sized_new (task->parts->len + 1);

	if (c == FUZZY_STAT) {
		io = fuzzy_cmd_stat (rule, c, flag, value, task->task_pool);
		if (io) {
			g_ptr_array_add (res, io);
		}

		goto end;
	}

	for (i = 0; i < task->text_parts->len; i ++) {
		part = g_ptr_array_index (task->text_parts, i);

		if (IS_PART_EMPTY (part)) {
			continue;
		}

		/* Check length of part */
		if (fuzzy_module_ctx->min_bytes > part->content->len) {
			msg_info_task ("<%s>, part is shorter than %d bytes (%d bytes), "
					"skip fuzzy check",
					task->message_id, fuzzy_module_ctx->min_bytes,
					part->content->len);
			continue;
		}

		if (part->normalized_words == NULL || part->normalized_words->len == 0) {
			msg_info_task ("<%s>, part hash empty, skip fuzzy check",
				task->message_id);
			continue;
		}

		if (fuzzy_module_ctx->min_hash_len != 0 &&
			part->normalized_words->len < fuzzy_module_ctx->min_hash_len) {
			msg_info_task (
				"<%s>, part hash is shorter than %d symbols, skip fuzzy check",
				task->message_id,
				fuzzy_module_ctx->min_hash_len);
			continue;
		}

		io = fuzzy_cmd_from_text_part (rule, c, flag, value, task->task_pool,
				part);
		if (io) {
			g_ptr_array_add (res, io);
		}
	}

	/* Process other parts and images */
	for (i = 0; i < task->parts->len; i ++) {
		mime_part = g_ptr_array_index (task->parts, i);

		if (mime_part->flags & RSPAMD_MIME_PART_IMAGE) {
			image = mime_part->specific_data;

			if (image->data->len > 0) {
				if (fuzzy_module_ctx->min_height <= 0 || image->height >=
						fuzzy_module_ctx->min_height) {
					if (fuzzy_module_ctx->min_width <= 0 || image->width >=
							fuzzy_module_ctx->min_width) {
						io = fuzzy_cmd_from_data_part (rule, c, flag, value,
								task->task_pool,
								image->parent->digest);
						if (io) {
							g_ptr_array_add (res, io);
						}
					}
				}
			}
		}

		if (mime_part->content->len > 0 &&
			fuzzy_check_content_type (rule, mime_part->type)) {
			if (fuzzy_module_ctx->min_bytes <= 0 || mime_part->content->len >=
				fuzzy_module_ctx->min_bytes) {
				io = fuzzy_cmd_from_data_part (rule, c, flag, value,
						task->task_pool,
						mime_part->digest);
				if (io) {
					g_ptr_array_add (res, io);
				}
			}
		}
	}

	/* Process metadata */
#if 0
	io = fuzzy_cmd_from_task_meta (rule, c, flag, value,
			task->task_pool, task);
	if (io) {
		g_ptr_array_add (res, io);
	}
#endif
end:
	if (res->len == 0) {
		g_ptr_array_free (res, FALSE);
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

	/* Get upstream */
	selected = rspamd_upstream_get (rule->servers, RSPAMD_UPSTREAM_ROUND_ROBIN,
			NULL, 0);
	if (selected) {
		addr = rspamd_upstream_addr (selected);
		if ((sock = rspamd_inet_address_connect (addr, SOCK_DGRAM, TRUE)) == -1) {
			msg_warn_task ("cannot connect to %s(%s), %d, %s",
				rspamd_upstream_name (selected),
				rspamd_inet_address_to_string (addr),
				errno,
				strerror (errno));
			rspamd_upstream_fail (selected);
		}
		else {
			/* Create session for a socket */
			session =
				rspamd_mempool_alloc0 (task->task_pool,
					sizeof (struct fuzzy_client_session));
			msec_to_tv (fuzzy_module_ctx->io_timeout, &session->tv);
			session->state = 0;
			session->commands = commands;
			session->task = task;
			session->fd = sock;
			session->server = selected;
			session->rule = rule;
			session->addr = addr;

			event_set (&session->ev, sock, EV_WRITE, fuzzy_check_io_callback,
					session);
			event_base_set (session->task->ev_base, &session->ev);
			event_add (&session->ev, NULL);

			evtimer_set (&session->timev, fuzzy_check_timer_callback,
					session);
			event_base_set (session->task->ev_base, &session->timev);
			event_add (&session->timev, &session->tv);

			rspamd_session_add_event (task->s,
				fuzzy_io_fin,
				session,
				g_quark_from_static_string ("fuzzy check"));
		}
	}
}

/* This callback is called when we check message in fuzzy hashes storage */
static void
fuzzy_symbol_callback (struct rspamd_task *task, void *unused)
{
	struct fuzzy_rule *rule;
	GList *cur;
	GPtrArray *commands;

	if (!fuzzy_module_ctx->enabled) {
		return;
	}

	/* Check whitelist */
	if (fuzzy_module_ctx->whitelist) {
		if (radix_find_compressed_addr (fuzzy_module_ctx->whitelist,
				task->from_addr) != RADIX_NO_VALUE) {
			msg_info_task ("<%s>, address %s is whitelisted, skip fuzzy check",
				task->message_id,
				rspamd_inet_address_to_string (task->from_addr));
			return;
		}
	}

	cur = fuzzy_module_ctx->fuzzy_rules;
	while (cur) {
		rule = cur->data;
		commands = fuzzy_generate_commands (task, rule, FUZZY_CHECK, 0, 0);
		if (commands != NULL) {
			register_fuzzy_client_call (task, rule, commands);
		}
		cur = g_list_next (cur);
	}
}

void
fuzzy_stat_command (struct rspamd_task *task)
{
	struct fuzzy_rule *rule;
	GList *cur;
	GPtrArray *commands;

	if (!fuzzy_module_ctx->enabled) {
		return;
	}

	cur = fuzzy_module_ctx->fuzzy_rules;
	while (cur) {
		rule = cur->data;
		commands = fuzzy_generate_commands (task, rule, FUZZY_STAT, 0, 0);
		if (commands != NULL) {
			register_fuzzy_client_call (task, rule, commands);
		}
		cur = g_list_next (cur);
	}
}

static inline gint
register_fuzzy_controller_call (struct rspamd_http_connection_entry *entry,
	struct fuzzy_rule *rule,
	struct rspamd_task *task,
	GPtrArray *commands,
	gint *saved,
	GError **err)
{
	struct fuzzy_learn_session *s;
	struct upstream *selected;
	rspamd_inet_addr_t *addr;
	struct rspamd_controller_session *session = entry->ud;
	gint sock;
	gint ret = -1;

	/* Get upstream */

	while ((selected = rspamd_upstream_get (rule->servers,
			RSPAMD_UPSTREAM_SEQUENTIAL, NULL, 0))) {
		/* Create UDP socket */
		addr = rspamd_upstream_addr (selected);

		if ((sock = rspamd_inet_address_connect (addr,
				SOCK_DGRAM, TRUE)) == -1) {
			rspamd_upstream_fail (selected);
		}
		else {
			s =
				rspamd_mempool_alloc0 (session->pool,
					sizeof (struct fuzzy_learn_session));

			msec_to_tv (fuzzy_module_ctx->io_timeout, &s->tv);
			s->task = task;
			s->addr = addr;
			s->commands = commands;
			s->http_entry = entry;
			s->server = selected;
			s->saved = saved;
			s->fd = sock;
			s->err = err;
			s->rule = rule;
			/* We ref connection to avoid freeing before we process fuzzy rule */
			rspamd_http_connection_ref (entry->conn);

			event_set (&s->ev, sock, EV_WRITE, fuzzy_controller_io_callback, s);
			event_base_set (entry->rt->ev_base, &s->ev);
			event_add (&s->ev, NULL);

			evtimer_set (&s->timev, fuzzy_controller_timer_callback,
					s);
			event_base_set (s->task->ev_base, &s->timev);
			event_add (&s->timev, &s->tv);

			(*saved)++;
			ret = 1;
		}
	}

	return ret;
}

static void
fuzzy_process_handler (struct rspamd_http_connection_entry *conn_ent,
	struct rspamd_http_message *msg, gint cmd, gint value, gint flag,
	struct fuzzy_ctx *ctx)
{
	struct fuzzy_rule *rule;
	struct rspamd_controller_session *session = conn_ent->ud;
	struct rspamd_task *task, **ptask;
	gboolean processed = FALSE, res = TRUE, skip;
	GList *cur;
	GError **err;
	GPtrArray *commands;
	GString *tb;
	lua_State *L;
	gint r, *saved, rules = 0, err_idx;

	/* Prepare task */
	task = rspamd_task_new (session->wrk, session->cfg);
	task->cfg = ctx->cfg;
	task->ev_base = conn_ent->rt->ev_base;

	/* Allocate message from string */
	/* XXX: what about encrypted messsages ? */
	task->msg.begin = msg->body_buf.begin;
	task->msg.len = msg->body_buf.len;

	saved = rspamd_mempool_alloc0 (session->pool, sizeof (gint));
	err = rspamd_mempool_alloc0 (session->pool, sizeof (GError *));
	r = rspamd_message_parse (task);

	if (r == -1) {
		msg_warn_task ("<%s>: cannot process message for fuzzy",
				task->message_id);
		rspamd_task_free (task);
		rspamd_controller_send_error (conn_ent, 400,
			"Message processing error");
		return;
	}

	cur = fuzzy_module_ctx->fuzzy_rules;

	while (cur && res) {
		rule = cur->data;

		if (rule->read_only) {
			cur = g_list_next (cur);
			continue;
		}

		/* Check for flag */
		if (g_hash_table_lookup (rule->mappings,
				GINT_TO_POINTER (flag)) == NULL) {
			msg_info_task ("skip rule %s as it has no flag %d defined"
					" false", rule->name, flag);
			cur = g_list_next (cur);
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
				tb = lua_touserdata (L, -1);
				msg_err_task ("call to user extraction script failed: %v", tb);
				g_string_free (tb, TRUE);
			}
			else {
				if (lua_gettop (L) > 1) {
					skip = !(lua_toboolean (L, -2));

					if (lua_isnumber (L, -1)) {
						msg_info_task ("learn condition changed flag from %d to "
								"%d", flag, (guint)lua_tonumber (L, -1));
						flag = lua_tonumber (L, -1);
					}
				}
				else {
					skip = !(lua_toboolean (L, -1));
				}
			}

			/* Result + error function */
			lua_settop (L, 0);

			if (skip) {
				msg_info_task ("skip rule %s as its condition callback returned"
						" false", rule->name);
				cur = g_list_next (cur);
				continue;
			}
		}

		rules ++;

		res = 0;
		commands = fuzzy_generate_commands (task, rule, cmd, flag, value);
		if (commands != NULL) {
			res = register_fuzzy_controller_call (conn_ent, rule, task, commands,
					saved, err);
		}

		if (res) {
			processed = TRUE;
		}

		cur = g_list_next (cur);
	}

	if (res == -1) {
		msg_warn_task ("<%s>: cannot send fuzzy request: %s", task->message_id,
				strerror (errno));
		rspamd_controller_send_error (conn_ent, 400, "Message sending error");
		rspamd_task_free (task);
		return;
	}
	else if (!processed) {
		if (rules) {
			msg_warn_task ("<%s>: no content to generate fuzzy",
					task->message_id);
			rspamd_controller_send_error (conn_ent, 404,
				"No content to generate fuzzy for flag %d", flag);
		}
		else {
			msg_warn_task ("<%s>: no fuzzy rules found for flag %d",
					task->message_id,
				flag);
			rspamd_controller_send_error (conn_ent, 404,
				"No fuzzy rules matched for flag %d", flag);
		}
		rspamd_task_free (task);
		return;
	}

	return;
}

static int
fuzzy_controller_handler (struct rspamd_http_connection_entry *conn_ent,
	struct rspamd_http_message *msg, struct module_ctx *ctx, gint cmd)
{
	const rspamd_ftok_t *arg;
	glong value = 1, flag = 0;

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
			GList *cur;
			GHashTableIter it;
			gpointer k, v;
			struct fuzzy_mapping *map;

			for (cur = fuzzy_module_ctx->fuzzy_rules; cur != NULL && flag == 0;
					cur = g_list_next (cur)) {
				rule = cur->data;

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

	fuzzy_process_handler (conn_ent, msg, cmd, value, flag,
		(struct fuzzy_ctx *)ctx);

	return 0;
}

static gboolean
fuzzy_add_handler (struct rspamd_http_connection_entry *conn_ent,
	struct rspamd_http_message *msg, struct module_ctx *ctx)
{
	return fuzzy_controller_handler (conn_ent, msg,
			   ctx, FUZZY_WRITE);
}

static gboolean
fuzzy_delete_handler (struct rspamd_http_connection_entry *conn_ent,
	struct rspamd_http_message *msg, struct module_ctx *ctx)
{
	return fuzzy_controller_handler (conn_ent, msg,
			   ctx, FUZZY_DEL);
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

	return 0;
}
