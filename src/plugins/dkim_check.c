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
/***MODULE:dkim
 * rspamd module that checks dkim records of incoming email
 *
 * Allowed options:
 * - symbol_allow (string): symbol to insert in case of allow (default: 'R_DKIM_ALLOW')
 * - symbol_reject (string): symbol to insert (default: 'R_DKIM_REJECT')
 * - symbol_tempfail (string): symbol to insert in case of temporary fail (default: 'R_DKIM_TEMPFAIL')
 * - symbol_permfail (string): symbol to insert in case of permanent failure (default: 'R_DKIM_PERMFAIL')
 * - symbol_na (string): symbol to insert in case of no signing (default: 'R_DKIM_NA')
 * - whitelist (map): map of whitelisted networks
 * - domains (map): map of domains to check
 * - strict_multiplier (number): multiplier for strict domains
 * - time_jitter (number): jitter in seconds to allow time diff while checking
 * - trusted_only (flag): check signatures only for domains in 'domains' map
 */


#include "config.h"
#include "libmime/message.h"
#include "libserver/dkim.h"
#include "libutil/hash.h"
#include "libserver/maps/map.h"
#include "libserver/maps/map_helpers.h"
#include "rspamd.h"
#include "utlist.h"
#include "unix-std.h"
#include "lua/lua_common.h"
#include "libserver/mempool_vars_internal.h"

#define DEFAULT_SYMBOL_REJECT "R_DKIM_REJECT"
#define DEFAULT_SYMBOL_TEMPFAIL "R_DKIM_TEMPFAIL"
#define DEFAULT_SYMBOL_ALLOW "R_DKIM_ALLOW"
#define DEFAULT_SYMBOL_NA "R_DKIM_NA"
#define DEFAULT_SYMBOL_PERMFAIL "R_DKIM_PERMFAIL"
#define DEFAULT_CACHE_SIZE 2048
#define DEFAULT_TIME_JITTER 60
#define DEFAULT_MAX_SIGS 5

static const gchar *M = "rspamd dkim plugin";

static const gchar default_sign_headers[] = ""
		"(o)from:(x)sender:(o)reply-to:(o)subject:(x)date:(x)message-id:"
		"(o)to:(o)cc:(x)mime-version:(x)content-type:(x)content-transfer-encoding:"
		"resent-to:resent-cc:resent-from:resent-sender:resent-message-id:"
		"(x)in-reply-to:(x)references:list-id:list-help:list-owner:list-unsubscribe:"
		"list-unsubscribe-post:list-subscribe:list-post:(x)openpgp:(x)autocrypt";
static const gchar default_arc_sign_headers[] = ""
		"(o)from:(x)sender:(o)reply-to:(o)subject:(x)date:(x)message-id:"
		"(o)to:(o)cc:(x)mime-version:(x)content-type:(x)content-transfer-encoding:"
		"resent-to:resent-cc:resent-from:resent-sender:resent-message-id:"
		"(x)in-reply-to:(x)references:list-id:list-help:list-owner:list-unsubscribe:"
		"list-unsubscribe-post:list-subscribe:list-post:dkim-signature:(x)openpgp:"
		"(x)autocrypt";

struct dkim_ctx {
	struct module_ctx ctx;
	const gchar *symbol_reject;
	const gchar *symbol_tempfail;
	const gchar *symbol_allow;
	const gchar *symbol_na;
	const gchar *symbol_permfail;

	struct rspamd_radix_map_helper *whitelist_ip;
	struct rspamd_hash_map_helper *dkim_domains;
	guint strict_multiplier;
	guint time_jitter;
	rspamd_lru_hash_t *dkim_hash;
	rspamd_lru_hash_t *dkim_sign_hash;
	const gchar *sign_headers;
	const gchar *arc_sign_headers;
	guint max_sigs;
	gboolean trusted_only;
	gboolean check_local;
	gboolean check_authed;
};

struct dkim_check_result {
	rspamd_dkim_context_t *ctx;
	rspamd_dkim_key_t *key;
	struct rspamd_task *task;
	struct rspamd_dkim_check_result *res;
	gdouble mult_allow;
	gdouble mult_deny;
	struct rspamd_symcache_item *item;
	struct dkim_check_result *next, *prev, *first;
};

static void dkim_symbol_callback (struct rspamd_task *task,
								  struct rspamd_symcache_item *item,
								  void *unused);
static void dkim_sign_callback (struct rspamd_task *task,
								struct rspamd_symcache_item *item,
								void *unused);

static gint lua_dkim_sign_handler (lua_State *L);
static gint lua_dkim_verify_handler (lua_State *L);
static gint lua_dkim_canonicalize_handler (lua_State *L);

/* Initialization */
gint dkim_module_init (struct rspamd_config *cfg, struct module_ctx **ctx);
gint dkim_module_config (struct rspamd_config *cfg, bool validate);
gint dkim_module_reconfig (struct rspamd_config *cfg);

module_t dkim_module = {
		"dkim",
		dkim_module_init,
		dkim_module_config,
		dkim_module_reconfig,
		NULL,
		RSPAMD_MODULE_VER,
		(guint)-1,
};

static inline struct dkim_ctx *
dkim_get_context (struct rspamd_config *cfg)
{
	return (struct dkim_ctx *)g_ptr_array_index (cfg->c_modules,
			dkim_module.ctx_offset);
}

static void
dkim_module_key_dtor (gpointer k)
{
	rspamd_dkim_key_t *key = k;

	rspamd_dkim_key_unref (key);
}

static void
dkim_module_free_list (gpointer k)
{
	g_list_free_full ((GList *)k, rspamd_gstring_free_hard);
}

gint
dkim_module_init (struct rspamd_config *cfg, struct module_ctx **ctx)
{
	struct dkim_ctx *dkim_module_ctx;

	dkim_module_ctx = rspamd_mempool_alloc0 (cfg->cfg_pool,
			sizeof (*dkim_module_ctx));
	dkim_module_ctx->sign_headers = default_sign_headers;
	dkim_module_ctx->arc_sign_headers = default_arc_sign_headers;
	dkim_module_ctx->max_sigs = DEFAULT_MAX_SIGS;

	*ctx = (struct module_ctx *)dkim_module_ctx;

	rspamd_rcl_add_doc_by_path (cfg,
			NULL,
			"DKIM check plugin",
			"dkim",
			UCL_OBJECT,
			NULL,
			0,
			NULL,
			0);
	rspamd_rcl_add_doc_by_path (cfg,
			"dkim",
			"Map of IP addresses that should be excluded from DKIM checks",
			"whitelist",
			UCL_STRING,
			NULL,
			0,
			NULL,
			0);
	rspamd_rcl_add_doc_by_path (cfg,
			"dkim",
			"Symbol that is added if DKIM check is successful",
			"symbol_allow",
			UCL_STRING,
			NULL,
			0,
			DEFAULT_SYMBOL_ALLOW,
			0);
	rspamd_rcl_add_doc_by_path (cfg,
			"dkim",
			"Symbol that is added if DKIM check is unsuccessful",
			"symbol_reject",
			UCL_STRING,
			NULL,
			0,
			DEFAULT_SYMBOL_REJECT,
			0);
	rspamd_rcl_add_doc_by_path (cfg,
			"dkim",
			"Symbol that is added if DKIM check can't be completed (e.g. DNS failure)",
			"symbol_tempfail",
			UCL_STRING,
			NULL,
			0,
			DEFAULT_SYMBOL_TEMPFAIL,
			0);
	rspamd_rcl_add_doc_by_path (cfg,
			"dkim",
			"Symbol that is added if mail is not signed",
			"symbol_na",
			UCL_STRING,
			NULL,
			0,
			DEFAULT_SYMBOL_NA,
			0);
	rspamd_rcl_add_doc_by_path (cfg,
			"dkim",
			"Symbol that is added if permanent failure encountered",
			"symbol_permfail",
			UCL_STRING,
			NULL,
			0,
			DEFAULT_SYMBOL_PERMFAIL,
			0);
	rspamd_rcl_add_doc_by_path (cfg,
			"dkim",
			"Size of DKIM keys cache",
			"dkim_cache_size",
			UCL_INT,
			NULL,
			0,
			G_STRINGIFY (DEFAULT_CACHE_SIZE),
			0);
	rspamd_rcl_add_doc_by_path (cfg,
			"dkim",
			"Allow this time difference when checking DKIM signature time validity",
			"time_jitter",
			UCL_TIME,
			NULL,
			0,
			G_STRINGIFY (DEFAULT_TIME_JITTER),
			0);
	rspamd_rcl_add_doc_by_path (cfg,
			"dkim",
			"Domains to check DKIM for (check all domains if this option is empty)",
			"domains",
			UCL_STRING,
			NULL,
			0,
			"empty",
			0);
	rspamd_rcl_add_doc_by_path (cfg,
			"dkim",
			"Map of domains that are treated as 'trusted' meaning that DKIM policy failure has more significant score",
			"trusted_domains",
			UCL_STRING,
			NULL,
			0,
			"empty",
			0);
	rspamd_rcl_add_doc_by_path (cfg,
			"dkim",
			"Multiply dkim score by this factor for trusted domains",
			"strict_multiplier",
			UCL_FLOAT,
			NULL,
			0,
			NULL,
			0);
	rspamd_rcl_add_doc_by_path (cfg,
			"dkim",
			"Check DKIM policies merely for `trusted_domains`",
			"trusted_only",
			UCL_BOOLEAN,
			NULL,
			0,
			"false",
			0);
	rspamd_rcl_add_doc_by_path (cfg,
			"dkim",
			"Lua script that tells if a message should be signed and with what params (obsoleted)",
			"sign_condition",
			UCL_STRING,
			NULL,
			0,
			"empty",
			0);
	rspamd_rcl_add_doc_by_path (cfg,
			"dkim",
			"Obsoleted: maximum number of DKIM signatures to check",
			"max_sigs",
			UCL_INT,
			NULL,
			0,
			"n/a",
			0);
	rspamd_rcl_add_doc_by_path (cfg,
			"dkim",
			"Headers used in signing",
			"sign_headers",
			UCL_STRING,
			NULL,
			0,
			default_sign_headers,
			0);

	return 0;
}

gint
dkim_module_config (struct rspamd_config *cfg, bool validate)
{
	const ucl_object_t *value;
	gint res = TRUE, cb_id = -1;
	guint cache_size, sign_cache_size;
	gboolean got_trusted = FALSE;
	struct dkim_ctx *dkim_module_ctx = dkim_get_context (cfg);

	/* Register global methods */
	lua_getglobal (cfg->lua_state, "rspamd_plugins");

	if (lua_type (cfg->lua_state, -1) == LUA_TTABLE) {
		lua_pushstring (cfg->lua_state, "dkim");
		lua_createtable (cfg->lua_state, 0, 1);
		/* Set methods */
		lua_pushstring (cfg->lua_state, "sign");
		lua_pushcfunction (cfg->lua_state, lua_dkim_sign_handler);
		lua_settable (cfg->lua_state, -3);
		lua_pushstring (cfg->lua_state, "verify");
		lua_pushcfunction (cfg->lua_state, lua_dkim_verify_handler);
		lua_settable (cfg->lua_state, -3);
		lua_pushstring (cfg->lua_state, "canon_header_relaxed");
		lua_pushcfunction (cfg->lua_state, lua_dkim_canonicalize_handler);
		lua_settable (cfg->lua_state, -3);
		/* Finish dkim key */
		lua_settable (cfg->lua_state, -3);
	}

	lua_pop (cfg->lua_state, 1); /* Remove global function */
	dkim_module_ctx->whitelist_ip = NULL;

	value = rspamd_config_get_module_opt (cfg, "dkim", "check_local");

	if (value == NULL) {
		value = rspamd_config_get_module_opt (cfg, "options", "check_local");
	}

	if (value != NULL) {
		dkim_module_ctx->check_local = ucl_object_toboolean (value);
	}
	else {
		dkim_module_ctx->check_local = FALSE;
	}

	value = rspamd_config_get_module_opt (cfg, "dkim",
			"check_authed");

	if (value == NULL) {
		value = rspamd_config_get_module_opt (cfg, "options",
				"check_authed");
	}

	if (value != NULL) {
		dkim_module_ctx->check_authed = ucl_object_toboolean (value);
	}
	else {
		dkim_module_ctx->check_authed = FALSE;
	}
	if ((value =
		rspamd_config_get_module_opt (cfg, "dkim", "symbol_reject")) != NULL) {
		dkim_module_ctx->symbol_reject = ucl_object_tostring (value);
	}
	else {
		dkim_module_ctx->symbol_reject = DEFAULT_SYMBOL_REJECT;
	}
	if ((value =
		rspamd_config_get_module_opt (cfg, "dkim",
		"symbol_tempfail")) != NULL) {
		dkim_module_ctx->symbol_tempfail = ucl_object_tostring (value);
	}
	else {
		dkim_module_ctx->symbol_tempfail = DEFAULT_SYMBOL_TEMPFAIL;
	}
	if ((value =
		rspamd_config_get_module_opt (cfg, "dkim", "symbol_allow")) != NULL) {
		dkim_module_ctx->symbol_allow = ucl_object_tostring (value);
	}
	else {
		dkim_module_ctx->symbol_allow = DEFAULT_SYMBOL_ALLOW;
	}
	if ((value =
		rspamd_config_get_module_opt (cfg, "dkim", "symbol_na")) != NULL) {
		dkim_module_ctx->symbol_na = ucl_object_tostring (value);
	}
	else {
		dkim_module_ctx->symbol_na = DEFAULT_SYMBOL_NA;
	}
	if ((value =
		rspamd_config_get_module_opt (cfg, "dkim", "symbol_permfail")) != NULL) {
		dkim_module_ctx->symbol_permfail = ucl_object_tostring (value);
	}
	else {
		dkim_module_ctx->symbol_permfail = DEFAULT_SYMBOL_PERMFAIL;
	}
	if ((value =
		rspamd_config_get_module_opt (cfg, "dkim",
		"dkim_cache_size")) != NULL) {
		cache_size = ucl_object_toint (value);
	}
	else {
		cache_size = DEFAULT_CACHE_SIZE;
	}

	if ((value =
			rspamd_config_get_module_opt (cfg, "dkim",
					"sign_cache_size")) != NULL) {
		sign_cache_size = ucl_object_toint (value);
	}
	else {
		sign_cache_size = 128;
	}

	if ((value =
		rspamd_config_get_module_opt (cfg, "dkim", "time_jitter")) != NULL) {
		dkim_module_ctx->time_jitter = ucl_object_todouble (value);
	}
	else {
		dkim_module_ctx->time_jitter = DEFAULT_TIME_JITTER;
	}

	if ((value =
			rspamd_config_get_module_opt (cfg, "dkim", "max_sigs")) != NULL) {
		dkim_module_ctx->max_sigs = ucl_object_toint (value);
	}

	if ((value =
		rspamd_config_get_module_opt (cfg, "dkim", "whitelist")) != NULL) {

		rspamd_config_radix_from_ucl (cfg, value, "DKIM whitelist",
				&dkim_module_ctx->whitelist_ip, NULL, NULL, "dkim whitelist");
	}

	if ((value =
		rspamd_config_get_module_opt (cfg, "dkim", "domains")) != NULL) {
		if (!rspamd_map_add_from_ucl (cfg, value,
				"DKIM domains",
				rspamd_kv_list_read,
				rspamd_kv_list_fin,
				rspamd_kv_list_dtor,
				(void **)&dkim_module_ctx->dkim_domains,
				NULL, RSPAMD_MAP_DEFAULT)) {
			msg_warn_config ("cannot load dkim domains list from %s",
				ucl_object_tostring (value));
		}
		else {
			got_trusted = TRUE;
		}
	}

	if (!got_trusted && (value =
			rspamd_config_get_module_opt (cfg, "dkim", "trusted_domains")) != NULL) {
		if (!rspamd_map_add_from_ucl (cfg, value,
				"DKIM domains",
				rspamd_kv_list_read,
				rspamd_kv_list_fin,
				rspamd_kv_list_dtor,
				(void **)&dkim_module_ctx->dkim_domains,
				NULL, RSPAMD_MAP_DEFAULT)) {
			msg_warn_config ("cannot load dkim domains list from %s",
					ucl_object_tostring (value));

			if (validate) {
				return FALSE;
			}
		}
		else {
			got_trusted = TRUE;
		}
	}

	if ((value =
		rspamd_config_get_module_opt (cfg, "dkim",
		"strict_multiplier")) != NULL) {
		dkim_module_ctx->strict_multiplier = ucl_object_toint (value);
	}
	else {
		dkim_module_ctx->strict_multiplier = 1;
	}

	if ((value =
		rspamd_config_get_module_opt (cfg, "dkim", "trusted_only")) != NULL) {
		dkim_module_ctx->trusted_only = ucl_object_toboolean (value);
	}
	else {
		dkim_module_ctx->trusted_only = FALSE;
	}

	if ((value =
			rspamd_config_get_module_opt (cfg, "dkim", "sign_headers")) != NULL) {
		dkim_module_ctx->sign_headers = ucl_object_tostring (value);
	}

	if ((value =
				 rspamd_config_get_module_opt (cfg, "arc", "sign_headers")) != NULL) {
		dkim_module_ctx->arc_sign_headers = ucl_object_tostring (value);
	}

	if (cache_size > 0) {
		dkim_module_ctx->dkim_hash = rspamd_lru_hash_new (
				cache_size,
				g_free,
				dkim_module_key_dtor);
		rspamd_mempool_add_destructor (cfg->cfg_pool,
				(rspamd_mempool_destruct_t)rspamd_lru_hash_destroy,
				dkim_module_ctx->dkim_hash);
	}

	if (sign_cache_size > 0) {
		dkim_module_ctx->dkim_sign_hash = rspamd_lru_hash_new (
				sign_cache_size,
				g_free,
				(GDestroyNotify) rspamd_dkim_sign_key_unref);
		rspamd_mempool_add_destructor (cfg->cfg_pool,
				(rspamd_mempool_destruct_t)rspamd_lru_hash_destroy,
				dkim_module_ctx->dkim_sign_hash);
	}

	if (dkim_module_ctx->trusted_only && !got_trusted) {
		msg_err_config ("trusted_only option is set and no trusted domains are defined");
		if (validate) {
			return FALSE;
		}
	}
	else {
		if (!rspamd_config_is_module_enabled (cfg, "dkim")) {
			return TRUE;
		}

		cb_id = rspamd_symcache_add_symbol (cfg->cache,
				"DKIM_CHECK",
				0,
				dkim_symbol_callback,
				NULL,
				SYMBOL_TYPE_CALLBACK,
				-1);
		rspamd_config_add_symbol (cfg,
				"DKIM_CHECK",
				0.0,
				"DKIM check callback",
				"policies",
				RSPAMD_SYMBOL_FLAG_IGNORE_METRIC,
				1,
				1);
		rspamd_config_add_symbol_group (cfg, "DKIM_CHECK", "dkim");
		rspamd_symcache_add_symbol (cfg->cache,
				dkim_module_ctx->symbol_reject,
				0,
				NULL,
				NULL,
				SYMBOL_TYPE_VIRTUAL | SYMBOL_TYPE_FINE,
				cb_id);
		rspamd_symcache_add_symbol (cfg->cache,
				dkim_module_ctx->symbol_na,
				0,
				NULL, NULL,
				SYMBOL_TYPE_VIRTUAL | SYMBOL_TYPE_FINE,
				cb_id);
		rspamd_symcache_add_symbol (cfg->cache,
				dkim_module_ctx->symbol_permfail,
				0,
				NULL, NULL,
				SYMBOL_TYPE_VIRTUAL | SYMBOL_TYPE_FINE,
				cb_id);
		rspamd_symcache_add_symbol (cfg->cache,
				dkim_module_ctx->symbol_tempfail,
				0,
				NULL, NULL,
				SYMBOL_TYPE_VIRTUAL | SYMBOL_TYPE_FINE,
				cb_id);
		rspamd_symcache_add_symbol (cfg->cache,
				dkim_module_ctx->symbol_allow,
				0,
				NULL, NULL,
				SYMBOL_TYPE_VIRTUAL | SYMBOL_TYPE_FINE,
				cb_id);

		rspamd_symcache_add_symbol (cfg->cache,
				"DKIM_TRACE",
				0,
				NULL, NULL,
				SYMBOL_TYPE_VIRTUAL | SYMBOL_TYPE_NOSTAT,
				cb_id);
		rspamd_config_add_symbol (cfg,
				"DKIM_TRACE",
				0.0,
				"DKIM trace symbol",
				"policies",
				RSPAMD_SYMBOL_FLAG_IGNORE_METRIC,
				1,
				1);
		rspamd_config_add_symbol_group (cfg, "DKIM_TRACE", "dkim");

		msg_info_config ("init internal dkim module");
#ifndef HAVE_OPENSSL
		msg_warn_config (
			"openssl is not found so dkim rsa check is disabled, only check body hash, it is NOT safe to trust these results");
#endif
	}

	return res;
}


/**
 * Grab a private key from the cache
 * or from the key content provided
 */
rspamd_dkim_sign_key_t *
dkim_module_load_key_format (struct rspamd_task *task,
							 struct dkim_ctx *dkim_module_ctx,
							 const gchar *key, gsize keylen,
							 enum rspamd_dkim_key_format key_format)

{
	guchar h[rspamd_cryptobox_HASHBYTES],
			hex_hash[rspamd_cryptobox_HASHBYTES * 2 + 1];
	rspamd_dkim_sign_key_t *ret = NULL;
	GError *err = NULL;
	struct stat st;

	memset (hex_hash, 0, sizeof (hex_hash));
	rspamd_cryptobox_hash (h, key, keylen, NULL, 0);
	rspamd_encode_hex_buf (h, sizeof (h), hex_hash, sizeof (hex_hash));

	if (dkim_module_ctx->dkim_sign_hash) {
		ret = rspamd_lru_hash_lookup (dkim_module_ctx->dkim_sign_hash,
				hex_hash, time (NULL));
	}

	/*
	 * This fails for paths that are also valid base64.
	 * Maybe the caller should have specified a format.
	 */
	if (key_format == RSPAMD_DKIM_KEY_UNKNOWN) {
		if (key[0] == '.' || key[0] == '/') {
			if (!rspamd_cryptobox_base64_is_valid (key, keylen)) {
				key_format = RSPAMD_DKIM_KEY_FILE;
			}
		}
		else if (rspamd_cryptobox_base64_is_valid (key, keylen)) {
			key_format = RSPAMD_DKIM_KEY_BASE64;
		}
	}


	if (ret != NULL && key_format == RSPAMD_DKIM_KEY_FILE) {
		msg_debug_task("checking for stale file key");

		if (stat (key, &st) != 0) {
			msg_err_task("cannot stat key file: %s", strerror (errno));
			return NULL;
		}

		if (rspamd_dkim_sign_key_maybe_invalidate (ret, st.st_mtime)) {
			msg_debug_task("removing stale file key");
			/*
			 * Invalidate DKIM key
			 * removal from lru cache also cleanup the key and value
			 */
			if (dkim_module_ctx->dkim_sign_hash) {
				rspamd_lru_hash_remove (dkim_module_ctx->dkim_sign_hash,
						hex_hash);
			}
			ret = NULL;
		}
	}

	/* found key; done */
	if (ret != NULL) {
		return ret;
	}

	ret = rspamd_dkim_sign_key_load (key, keylen, key_format, &err);

	if (ret == NULL) {
		msg_err_task ("cannot load dkim key %s: %e",
				key, err);
		g_error_free (err);
	}
	else if (dkim_module_ctx->dkim_sign_hash) {
		rspamd_lru_hash_insert (dkim_module_ctx->dkim_sign_hash,
				g_strdup (hex_hash), ret, time (NULL), 0);
	}

	return ret;
}

static gint
lua_dkim_sign_handler (lua_State *L)
{
	struct rspamd_task *task = lua_check_task (L, 1);
	gint64 arc_idx = 0, expire = 0;
	enum rspamd_dkim_type sign_type = RSPAMD_DKIM_NORMAL;
	GError *err = NULL;
	GString *hdr;
	GList *sigs = NULL;
	const gchar *selector = NULL, *domain = NULL, *key = NULL, *rawkey = NULL,
			*headers = NULL, *sign_type_str = NULL, *arc_cv = NULL,
			*pubkey = NULL;
	rspamd_dkim_sign_context_t *ctx;
	rspamd_dkim_sign_key_t *dkim_key;
	gsize rawlen = 0, keylen = 0;
	gboolean no_cache = FALSE, strict_pubkey_check = FALSE;
	struct dkim_ctx *dkim_module_ctx;

	luaL_argcheck (L, lua_type (L, 2) == LUA_TTABLE, 2, "'table' expected");
	/*
	 * Get the following elements:
	 * - selector
	 * - domain
	 * - key
	 */
	if (!rspamd_lua_parse_table_arguments (L, 2, &err,
			RSPAMD_LUA_PARSE_ARGUMENTS_DEFAULT,
			"key=V;rawkey=V;*domain=S;*selector=S;no_cache=B;headers=S;"
			"sign_type=S;arc_idx=I;arc_cv=S;expire=I;pubkey=S;"
			"strict_pubkey_check=B",
			&keylen, &key, &rawlen, &rawkey, &domain,
			&selector, &no_cache, &headers,
			&sign_type_str, &arc_idx, &arc_cv, &expire, &pubkey,
			&strict_pubkey_check)) {
		msg_err_task ("cannot parse table arguments: %e",
				err);
		g_error_free (err);

		lua_pushboolean (L, FALSE);
		return 1;
	}

	dkim_module_ctx = dkim_get_context (task->cfg);

	if (key) {
		dkim_key = dkim_module_load_key_format (task, dkim_module_ctx, key,
				keylen, RSPAMD_DKIM_KEY_UNKNOWN);
	}
	else if (rawkey) {
		dkim_key = dkim_module_load_key_format (task, dkim_module_ctx, rawkey,
				rawlen, RSPAMD_DKIM_KEY_UNKNOWN);
	}
	else {
		msg_err_task ("neither key nor rawkey are specified");
		lua_pushboolean (L, FALSE);

		return 1;
	}

	if (dkim_key == NULL) {
		lua_pushboolean (L, FALSE);
		return 1;
	}

	if (sign_type_str) {
		if (strcmp (sign_type_str, "dkim") == 0) {
			sign_type = RSPAMD_DKIM_NORMAL;

			if (headers == NULL) {
				headers = dkim_module_ctx->sign_headers;
			}
		}
		else if (strcmp (sign_type_str, "arc-sign") == 0) {
			sign_type = RSPAMD_DKIM_ARC_SIG;

			if (headers == NULL) {
				headers = dkim_module_ctx->arc_sign_headers;
			}

			if (arc_idx == 0) {
				lua_settop (L, 0);
				return luaL_error (L, "no arc idx specified");
			}
		}
		else if (strcmp (sign_type_str, "arc-seal") == 0) {
			sign_type = RSPAMD_DKIM_ARC_SEAL;
			if (arc_cv == NULL) {
				lua_settop (L, 0);
				return luaL_error (L, "no arc cv specified");
			}
			if (arc_idx == 0) {
				lua_settop (L, 0);
				return luaL_error (L, "no arc idx specified");
			}
		}
		else {
			lua_settop (L, 0);
			return luaL_error (L, "unknown sign type: %s",
					sign_type_str);
		}
	}
	else {
		/* Unspecified sign type, assume plain dkim */
		if (headers == NULL) {
			headers = dkim_module_ctx->sign_headers;
		}
	}

	if (pubkey != NULL) {
		/* Also check if private and public keys match */
		rspamd_dkim_key_t *pk;
		keylen = strlen (pubkey);

		pk = rspamd_dkim_parse_key (pubkey, &keylen, NULL);

		if (pk == NULL) {
			if (strict_pubkey_check) {
				msg_err_task ("cannot parse pubkey from string: %s, skip signing",
						pubkey);
				lua_pushboolean (L, FALSE);

				return 1;
			}
			else {
				msg_warn_task ("cannot parse pubkey from string: %s",
						pubkey);
			}
		}
		else {
			GError *te = NULL;

			/* We have parsed the key, so try to check keys */
			if (!rspamd_dkim_match_keys (pk, dkim_key, &te)) {
				if (strict_pubkey_check) {
					msg_err_task ("public key for %s/%s does not match private "
								  "key: %e, skip signing",
							domain, selector, te);
					g_error_free (te);
					lua_pushboolean (L, FALSE);
					rspamd_dkim_key_unref (pk);

					return 1;
				}
				else {
					msg_warn_task ("public key for %s/%s does not match private "
								   "key: %e",
							domain, selector, te);
					g_error_free (te);
				}
			}

			rspamd_dkim_key_unref (pk);
		}
	}

	ctx = rspamd_create_dkim_sign_context (task, dkim_key,
			DKIM_CANON_RELAXED, DKIM_CANON_RELAXED,
			headers, sign_type, &err);

	if (ctx == NULL) {
		msg_err_task ("cannot create sign context: %e",
				err);
		g_error_free (err);

		lua_pushboolean (L, FALSE);
		return 1;
	}

	hdr = rspamd_dkim_sign (task, selector, domain, 0,
			expire, arc_idx, arc_cv, ctx);

	if (hdr) {

		if (!no_cache) {
			sigs = rspamd_mempool_get_variable (task->task_pool, "dkim-signature");

			if (sigs == NULL) {
				sigs = g_list_append (sigs, hdr);
				rspamd_mempool_set_variable (task->task_pool, "dkim-signature",
						sigs, dkim_module_free_list);
			} else {
				sigs = g_list_append (sigs, hdr);
				(void)sigs;
			}
		}

		lua_pushboolean (L, TRUE);
		lua_pushlstring (L, hdr->str, hdr->len);

		if (no_cache) {
			g_string_free (hdr, TRUE);
		}

		return 2;
	}


	lua_pushboolean (L, FALSE);
	lua_pushnil (L);

	return 2;
}

gint
dkim_module_reconfig (struct rspamd_config *cfg)
{
	return dkim_module_config (cfg, false);
}

/*
 * Parse strict value for domain in format: 'reject_multiplier:deny_multiplier'
 */
static gboolean
dkim_module_parse_strict (const gchar *value, gdouble *allow, gdouble *deny)
{
	const gchar *colon;
	gchar *err = NULL;
	gdouble val;
	gchar numbuf[64];

	colon = strchr (value, ':');
	if (colon) {
		rspamd_strlcpy (numbuf, value,
				MIN (sizeof (numbuf), (colon - value) + 1));
		val = strtod (numbuf, &err);

		if (err == NULL || *err == '\0') {
			*deny = val;
			colon++;
			rspamd_strlcpy (numbuf, colon, sizeof (numbuf));
			err = NULL;
			val = strtod (numbuf, &err);

			if (err == NULL || *err == '\0') {
				*allow = val;
				return TRUE;
			}
		}
	}
	return FALSE;
}

static void
dkim_module_check (struct dkim_check_result *res)
{
	gboolean all_done = TRUE;
	const gchar *strict_value;
	struct dkim_check_result *first, *cur = NULL;
	struct dkim_ctx *dkim_module_ctx = dkim_get_context (res->task->cfg);
	struct rspamd_task *task = res->task;

	first = res->first;

	DL_FOREACH (first, cur) {
		if (cur->ctx == NULL) {
			continue;
		}

		if (cur->key != NULL && cur->res == NULL) {
			cur->res = rspamd_dkim_check (cur->ctx, cur->key, task);

			if (dkim_module_ctx->dkim_domains != NULL) {
				/* Perform strict check */
				const gchar *domain = rspamd_dkim_get_domain (cur->ctx);

				if ((strict_value =
						rspamd_match_hash_map (dkim_module_ctx->dkim_domains,
								domain,
								strlen (domain))) != NULL) {
					if (!dkim_module_parse_strict (strict_value, &cur->mult_allow,
							&cur->mult_deny)) {
						cur->mult_allow = dkim_module_ctx->strict_multiplier;
						cur->mult_deny = dkim_module_ctx->strict_multiplier;
					}
				}
			}
		}
	}

	DL_FOREACH (first, cur) {
		if (cur->ctx == NULL) {
			continue;
		}
		if (cur->res == NULL) {
			/* Still need a key */
			all_done = FALSE;
		}
	}

	if (all_done) {
		/* Create zero terminated array of results */
		struct rspamd_dkim_check_result **pres;
		guint nres = 0, i = 0;

		DL_FOREACH (first, cur) {
			if (cur->ctx == NULL || cur->res == NULL) {
				continue;
			}

			nres ++;
		}

		pres = rspamd_mempool_alloc (task->task_pool, sizeof (*pres) * (nres + 1));
		pres[nres] = NULL;

		DL_FOREACH (first, cur) {
			const gchar *symbol = NULL, *trace = NULL;
			gdouble symbol_weight = 1.0;

			if (cur->ctx == NULL || cur->res == NULL) {
				continue;
			}

			pres[i++] = cur->res;

			if (cur->res->rcode == DKIM_REJECT) {
				symbol = dkim_module_ctx->symbol_reject;
				trace = "-";
				symbol_weight = cur->mult_deny * 1.0;
			}
			else if (cur->res->rcode == DKIM_CONTINUE) {
				symbol = dkim_module_ctx->symbol_allow;
				trace = "+";
				symbol_weight = cur->mult_allow * 1.0;
			}
			else if (cur->res->rcode == DKIM_PERM_ERROR) {
				trace = "~";
				symbol = dkim_module_ctx->symbol_permfail;
			}
			else if (cur->res->rcode == DKIM_TRYAGAIN) {
				trace = "?";
				symbol = dkim_module_ctx->symbol_tempfail;
			}

			if (symbol != NULL) {
				const gchar *domain = rspamd_dkim_get_domain (cur->ctx);
				const gchar *selector = rspamd_dkim_get_selector (cur->ctx);
				gsize tracelen;
				gchar *tracebuf;

				tracelen = strlen (domain) + strlen (selector) + 4;
				tracebuf = rspamd_mempool_alloc (task->task_pool,
						tracelen);
				rspamd_snprintf (tracebuf, tracelen, "%s:%s", domain, trace);

				rspamd_task_insert_result (cur->task,
						"DKIM_TRACE",
						0.0,
						tracebuf);

				rspamd_snprintf (tracebuf, tracelen, "%s:s=%s", domain, selector);
				rspamd_task_insert_result (task,
						symbol,
						symbol_weight,
						tracebuf);
			}

		}

		rspamd_mempool_set_variable (task->task_pool,
				RSPAMD_MEMPOOL_DKIM_CHECK_RESULTS,
				pres, NULL);
	}
}

static void
dkim_module_key_handler (rspamd_dkim_key_t *key,
	gsize keylen,
	rspamd_dkim_context_t *ctx,
	gpointer ud,
	GError *err)
{
	struct dkim_check_result *res = ud;
	struct rspamd_task *task;
	struct dkim_ctx *dkim_module_ctx;

	task = res->task;
	dkim_module_ctx = dkim_get_context (task->cfg);

	if (key != NULL) {
		/* Another ref belongs to the check context */
		res->key = rspamd_dkim_key_ref (key);
		/*
		 * We actually receive key with refcount = 1, so we just assume that
		 * lru hash owns this object now
		 */
		/* Release key when task is processed */
		rspamd_mempool_add_destructor (res->task->task_pool,
				dkim_module_key_dtor, res->key);

		if (dkim_module_ctx->dkim_hash) {
			rspamd_lru_hash_insert (dkim_module_ctx->dkim_hash,
					g_strdup (rspamd_dkim_get_dns_key (ctx)),
					key, res->task->task_timestamp, rspamd_dkim_key_get_ttl (key));

			msg_info_task ("stored DKIM key for %s in LRU cache for %d seconds, "
						   "%d/%d elements in the cache",
					rspamd_dkim_get_dns_key (ctx),
					rspamd_dkim_key_get_ttl (key),
					rspamd_lru_hash_size (dkim_module_ctx->dkim_hash),
					rspamd_lru_hash_capacity (dkim_module_ctx->dkim_hash));
		}
	}
	else {
		/* Insert tempfail symbol */
		msg_info_task ("cannot get key for domain %s: %e",
				rspamd_dkim_get_dns_key (ctx), err);

		if (err != NULL) {
			if (err->code == DKIM_SIGERROR_NOKEY) {
				res->res = rspamd_dkim_create_result (ctx, DKIM_TRYAGAIN, task);
				res->res->fail_reason = "DNS error when getting key";
			}
			else {
				res->res = rspamd_dkim_create_result (ctx, DKIM_PERM_ERROR, task);
				res->res->fail_reason = "invalid DKIM record";
			}
		}
	}

	if (err) {
		g_error_free (err);
	}

	dkim_module_check (res);
}

static void
dkim_symbol_callback (struct rspamd_task *task,
		struct rspamd_symcache_item *item,
		void *unused)
{
	rspamd_dkim_context_t *ctx;
	rspamd_dkim_key_t *key;
	GError *err = NULL;
	struct rspamd_mime_header *rh, *rh_cur;
	struct dkim_check_result *res = NULL, *cur;
	guint checked = 0;
	gdouble *dmarc_checks;
	struct dkim_ctx *dkim_module_ctx = dkim_get_context (task->cfg);

	/* Allow dmarc */
	dmarc_checks = rspamd_mempool_get_variable (task->task_pool,
			RSPAMD_MEMPOOL_DMARC_CHECKS);

	if (dmarc_checks) {
		(*dmarc_checks) ++;
	}
	else {
		dmarc_checks = rspamd_mempool_alloc (task->task_pool,
				sizeof (*dmarc_checks));
		*dmarc_checks = 1;
		rspamd_mempool_set_variable (task->task_pool,
				RSPAMD_MEMPOOL_DMARC_CHECKS,
				dmarc_checks, NULL);
	}

	/* First check if plugin should be enabled */
	if ((!dkim_module_ctx->check_authed && task->user != NULL)
			|| (!dkim_module_ctx->check_local &&
			rspamd_ip_is_local_cfg (task->cfg, task->from_addr))) {
		msg_info_task ("skip DKIM checks for local networks and authorized users");
		rspamd_symcache_finalize_item (task, item);

		return;
	}
	/* Check whitelist */
	if (rspamd_match_radix_map_addr (dkim_module_ctx->whitelist_ip,
			task->from_addr) != NULL) {
		msg_info_task ("skip DKIM checks for whitelisted address");
		rspamd_symcache_finalize_item (task, item);

		return;
	}

	rspamd_symcache_item_async_inc (task, item, M);

	/* Now check if a message has its signature */
	rh = rspamd_message_get_header_array(task, RSPAMD_DKIM_SIGNHEADER, FALSE);
	if (rh) {
		msg_debug_task ("dkim signature found");

		DL_FOREACH (rh, rh_cur) {
			if (rh_cur->decoded == NULL || rh_cur->decoded[0] == '\0') {
				msg_info_task ("cannot load empty DKIM signature");
				continue;
			}

			cur = rspamd_mempool_alloc0 (task->task_pool, sizeof (*cur));
			cur->first = res;
			cur->res = NULL;
			cur->task = task;
			cur->mult_allow = 1.0;
			cur->mult_deny = 1.0;
			cur->item = item;

			ctx = rspamd_create_dkim_context (rh_cur->decoded,
					task->task_pool,
					task->resolver,
					dkim_module_ctx->time_jitter,
					RSPAMD_DKIM_NORMAL,
					&err);

			if (res == NULL) {
				res = cur;
				res->first = res;
				res->prev = res;
			}
			else {
				DL_APPEND (res, cur);
			}

			if (ctx == NULL) {
				if (err != NULL) {
					msg_info_task ("cannot parse DKIM signature: %e",
							err);
					g_error_free (err);
					err = NULL;
				}
				else {
					msg_info_task ("cannot parse DKIM signature: "
							"unknown error");
				}

				continue;
			}
			else {
				/* Get key */
				cur->ctx = ctx;
				const gchar *domain = rspamd_dkim_get_domain (cur->ctx);

				if (dkim_module_ctx->trusted_only &&
						(dkim_module_ctx->dkim_domains == NULL ||
								rspamd_match_hash_map (dkim_module_ctx->dkim_domains,
										domain, strlen (domain)) == NULL)) {
					msg_debug_task ("skip dkim check for %s domain",
							rspamd_dkim_get_domain (ctx));

					continue;
				}

				if (dkim_module_ctx->dkim_hash) {
					key = rspamd_lru_hash_lookup (dkim_module_ctx->dkim_hash,
							rspamd_dkim_get_dns_key (ctx),
							task->task_timestamp);
				}
				else {
					key = NULL;
				}

				if (key != NULL) {
					cur->key = rspamd_dkim_key_ref (key);
					/* Release key when task is processed */
					rspamd_mempool_add_destructor (task->task_pool,
							dkim_module_key_dtor, cur->key);
				}
				else {
					if (!rspamd_get_dkim_key (ctx,
							task,
							dkim_module_key_handler,
							cur)) {
						continue;
					}
				}
			}

			checked ++;

			if (checked > dkim_module_ctx->max_sigs) {
				msg_info_task ("message has multiple signatures but we"
						" stopped after %d checked signatures as limit"
						" is reached", checked);
				break;
			}
		}
	}
	else {
		rspamd_task_insert_result (task,
				dkim_module_ctx->symbol_na,
				1.0,
				NULL);
	}

	if (res != NULL) {
		dkim_module_check (res);
	}

	rspamd_symcache_item_async_dec_check (task, item, M);
}

struct rspamd_dkim_lua_verify_cbdata {
	rspamd_dkim_context_t *ctx;
	struct rspamd_task *task;
	lua_State *L;
	rspamd_dkim_key_t *key;
	gint cbref;
};

static void
dkim_module_lua_push_verify_result (struct rspamd_dkim_lua_verify_cbdata *cbd,
		struct rspamd_dkim_check_result *res, GError *err)
{
	struct rspamd_task **ptask, *task;
	const gchar *error_str = "unknown error";
	gboolean success = FALSE;

	task = cbd->task;

	switch (res->rcode) {
	case DKIM_CONTINUE:
		error_str = NULL;
		success = TRUE;
		break;
	case DKIM_REJECT:
		if (err) {
			error_str = err->message;
		}
		else {
			error_str = "reject";
		}
		break;
	case DKIM_TRYAGAIN:
		if (err) {
			error_str = err->message;
		}
		else {
			error_str = "tempfail";
		}
		break;
	case DKIM_NOTFOUND:
		if (err) {
			error_str = err->message;
		}
		else {
			error_str = "not found";
		}
		break;
	case DKIM_RECORD_ERROR:
		if (err) {
			error_str = err->message;
		}
		else {
			error_str = "bad record";
		}
		break;
	case DKIM_PERM_ERROR:
		if (err) {
			error_str = err->message;
		}
		else {
			error_str = "permanent error";
		}
		break;
	default:
		break;
	}

	lua_rawgeti (cbd->L, LUA_REGISTRYINDEX, cbd->cbref);
	ptask = lua_newuserdata (cbd->L, sizeof (*ptask));
	*ptask = task;
	lua_pushboolean (cbd->L, success);

	if (error_str) {
		lua_pushstring (cbd->L, error_str);
	}
	else {
		lua_pushnil (cbd->L);
	}

	if (cbd->ctx) {
		if (res->domain) {
			lua_pushstring (cbd->L, res->domain);
		}
		else {
			lua_pushnil (cbd->L);
		}

		if (res->selector) {
			lua_pushstring (cbd->L, res->selector);
		}
		else {
			lua_pushnil (cbd->L);
		}

		if (res->short_b) {
			lua_pushstring (cbd->L, res->short_b);
		}
		else {
			lua_pushnil (cbd->L);
		}

		if (res->fail_reason) {
			lua_pushstring (cbd->L, res->fail_reason);
		}
		else {
			lua_pushnil (cbd->L);
		}
	}
	else {
		lua_pushnil (cbd->L);
		lua_pushnil (cbd->L);
		lua_pushnil (cbd->L);
		lua_pushnil (cbd->L);
	}

	if (lua_pcall (cbd->L, 7, 0, 0) != 0) {
		msg_err_task ("call to verify callback failed: %s",
				lua_tostring (cbd->L, -1));
		lua_pop (cbd->L, 1);
	}

	luaL_unref (cbd->L, LUA_REGISTRYINDEX, cbd->cbref);
}

static void
dkim_module_lua_on_key (rspamd_dkim_key_t *key,
						gsize keylen,
						rspamd_dkim_context_t *ctx,
						gpointer ud,
						GError *err)
{
	struct rspamd_dkim_lua_verify_cbdata *cbd = ud;
	struct rspamd_task *task;
	struct rspamd_dkim_check_result *res;
	struct dkim_ctx *dkim_module_ctx;

	task = cbd->task;
	dkim_module_ctx = dkim_get_context (task->cfg);

	if (key != NULL) {
		/* Another ref belongs to the check context */
		cbd->key = rspamd_dkim_key_ref (key);
		/*
		 * We actually receive key with refcount = 1, so we just assume that
		 * lru hash owns this object now
		 */

		if (dkim_module_ctx->dkim_hash) {
			rspamd_lru_hash_insert (dkim_module_ctx->dkim_hash,
					g_strdup (rspamd_dkim_get_dns_key (ctx)),
					key, cbd->task->task_timestamp, rspamd_dkim_key_get_ttl (key));
		}
		/* Release key when task is processed */
		rspamd_mempool_add_destructor (cbd->task->task_pool,
				dkim_module_key_dtor, cbd->key);
	}
	else {
		/* Insert tempfail symbol */
		msg_info_task ("cannot get key for domain %s: %e",
				rspamd_dkim_get_dns_key (ctx), err);

		if (err != NULL) {
			if (err->code == DKIM_SIGERROR_NOKEY) {
				res = rspamd_dkim_create_result (ctx, DKIM_TRYAGAIN, task);
				res->fail_reason = "DNS error when getting key";

			}
			else {
				res = rspamd_dkim_create_result (ctx, DKIM_PERM_ERROR, task);
				res->fail_reason = "invalid DKIM record";
			}
		}
		else {
			res = rspamd_dkim_create_result (ctx, DKIM_TRYAGAIN, task);
			res->fail_reason = "DNS error when getting key";
		}

		dkim_module_lua_push_verify_result (cbd, res, err);

		if (err) {
			g_error_free (err);
		}

		return;
	}

	res = rspamd_dkim_check (cbd->ctx, cbd->key, cbd->task);
	dkim_module_lua_push_verify_result (cbd, res, NULL);
}

static gint
lua_dkim_verify_handler (lua_State *L)
{
	struct rspamd_task *task = lua_check_task (L, 1);
	const gchar *sig = luaL_checkstring (L, 2);
	rspamd_dkim_context_t *ctx;
	struct rspamd_dkim_lua_verify_cbdata *cbd;
	rspamd_dkim_key_t *key;
	struct rspamd_dkim_check_result *ret;
	GError *err = NULL;
	const gchar *type_str = NULL;
	enum rspamd_dkim_type type = RSPAMD_DKIM_NORMAL;
	struct dkim_ctx *dkim_module_ctx;

	if (task && sig && lua_isfunction (L, 3)) {
		if (lua_isstring (L, 4)) {
			type_str = lua_tostring (L, 4);

			if (type_str) {
				if (strcmp (type_str, "dkim") == 0) {
					type = RSPAMD_DKIM_NORMAL;
				}
				else if (strcmp (type_str, "arc-sign") == 0) {
					type = RSPAMD_DKIM_ARC_SIG;
				}
				else if (strcmp (type_str, "arc-seal") == 0) {
					type = RSPAMD_DKIM_ARC_SEAL;
				}
				else {
					lua_settop (L, 0);
					return luaL_error (L, "unknown sign type: %s",
							type_str);
				}
			}
		}

		dkim_module_ctx = dkim_get_context (task->cfg);

		ctx = rspamd_create_dkim_context (sig,
				task->task_pool,
				task->resolver,
				dkim_module_ctx->time_jitter,
				type,
				&err);

		if (ctx == NULL) {
			lua_pushboolean (L, false);

			if (err) {
				lua_pushstring (L, err->message);
				g_error_free (err);
			}
			else {
				lua_pushstring (L, "unknown error");
			}

			return 2;
		}

		cbd = rspamd_mempool_alloc (task->task_pool, sizeof (*cbd));
		cbd->L = L;
		cbd->task = task;
		lua_pushvalue (L, 3);
		cbd->cbref = luaL_ref (L, LUA_REGISTRYINDEX);
		cbd->ctx = ctx;
		cbd->key = NULL;

		if (dkim_module_ctx->dkim_hash) {
			key = rspamd_lru_hash_lookup (dkim_module_ctx->dkim_hash,
					rspamd_dkim_get_dns_key (ctx),
					task->task_timestamp);
		}
		else {
			key = NULL;
		}

		if (key != NULL) {
			cbd->key = rspamd_dkim_key_ref (key);
			/* Release key when task is processed */
			rspamd_mempool_add_destructor (task->task_pool,
					dkim_module_key_dtor, cbd->key);
			ret = rspamd_dkim_check (cbd->ctx, cbd->key, cbd->task);
			dkim_module_lua_push_verify_result (cbd, ret, NULL);
		}
		else {
			rspamd_get_dkim_key (ctx,
					task,
					dkim_module_lua_on_key,
					cbd);
		}
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	lua_pushboolean (L, TRUE);
	lua_pushnil (L);

	return 2;
}

static gint
lua_dkim_canonicalize_handler (lua_State *L)
{
	gsize nlen, vlen;
	const gchar *hname = luaL_checklstring (L, 1, &nlen),
		*hvalue = luaL_checklstring (L, 2, &vlen);
	static gchar st_buf[8192];
	gchar *buf;
	guint inlen;
	gboolean allocated = FALSE;
	goffset r;

	if (hname && hvalue && nlen > 0) {
		inlen = nlen + vlen + sizeof (":" CRLF);

		if (inlen > sizeof (st_buf)) {
			buf = g_malloc (inlen);
			allocated = TRUE;
		}
		else {
			/* Faster */
			buf = st_buf;
		}

		r = rspamd_dkim_canonize_header_relaxed_str (hname, hvalue, buf, inlen);

		if (r == -1) {
			lua_pushnil (L);
		}
		else {
			lua_pushlstring (L, buf, r);
		}

		if (allocated) {
			g_free (buf);
		}
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}
