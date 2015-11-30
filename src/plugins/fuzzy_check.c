/*
 * Copyright (c) 2009-2012, Vsevolod Stakhov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY AUTHOR ''AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
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
#include "keypair_private.h"
#include "unix-std.h"
#include <math.h>

#define DEFAULT_SYMBOL "R_FUZZY_HASH"
#define DEFAULT_UPSTREAM_ERROR_TIME 10
#define DEFAULT_UPSTREAM_DEAD_TIME 300
#define DEFAULT_UPSTREAM_MAXERRORS 10

#define DEFAULT_IO_TIMEOUT 500
#define DEFAULT_RETRANSMITS 3
#define DEFAULT_PORT 11335

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
	GHashTable *mappings;
	GList *mime_types;
	GList *fuzzy_headers;
	GString *hash_key;
	GString *shingles_key;
	gpointer local_key;
	gpointer peer_key;
	double max_score;
	gboolean read_only;
	gboolean skip_unknown;
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
};

struct fuzzy_client_session {
	GPtrArray *commands;
	struct rspamd_task *task;
	struct upstream *server;
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
	fuzzy_attach_controller
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
		elt = ucl_object_find_key (val, "symbol");
		if (elt == NULL || !ucl_object_tostring_safe (elt, &sym)) {
			sym = ucl_object_key (val);
		}
		if (sym != NULL) {
			map =
				rspamd_mempool_alloc (fuzzy_module_ctx->fuzzy_pool,
					sizeof (struct fuzzy_mapping));
			map->symbol = sym;
			elt = ucl_object_find_key (val, "flag");
			if (elt != NULL && ucl_obj_toint_safe (elt, &map->fuzzy_flag)) {
				elt = ucl_object_find_key (val, "max_score");
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
		rspamd_http_connection_key_unref (rule->local_key);
	}
	if (rule->peer_key) {
		rspamd_http_connection_key_unref (rule->peer_key);
	}
}

static gint
fuzzy_parse_rule (struct rspamd_config *cfg, const ucl_object_t *obj, gint cb_id)
{
	const ucl_object_t *value, *cur;
	struct fuzzy_rule *rule;
	ucl_object_iter_t it = NULL;
	const char *k = NULL;

	if (obj->type != UCL_OBJECT) {
		msg_err_config ("invalid rule definition");
		return -1;
	}

	rule = fuzzy_rule_new (fuzzy_module_ctx->default_symbol,
			fuzzy_module_ctx->fuzzy_pool);

	if ((value = ucl_object_find_key (obj, "mime_types")) != NULL) {
		it = NULL;
		while ((cur = ucl_iterate_object (value, &it, value->type == UCL_ARRAY))
				!= NULL) {
			rule->mime_types = g_list_concat (rule->mime_types,
					parse_mime_types (ucl_obj_tostring (cur)));
		}
	}

	if (rule->mime_types != NULL) {
		rspamd_mempool_add_destructor (fuzzy_module_ctx->fuzzy_pool,
			(rspamd_mempool_destruct_t)g_list_free, rule->mime_types);
	}

	if ((value = ucl_object_find_key (obj, "headers")) != NULL) {
		it = NULL;
		while ((cur = ucl_iterate_object (value, &it, value->type == UCL_ARRAY))
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


	if ((value = ucl_object_find_key (obj, "max_score")) != NULL) {
		rule->max_score = ucl_obj_todouble (value);
	}
	if ((value = ucl_object_find_key (obj,  "symbol")) != NULL) {
		rule->symbol = ucl_obj_tostring (value);
	}
	if ((value = ucl_object_find_key (obj, "read_only")) != NULL) {
		rule->read_only = ucl_obj_toboolean (value);
	}
	if ((value = ucl_object_find_key (obj, "skip_unknown")) != NULL) {
		rule->skip_unknown = ucl_obj_toboolean (value);
	}

	if ((value = ucl_object_find_key (obj, "servers")) != NULL) {
		rule->servers = rspamd_upstreams_create (cfg->ups_ctx);
		rspamd_mempool_add_destructor (fuzzy_module_ctx->fuzzy_pool,
				(rspamd_mempool_destruct_t)rspamd_upstreams_destroy,
				rule->servers);
		rspamd_upstreams_from_ucl (rule->servers, value, DEFAULT_PORT, NULL);
	}
	if ((value = ucl_object_find_key (obj, "fuzzy_map")) != NULL) {
		it = NULL;
		while ((cur = ucl_iterate_object (value, &it, true)) != NULL) {
			parse_flags (rule, cfg, cur, cb_id);
		}
	}

	if ((value = ucl_object_find_key (obj, "encryption_key")) != NULL) {
		/* Create key from user's input */
		k = ucl_object_tostring (value);
		if (k == NULL || (rule->peer_key =
					rspamd_http_connection_make_peer_key (k)) == NULL) {
			msg_err_config ("bad encryption key value: %s",
					k);
			return -1;
		}

		rule->local_key = rspamd_http_connection_gen_key ();
	}

	if ((value = ucl_object_find_key (obj, "fuzzy_key")) != NULL) {
		/* Create key from user's input */
		k = ucl_object_tostring (value);
	}

	/* Setup keys */
	if (k == NULL) {
		/* Use some default key for all ops */
		k = "rspamd";
	}

	rule->hash_key = g_string_sized_new (rspamd_cryptobox_HASHBYTES);
	rspamd_cryptobox_hash (rule->hash_key->str, k, strlen (k), NULL, 0);
	rule->hash_key->len = rspamd_cryptobox_HASHKEYBYTES;

	if ((value = ucl_object_find_key (obj, "fuzzy_shingles_key")) != NULL) {
		k = ucl_object_tostring (value);
	}
	if (k == NULL) {
		k = "rspamd";
	}

	rule->shingles_key = g_string_sized_new (rspamd_cryptobox_HASHBYTES);
	rspamd_cryptobox_hash (rule->shingles_key->str, k, strlen (k), NULL, 0);
	rule->shingles_key->len = 16;

	if (rspamd_upstreams_count (rule->servers) == 0) {
		msg_err_config ("no servers defined for fuzzy rule with symbol: %s",
			rule->symbol);
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

	return 0;
}

gint
fuzzy_check_module_config (struct rspamd_config *cfg)
{
	const ucl_object_t *value, *cur;
	gint res = TRUE, cb_id, nrules = 0;

	if (!rspamd_config_is_module_enabled (cfg, "fuzzy_check")) {
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
		fuzzy_module_ctx->whitelist = radix_create_compressed ();
		if (!rspamd_map_add (cfg, ucl_obj_tostring (value),
			"Fuzzy whitelist", rspamd_radix_read, rspamd_radix_fin,
			(void **)&fuzzy_module_ctx->whitelist)) {
			radix_add_generic_iplist (ucl_obj_tostring (value),
					&fuzzy_module_ctx->whitelist);
		}
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

		LL_FOREACH (value, cur) {
			fuzzy_parse_rule (cfg, cur, cb_id);
			nrules ++;
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
	memset (fuzzy_module_ctx, 0, sizeof (*fuzzy_module_ctx));
	fuzzy_module_ctx->ctx = saved_ctx;
	fuzzy_module_ctx->fuzzy_pool = rspamd_mempool_new (rspamd_mempool_suggest_size (), NULL);
	fuzzy_module_ctx->cfg = cfg;

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
fuzzy_preprocess_words (struct mime_text_part *part, rspamd_mempool_t *pool)
{
	return part->normalized_words;
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
	struct rspamd_http_keypair *lk, *rk;
	GHashTableIter it;
	gpointer k, v;
	struct rspamd_url *u;
	struct raw_header *rh;
	GList *cur;

	if (rule->peer_key) {
		enccmd = rspamd_mempool_alloc0 (pool, sizeof (*enccmd));
		cmd = &enccmd->cmd;
		lk = rule->local_key;
		rk = rule->peer_key;
	}
	else {
		cmd = rspamd_mempool_alloc0 (pool, sizeof (*cmd));
	}

	cmd->cmd = c;
	cmd->version = RSPAMD_FUZZY_VERSION;
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

	if (rule->peer_key) {
		g_assert (enccmd != NULL);
		/* Encrypt data */
		memcpy (enccmd->hdr.magic,
				fuzzy_encrypted_magic,
				sizeof (enccmd->hdr.magic));
		ottery_rand_bytes (enccmd->hdr.nonce, sizeof (enccmd->hdr.nonce));
		memcpy (enccmd->hdr.pubkey, lk->pk, sizeof (enccmd->hdr.pubkey));
		rspamd_keypair_cache_process (fuzzy_module_ctx->keypairs_cache,
				lk, rk);
		rspamd_cryptobox_encrypt_nm_inplace ((guchar *) cmd, sizeof (*cmd),
				enccmd->hdr.nonce, rk->nm, enccmd->hdr.mac);
		io->io.iov_base = enccmd;
		io->io.iov_len = sizeof (*enccmd);
	}
	else {
		io->io.iov_base = cmd;
		io->io.iov_len = sizeof (*cmd);
	}

	return io;
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
		struct mime_text_part *part)
{
	struct rspamd_fuzzy_shingle_cmd *shcmd;
	struct rspamd_fuzzy_encrypted_shingle_cmd *encshcmd;
	struct rspamd_shingle *sh;
	guint i;
	rspamd_cryptobox_hash_state_t st;
	rspamd_ftok_t *word;
	GArray *words;
	struct fuzzy_cmd_io *io;
	struct rspamd_http_keypair *lk, *rk;

	if (rule->peer_key) {
		encshcmd = rspamd_mempool_alloc0 (pool, sizeof (*encshcmd));
		shcmd = &encshcmd->cmd;
		lk = rule->local_key;
		rk = rule->peer_key;
	}
	else {
		shcmd = rspamd_mempool_alloc0 (pool, sizeof (*shcmd));
		encshcmd = NULL;
	}

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

	msg_debug_pool ("loading shingles with key %*xs", 16,
			rule->shingles_key->str);
	sh = rspamd_shingles_generate (words,
			rule->shingles_key->str, pool,
			rspamd_shingles_default_filter, NULL);
	if (sh != NULL) {
		memcpy (&shcmd->sgl, sh, sizeof (shcmd->sgl));
		shcmd->basic.shingles_count = RSPAMD_SHINGLE_SIZE;
	}

	shcmd->basic.tag = ottery_rand_uint32 ();
	shcmd->basic.cmd = c;
	shcmd->basic.version = RSPAMD_FUZZY_VERSION;
	if (c != FUZZY_CHECK) {
		shcmd->basic.flag = flag;
		shcmd->basic.value = weight;
	}

	io = rspamd_mempool_alloc (pool, sizeof (*io));
	io->tag = shcmd->basic.tag;
	io->flags = 0;

	if (rule->peer_key) {
		g_assert (encshcmd != NULL);
		/* Encrypt data */
		memcpy (encshcmd->hdr.magic,
				fuzzy_encrypted_magic,
				sizeof (encshcmd->hdr.magic));
		ottery_rand_bytes (encshcmd->hdr.nonce, sizeof (encshcmd->hdr.nonce));
		memcpy (encshcmd->hdr.pubkey, lk->pk, sizeof (encshcmd->hdr.pubkey));
		rspamd_keypair_cache_process (fuzzy_module_ctx->keypairs_cache,
				lk, rk);
		rspamd_cryptobox_encrypt_nm_inplace ((guchar *)shcmd, sizeof (*shcmd),
				encshcmd->hdr.nonce, rk->nm, encshcmd->hdr.mac);
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
		const guchar *data,
		gsize datalen)
{
	struct rspamd_fuzzy_cmd *cmd;
	struct rspamd_fuzzy_encrypted_cmd *enccmd;
	struct fuzzy_cmd_io *io;
	rspamd_cryptobox_hash_state_t st;
	struct rspamd_http_keypair *lk, *rk;

	if (rule->peer_key) {
		enccmd = rspamd_mempool_alloc0 (pool, sizeof (*enccmd));
		cmd = &enccmd->cmd;
		lk = rule->local_key;
		rk = rule->peer_key;
	}
	else {
		cmd = rspamd_mempool_alloc0 (pool, sizeof (*cmd));
	}

	cmd->cmd = c;
	cmd->version = RSPAMD_FUZZY_VERSION;
	if (c != FUZZY_CHECK) {
		cmd->flag = flag;
		cmd->value = weight;
	}
	cmd->shingles_count = 0;
	cmd->tag = ottery_rand_uint32 ();
	/* Use blake2b for digest */
	rspamd_cryptobox_hash_init (&st, rule->hash_key->str, rule->hash_key->len);
	rspamd_cryptobox_hash_update (&st, data, datalen);
	rspamd_cryptobox_hash_final (&st, cmd->digest);

	io = rspamd_mempool_alloc (pool, sizeof (*io));
	io->flags = 0;
	io->tag = cmd->tag;

	if (rule->peer_key) {
		g_assert (enccmd != NULL);
		/* Encrypt data */
		memcpy (enccmd->hdr.magic,
				fuzzy_encrypted_magic,
				sizeof (enccmd->hdr.magic));
		ottery_rand_bytes (enccmd->hdr.nonce, sizeof (enccmd->hdr.nonce));
		memcpy (enccmd->hdr.pubkey, lk->pk, sizeof (enccmd->hdr.pubkey));
		rspamd_keypair_cache_process (fuzzy_module_ctx->keypairs_cache,
				lk, rk);
		rspamd_cryptobox_encrypt_nm_inplace ((guchar *)cmd, sizeof (*cmd),
				enccmd->hdr.nonce, rk->nm, enccmd->hdr.mac);
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
		struct fuzzy_rule *rule)
{
	guchar *p = *pos;
	gint remain = *r;
	guint i, required_size;
	struct fuzzy_cmd_io *io;
	const struct rspamd_fuzzy_reply *rep;
	struct rspamd_fuzzy_encrypted_reply encrep;
	struct rspamd_http_keypair *lk, *rk;
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
		lk = rule->local_key;
		rk = rule->peer_key;
		/* Try to decrypt reply */
		rspamd_keypair_cache_process (fuzzy_module_ctx->keypairs_cache,
				lk, rk);

		if (!rspamd_cryptobox_decrypt_nm_inplace ((guchar *)&encrep.rep,
				sizeof (encrep.rep),
				encrep.hdr.nonce,
				rk->nm,
				encrep.hdr.mac)) {
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

/* Fuzzy check callback */
static void
fuzzy_check_io_callback (gint fd, short what, void *arg)
{
	struct fuzzy_client_session *session = arg;
	const struct rspamd_fuzzy_reply *rep;
	struct rspamd_task *task;
	struct fuzzy_mapping *map;
	guchar buf[2048], *p;
	const gchar *symbol;
	struct fuzzy_cmd_io *io;
	guint i;
	gint r;
	double nval;
	enum {
		return_error = 0,
		return_want_more,
		return_finished
	} ret = return_error;

	task = session->task;

	if (what == EV_WRITE) {
		if (!fuzzy_cmd_vector_to_wire (fd, session->commands)) {
			ret = return_error;
		}
		else {
			session->state = 1;
			ret = return_want_more;
		}
	}
	else if (session->state == 1) {
		/* Try to read reply */
		if ((r = read (fd, buf, sizeof (buf) - 1)) == -1) {
			if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
				event_add (&session->ev, NULL);
				return;
			}
		}
		else {
			p = buf;
			ret = return_want_more;

			while ((rep = fuzzy_process_reply (&p, &r,
					session->commands, session->rule)) != NULL) {
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

				if (rep->prob > 0.5) {
					nval = fuzzy_normalize (rep->value, session->rule->max_score);
					nval *= rep->prob;
					msg_info_task (
							"<%s>, found fuzzy hash with weight: %.2f, in list: %s:%d%s",
							session->task->message_id,
							nval,
							symbol,
							rep->flag,
							map == NULL ? "(unknown)" : "");
					if (map != NULL || !session->rule->skip_unknown) {
						rspamd_snprintf (buf,
								sizeof (buf),
								"%d: %.2f / %.2f",
								rep->flag,
								rep->prob,
								nval);
						rspamd_task_insert_result_single (session->task,
								symbol,
								nval,
								g_list_prepend (NULL,
									rspamd_mempool_strdup (
										session->task->task_pool, buf)));
					}
				}
				ret = return_finished;
			}
		}
	}
	else {
		/* Should not happen */
		g_assert (0);
	}

	if (ret == return_want_more) {
		/* Processed write, switch to reading */
		event_del (&session->ev);
		event_set (&session->ev, fd, EV_READ,
				fuzzy_check_io_callback, session);
		event_add (&session->ev, NULL);
	}
	else if (ret == return_error) {
		/* Error state */
		msg_err_task ("got error on IO with server %s, on %s, %d, %s",
			rspamd_upstream_name (session->server),
			session->state == 1 ? "read" : "write",
			errno,
			strerror (errno));
		rspamd_upstream_fail (session->server);
		rspamd_session_remove_event (session->task->s, fuzzy_io_fin, session);
	}
	else {
		/* Read something from network */
		rspamd_upstream_ok (session->server);
		guint nreplied = 0;

		for (i = 0; i < session->commands->len; i++) {
			io = g_ptr_array_index (session->commands, i);

			if (io->flags & FUZZY_CMD_FLAG_REPLIED) {
				nreplied++;
			}
		}

		if (nreplied == session->commands->len) {
			rspamd_session_remove_event (session->task->s, fuzzy_io_fin, session);
		}
		else {
			/* Need to read more */
			event_del (&session->ev);
			event_set (&session->ev, fd, EV_READ,
					fuzzy_check_io_callback, session);
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

	task = session->task;

	if (session->retransmits >= fuzzy_module_ctx->retransmits) {
		msg_err_task ("got IO timeout with server %s, after %d retransmits",
				rspamd_upstream_name (session->server),
				session->retransmits);
		rspamd_upstream_fail (session->server);
		rspamd_session_remove_event (session->task->s, fuzzy_io_fin, session);
	}
	else {
		/* Plan write event */
		event_del (&session->ev);
		event_set (&session->ev, fd, EV_WRITE,
				fuzzy_check_io_callback, session);
		event_add (&session->ev, NULL);

		/* Plan new retransmit timer */
		event_del (&session->timev);
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
	const gchar *symbol;
	gint r;
	enum {
		return_error = 0,
		return_want_more,
		return_finished
	} ret = return_want_more;
	guint i, nreplied;

	task = session->task;

	if (what == EV_WRITE) {
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
	else if (what == EV_READ) {
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
					session->commands, session->rule)) != NULL) {
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
					msg_info_task ("processed fuzzy hash <%d>, list: %s:%d for "
									"message <%s>",
							rep->tag,
							symbol,
							rep->flag,
							session->task->message_id);
				}
				else {
					msg_info_task ("cannot process fuzzy hash for message "
							"<%s>, "
							"list %s:%d, error: %d",
							session->task->message_id,
							symbol,
							rep->flag,
							rep->value);
					if (*(session->err) == NULL) {
						g_set_error (session->err,
							g_quark_from_static_string ("fuzzy check"),
							EINVAL, "process fuzzy error");
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
	else {
		g_assert (0);
	}

	if (ret == return_want_more) {
		event_del (&session->ev);
		event_set (&session->ev, fd, EV_READ,
				fuzzy_controller_io_callback, session);
		event_add (&session->ev, NULL);
		return;
	}
	else if (ret == return_error) {
		msg_err_task ("got error in IO with server %s, %d, %s",
				rspamd_upstream_name (session->server), errno, strerror (errno));
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

	task = session->task;

	if (session->retransmits >= fuzzy_module_ctx->retransmits) {
		rspamd_upstream_fail (session->server);
		rspamd_controller_send_error (session->http_entry,
				500, "IO timeout with fuzzy storage");
		msg_err_task ("got IO timeout with server %s, after %d retransmits",
				rspamd_upstream_name (session->server),
				session->retransmits);

		if (*session->saved > 0 ) {
			(*session->saved)--;
			if (*session->saved == 0 && session->task != NULL) {
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
		event_del (&session->ev);
		event_set (&session->ev, fd, EV_WRITE,
				fuzzy_controller_io_callback, session);
		event_add (&session->ev, NULL);

		/* Plan new retransmit timer */
		event_del (&session->timev);
		event_add (&session->timev, &session->tv);
		session->retransmits ++;
	}
}

static GPtrArray *
fuzzy_generate_commands (struct rspamd_task *task, struct fuzzy_rule *rule,
		gint c, gint flag, guint32 value)
{
	struct mime_text_part *part;
	struct mime_part *mime_part;
	struct rspamd_image *image;
	struct fuzzy_cmd_io *io;
	guint i;
	GPtrArray *res;

	res = g_ptr_array_new ();

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

	/* Process images */
	GList *cur;

	cur = task->images;
	while (cur) {
		image = cur->data;
		if (image->data->len > 0) {
			if (fuzzy_module_ctx->min_height <= 0 || image->height >=
				fuzzy_module_ctx->min_height) {
				if (fuzzy_module_ctx->min_width <= 0 || image->width >=
					fuzzy_module_ctx->min_width) {
					if (c == FUZZY_CHECK) {
						io = fuzzy_cmd_from_data_part (rule, c, flag, value,
								task->task_pool,
								image->data->data, image->data->len);
						if (io) {
							g_ptr_array_add (res, io);
						}
					}
					io = fuzzy_cmd_from_data_part (rule, c, flag, value,
							task->task_pool,
							image->data->data, image->data->len);
					if (io) {
						g_ptr_array_add (res, io);
					}
				}
			}
		}
		cur = g_list_next (cur);
	}

	/* Process other parts */
	for (i = 0; i < task->parts->len; i ++) {
		mime_part = g_ptr_array_index (task->parts, i);

		if (mime_part->content->len > 0 &&
			fuzzy_check_content_type (rule, mime_part->type)) {
			if (fuzzy_module_ctx->min_bytes <= 0 || mime_part->content->len >=
				fuzzy_module_ctx->min_bytes) {
				io = fuzzy_cmd_from_data_part (rule, c, flag, value,
						task->task_pool,
						mime_part->content->data, mime_part->content->len);
				if (io) {
					g_ptr_array_add (res, io);
				}
			}
		}
	}

	/* Process metadata */
	io = fuzzy_cmd_from_task_meta (rule, c, flag, value,
			task->task_pool, task);
	if (io) {
		g_ptr_array_add (res, io);
	}

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
	gint sock;

	/* Get upstream */
	selected = rspamd_upstream_get (rule->servers, RSPAMD_UPSTREAM_ROUND_ROBIN,
			NULL, 0);
	if (selected) {
		if ((sock = rspamd_inet_address_connect (rspamd_upstream_addr (selected),
				SOCK_DGRAM, TRUE)) == -1) {
			msg_warn_task ("cannot connect to %s, %d, %s",
				rspamd_upstream_name (selected),
				errno,
				strerror (errno));
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

static inline gboolean
register_fuzzy_controller_call (struct rspamd_http_connection_entry *entry,
	struct fuzzy_rule *rule,
	struct rspamd_task *task,
	GPtrArray *commands,
	gint *saved,
	GError **err)
{
	struct fuzzy_learn_session *s;
	struct upstream *selected;
	struct rspamd_controller_session *session = entry->ud;
	gint sock;
	gboolean ret = FALSE;

	/* Get upstream */

	while ((selected = rspamd_upstream_get (rule->servers,
			RSPAMD_UPSTREAM_SEQUENTIAL, NULL, 0))) {
		/* Create UDP socket */
		if ((sock = rspamd_inet_address_connect (rspamd_upstream_addr (selected),
				SOCK_DGRAM, TRUE)) == -1) {
			rspamd_upstream_fail (selected);
		}
		else {
			s =
				rspamd_mempool_alloc0 (session->pool,
					sizeof (struct fuzzy_learn_session));

			msec_to_tv (fuzzy_module_ctx->io_timeout, &s->tv);
			s->task = task;
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
			ret = TRUE;
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
	struct rspamd_task *task;
	gboolean processed = FALSE, res = TRUE;
	GList *cur;
	GError **err;
	GPtrArray *commands;
	gint r, *saved, rules = 0;

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
			cur = g_list_next (cur);
			continue;
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
		else if (res == -1) {
			break;
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

static gboolean
fuzzy_controller_handler (struct rspamd_http_connection_entry *conn_ent,
	struct rspamd_http_message *msg, struct module_ctx *ctx, gint cmd)
{
	const rspamd_ftok_t *arg;
	glong value = 1, flag = 0;

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
