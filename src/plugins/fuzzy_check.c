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
#include "libmime/expressions.h"
#include "libutil/map.h"
#include "libmime/images.h"
#include "fuzzy_storage.h"
#include "utlist.h"
#include "main.h"
#include "blake2.h"

#define DEFAULT_SYMBOL "R_FUZZY_HASH"
#define DEFAULT_UPSTREAM_ERROR_TIME 10
#define DEFAULT_UPSTREAM_DEAD_TIME 300
#define DEFAULT_UPSTREAM_MAXERRORS 10

#define DEFAULT_IO_TIMEOUT 500
#define DEFAULT_PORT 11335

struct fuzzy_mapping {
	guint64 fuzzy_flag;
	const gchar *symbol;
	double weight;
};

struct fuzzy_mime_type {
	gchar *type;
	gchar *subtype;
};

struct fuzzy_rule {
	struct upstream_list *servers;
	gint servers_num;
	const gchar *symbol;
	GHashTable *mappings;
	GList *mime_types;
	GString *hash_key;
	GString *shingles_key;
	double max_score;
	gboolean read_only;
	gboolean skip_unknown;
};

struct fuzzy_ctx {
	gint (*filter) (struct rspamd_task * task);
	rspamd_mempool_t *fuzzy_pool;
	GList *fuzzy_rules;
	struct rspamd_config *cfg;
	const gchar *default_symbol;
	guint32 min_hash_len;
	radix_compressed_t *whitelist;
	guint32 min_bytes;
	guint32 min_height;
	guint32 min_width;
	guint32 io_timeout;
};

struct fuzzy_client_session {
	gint state;
	rspamd_fuzzy_t *h;
	struct event ev;
	struct timeval tv;
	struct rspamd_task *task;
	struct upstream *server;
	struct fuzzy_rule *rule;
	gint fd;
};

struct fuzzy_learn_session {
	struct event ev;
	rspamd_fuzzy_t *h;
	gint cmd;
	gint value;
	gint flag;
	gint *saved;
	GError **err;
	struct fuzzy_mapping *map;
	struct timeval tv;
	struct rspamd_http_connection_entry *http_entry;
	struct upstream *server;
	struct fuzzy_rule *rule;
	struct rspamd_task *task;
	gint fd;
};

static struct fuzzy_ctx *fuzzy_module_ctx = NULL;
static const gchar hex_digits[] = "0123456789abcdef";

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
	const ucl_object_t *val)
{
	const ucl_object_t *elt;
	struct fuzzy_mapping *map;
	const gchar *sym = NULL;

	if (val->type == UCL_STRING) {
		msg_err (
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
				register_virtual_symbol (&cfg->cache, map->symbol, 1.0);
			}
			else {
				msg_err ("fuzzy_map parameter has no flag definition");
			}
		}
		else {
			msg_err ("fuzzy_map parameter has no symbol definition");
		}
	}
	else {
		msg_err ("fuzzy_map parameter is of an unsupported type");
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
			type =
				rspamd_mempool_alloc (fuzzy_module_ctx->fuzzy_pool,
					sizeof (struct fuzzy_mime_type));
			type->type = rspamd_mempool_strdup (fuzzy_module_ctx->fuzzy_pool,
					strvec[i]);
			type->subtype = rspamd_mempool_strdup (fuzzy_module_ctx->fuzzy_pool,
					p + 1);
			res = g_list_prepend (res, type);
		}
		else {
			msg_info ("bad content type: %s", strvec[i]);
		}
	}

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
		if (g_mime_content_type_is_type (type, ft->type, ft->subtype)) {
			return TRUE;
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

static const gchar *
fuzzy_to_string (rspamd_fuzzy_t *h)
{
	static gchar strbuf [FUZZY_HASHLEN * 2 + 1];
	const int max_print = 5;
	gint i;
	guint8 byte;

	for (i = 0; i < max_print; i++) {
		byte = h->hash_pipe[i];
		if (byte == '\0') {
			break;
		}
		strbuf[i * 2] = hex_digits[byte >> 4];
		strbuf[i * 2 + 1] = hex_digits[byte & 0xf];
	}
	if (i == max_print) {
		memcpy (&strbuf[i * 2], "...", 4);
	}
	else {
		strbuf[i * 2] = '\0';
	}

	return strbuf;
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

static gint
fuzzy_parse_rule (struct rspamd_config *cfg, const ucl_object_t *obj)
{
	const ucl_object_t *value, *cur;
	struct fuzzy_rule *rule;
	ucl_object_iter_t it = NULL;

	if (obj->type != UCL_OBJECT) {
		msg_err ("invalid rule definition");
		return -1;
	}

	rule = fuzzy_rule_new (fuzzy_module_ctx->default_symbol,
			fuzzy_module_ctx->fuzzy_pool);

	if ((value = ucl_object_find_key (obj, "mime_types")) != NULL) {
		it = NULL;
		while ((cur = ucl_iterate_object (value, &it, obj->type == UCL_ARRAY))
				!= NULL) {
			rule->mime_types = g_list_concat (rule->mime_types,
					parse_mime_types (ucl_obj_tostring (cur)));
		}
	}

	if (rule->mime_types != NULL) {
		rspamd_mempool_add_destructor (fuzzy_module_ctx->fuzzy_pool,
			(rspamd_mempool_destruct_t)g_list_free, rule->mime_types);
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
		rule->servers = rspamd_upstreams_create ();
		rspamd_mempool_add_destructor (fuzzy_module_ctx->fuzzy_pool,
				(rspamd_mempool_destruct_t)rspamd_upstreams_destroy,
				rule->servers);
		rspamd_upstreams_from_ucl (rule->servers, value, DEFAULT_PORT, NULL);
	}
	if ((value = ucl_object_find_key (obj, "fuzzy_map")) != NULL) {
		it = NULL;
		while ((cur = ucl_iterate_object (value, &it, true)) != NULL) {
			parse_flags (rule, cfg, cur);
		}
	}

	if (rspamd_upstreams_count (rule->servers) == 0) {
		msg_err ("no servers defined for fuzzy rule with symbol: %s",
			rule->symbol);
		return -1;
	}
	else {
		fuzzy_module_ctx->fuzzy_rules = g_list_prepend (
			fuzzy_module_ctx->fuzzy_rules,
			rule);
		if (rule->symbol != fuzzy_module_ctx->default_symbol) {
			register_virtual_symbol (&cfg->cache, rule->symbol, 1.0);
		}
	}

	return 0;
}

gint
fuzzy_check_module_init (struct rspamd_config *cfg, struct module_ctx **ctx)
{
	fuzzy_module_ctx = g_malloc0 (sizeof (struct fuzzy_ctx));

	fuzzy_module_ctx->fuzzy_pool = rspamd_mempool_new (
		rspamd_mempool_suggest_size ());
	fuzzy_module_ctx->cfg = cfg;

	*ctx = (struct module_ctx *)fuzzy_module_ctx;

	return 0;
}

gint
fuzzy_check_module_config (struct rspamd_config *cfg)
{
	const ucl_object_t *value, *cur;
	gint res = TRUE;

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
		LL_FOREACH (value, cur) {
			fuzzy_parse_rule (cfg, cur);
		}
	}

	if (fuzzy_module_ctx->fuzzy_rules != NULL) {
		register_callback_symbol (&cfg->cache, fuzzy_module_ctx->default_symbol,
			1.0, fuzzy_symbol_callback, NULL);
	}
	else {
		msg_warn ("fuzzy module is enabled but no rules are defined");
	}

	return res;
}

gint
fuzzy_check_module_reconfig (struct rspamd_config *cfg)
{
	rspamd_mempool_delete (fuzzy_module_ctx->fuzzy_pool);

	memset (fuzzy_module_ctx, 0, sizeof (*fuzzy_module_ctx));
	fuzzy_module_ctx->fuzzy_pool = rspamd_mempool_new (
		rspamd_mempool_suggest_size ());
	fuzzy_module_ctx->cfg = cfg;

	return fuzzy_check_module_config (cfg);
}

/* Finalize IO */
static void
fuzzy_io_fin (void *ud)
{
	struct fuzzy_client_session *session = ud;

	event_del (&session->ev);
	close (session->fd);
}


/*
 * Create fuzzy command from a text part
 */
struct rspamd_fuzzy_cmd *
fuzzy_cmd_from_text_part (struct fuzzy_rule *rule,
		int c,
		gint flag,
		guint32 weight,
		rspamd_mempool_t *pool,
		struct mime_text_part *part,
		gboolean legacy,
		gsize *size)
{
	struct rspamd_fuzzy_cmd *cmd;
	struct rspamd_fuzzy_shingle_cmd *shcmd;
	struct rspamd_shingle *sh;
	guint i;
	blake2b_state st;
	rspamd_fstring_t *word;

	if (legacy || part->words == NULL) {
		cmd = rspamd_mempool_alloc0 (pool, sizeof (*cmd));
		cmd->cmd = c;
		cmd->version = RSPAMD_FUZZY_VERSION;
		if (c != FUZZY_CHECK) {
			cmd->flag = flag;
			cmd->value = weight;
		}
		cmd->shingles_count = 0;
		rspamd_strlcpy (cmd->digest, part->fuzzy->hash_pipe, sizeof (cmd->digest));
		*size = sizeof (struct rspamd_fuzzy_cmd);
	}
	else {
		shcmd = rspamd_mempool_alloc0 (pool, sizeof (*shcmd));
		shcmd->basic.cmd = c;
		shcmd->basic.version = RSPAMD_FUZZY_VERSION;
		if (c != FUZZY_CHECK) {
			shcmd->basic.flag = flag;
			shcmd->basic.value = weight;
		}

		/*
		 * Generate hash from all words in the part
		 */
		blake2b_init_key (&st, BLAKE2B_OUTBYTES, rule->hash_key->str,
				rule->hash_key->len);
		for (i = 0; i < part->words->len; i ++) {
			word = &g_array_index (part->words, rspamd_fstring_t, i);
			blake2b_update (&st, word->begin, word->len);
		}
		blake2b_final (&st, shcmd->basic.digest, sizeof (shcmd->basic.digest));

		sh = rspamd_shingles_generate (part->words, rule->shingles_key->str,
				pool, rspamd_shingles_default_filter, NULL);
		if (sh != NULL) {
			memcpy (&shcmd->sgl, sh, sizeof (shcmd->sgl));
			shcmd->basic.shingles_count = RSPAMD_SHINGLE_SIZE;
		}

		cmd = (struct rspamd_fuzzy_cmd *)shcmd;
		*size = sizeof (struct rspamd_fuzzy_shingle_cmd);
	}

	return cmd;
}

struct rspamd_fuzzy_cmd *
fuzzy_cmd_from_data_part (struct fuzzy_rule *rule,
		int c,
		gint flag,
		guint32 weight,
		rspamd_mempool_t *pool,
		const guchar *data,
		gsize datalen,
		gboolean legacy,
		gsize *size)
{
	struct rspamd_fuzzy_cmd *cmd;

	cmd = rspamd_mempool_alloc0 (pool, sizeof (*cmd));
	cmd->cmd = c;
	cmd->version = RSPAMD_FUZZY_VERSION;
	if (c != FUZZY_CHECK) {
		cmd->flag = flag;
		cmd->value = weight;
	}
	cmd->shingles_count = 0;

	if (legacy) {
		GChecksum *cksum;

		cksum = g_checksum_new (G_CHECKSUM_MD5);
		g_checksum_update (cksum, data, datalen);
		rspamd_strlcpy (cmd->digest, g_checksum_get_string (cksum),
				sizeof (cmd->digest));
	}
	else {
		/* Use blake2b for digest */
		blake2b_state st;

		blake2b_init_key (&st, BLAKE2B_OUTBYTES, rule->hash_key->str,
				rule->hash_key->len);
		blake2b_update (&st, data, datalen);
		blake2b_final (&st, cmd->digest, sizeof (cmd->digest));
	}

	*size = sizeof (struct rspamd_fuzzy_cmd);

	return cmd;
}

/* Call this whenever we got data from fuzzy storage */
static void
fuzzy_io_callback (gint fd, short what, void *arg)
{
	struct fuzzy_client_session *session = arg;
	struct legacy_fuzzy_cmd cmd;
	struct fuzzy_mapping *map;
	gchar buf[62], *err_str;
	const gchar *symbol;
	gint value = 0, flag = 0, r;
	double nval;
	gint ret = 0;

	if (what == EV_WRITE) {
		/* Send command to storage */
		memset (&cmd, 0, sizeof (cmd));
		cmd.blocksize = session->h->block_size;
		cmd.value = 0;
		memcpy (cmd.hash, session->h->hash_pipe, sizeof (cmd.hash));
		cmd.cmd = FUZZY_CHECK;
		cmd.flag = 0;
		if (write (fd, &cmd, sizeof (struct legacy_fuzzy_cmd)) == -1) {
			ret = -1;
		}
		else {
			event_del (&session->ev);
			event_set (&session->ev, fd, EV_READ, fuzzy_io_callback, session);
			event_add (&session->ev, &session->tv);
			session->state = 1;
		}
	}
	else if (session->state == 1) {
		/* Try to read reply */
		if ((r = read (fd, buf, sizeof (buf) - 1)) == -1) {
			ret = -1;
		}
		else if (buf[0] == 'O' && buf[1] == 'K') {
			buf[r] = 0;
			/* Now try to get value */
			value = strtol (buf + 3, &err_str, 10);
			if (*err_str == ' ') {
				/* Now read flag */
				flag = strtol (err_str + 1, &err_str, 10);
			}
			*err_str = '\0';
			/* Get mapping by flag */
			if ((map =
				g_hash_table_lookup (session->rule->mappings,
				GINT_TO_POINTER (flag))) == NULL) {
				/* Default symbol and default weight */
				symbol = session->rule->symbol;
				nval = fuzzy_normalize (value, session->rule->max_score);
			}
			else {
				/* Get symbol and weight from map */
				symbol = map->symbol;
				nval = fuzzy_normalize (value, map->weight);
			}
			msg_info (
				"<%s>, found fuzzy hash '%s' with weight: %.2f, in list: %s:%d%s",
				session->task->message_id,
				fuzzy_to_string (session->h),
				nval,
				symbol,
				flag,
				map == NULL ? "(unknown)" : "");
			if (map != NULL || !session->rule->skip_unknown) {
				rspamd_snprintf (buf,
					sizeof (buf),
					"%d: %d / %.2f",
					flag,
					value,
					nval);
				rspamd_task_insert_result_single (session->task,
					symbol,
					nval,
					g_list_prepend (NULL,
					rspamd_mempool_strdup (session->task->task_pool, buf)));
			}
		}
		ret = 1;
	}
	else {
		errno = ETIMEDOUT;
		ret = -1;
	}

	if (ret == 0) {
		return;
	}
	else if (ret == -1) {
		msg_err ("got error on IO with server %s, %d, %s",
			rspamd_upstream_name (session->server),
			errno,
			strerror (errno));
		rspamd_upstream_fail (session->server);
	}
	else {
		rspamd_upstream_ok (session->server);
	}

	remove_normal_event (session->task->s, fuzzy_io_fin, session);
}

static void
fuzzy_learn_callback (gint fd, short what, void *arg)
{
	struct fuzzy_learn_session *session = arg;
	struct legacy_fuzzy_cmd cmd;
	gchar buf[512];
	const gchar *cmd_name, *symbol;
	gint ret = 0;

	cmd_name = (session->cmd == FUZZY_WRITE ? "add" : "delete");
	if (what == EV_WRITE) {
		/* Send command to storage */
		cmd.blocksize = session->h->block_size;
		memcpy (cmd.hash, session->h->hash_pipe, sizeof (cmd.hash));
		cmd.cmd = session->cmd;
		cmd.value = session->value;
		cmd.flag = session->flag;
		if (write (fd, &cmd, sizeof (struct legacy_fuzzy_cmd)) == -1) {
			if (*(session->err) == NULL) {
				g_set_error (session->err,
					g_quark_from_static_string ("fuzzy check"),
					errno, "write socket error: %s", strerror (errno));
			}
			ret = -1;
		}
		else {
			event_del (&session->ev);
			event_set (&session->ev, fd, EV_READ, fuzzy_learn_callback,
				session);
			event_add (&session->ev, &session->tv);
		}
	}
	else if (what == EV_READ) {
		if (session->map) {
			symbol = session->map->symbol;
		}
		else {
			symbol = session->rule->symbol;
		}
		if (read (fd, buf, sizeof (buf)) == -1) {
			msg_info ("cannot %s fuzzy hash for message <%s>, list %s:%d",
				cmd_name,
				session->task->message_id,
				symbol,
				session->flag);
			if (*(session->err) == NULL) {
				g_set_error (session->err,
					g_quark_from_static_string ("fuzzy check"),
					errno, "read socket error: %s", strerror (errno));
			}
			ret = -1;
		}
		else if (buf[0] == 'O' && buf[1] == 'K') {
			msg_info ("%s fuzzy hash '%s', list: %s:%d for message <%s>",
				cmd_name,
				fuzzy_to_string (session->h),
				symbol,
				session->flag,
				session->task->message_id);
			ret = 1;
		}
		else {
			msg_info ("cannot %s fuzzy hash '%s' for message <%s>, list %s:%d",
				cmd_name,
				fuzzy_to_string (session->h),
				session->task->message_id,
				symbol,
				session->flag);
			if (*(session->err) == NULL) {
				g_set_error (session->err,
					g_quark_from_static_string (
						"fuzzy check"), EINVAL, "%s fuzzy error", cmd_name);
			}
			ret = 1;
		}
	}
	else {
		errno = ETIMEDOUT;
		if (*(session->err) == NULL) {
			g_set_error (session->err,
				g_quark_from_static_string (
					"fuzzy check"), EINVAL, "%s fuzzy, IO timeout", cmd_name);
		}
		ret = -1;
	}

	if (ret == 0) {
		return;
	}
	else if (ret == -1) {
		msg_err ("got error in IO with server %s, %d, %s",
				rspamd_upstream_name (session->server), errno, strerror (errno));
		rspamd_upstream_fail (session->server);
	}
	else {
		rspamd_upstream_ok (session->server);
	}

	rspamd_http_connection_unref (session->http_entry->conn);
	event_del (&session->ev);
	close (session->fd);

	if (--(*(session->saved)) == 0) {
		if (*(session->err) != NULL) {
			rspamd_controller_send_error (session->http_entry,
				(*session->err)->code, (*session->err)->message);
			g_error_free (*session->err);
		}
		else {
			rspamd_controller_send_string (session->http_entry,
				"{\"success\":true}");
		}
		rspamd_task_free (session->task, TRUE);
	}
}

static inline void
register_fuzzy_call (struct rspamd_task *task,
	struct fuzzy_rule *rule,
	rspamd_fuzzy_t *h)
{
	struct fuzzy_client_session *session;
	struct upstream *selected;
	gint sock;

	/* Get upstream */
	selected = rspamd_upstream_get (rule->servers, RSPAMD_UPSTREAM_HASHED,
			h->hash_pipe, sizeof (h->hash_pipe));
	if (selected) {
		if ((sock = rspamd_inet_address_connect (rspamd_upstream_addr (selected),
				SOCK_DGRAM, TRUE)) == -1) {
			msg_warn ("cannot connect to %s, %d, %s",
				rspamd_upstream_name (selected),
				errno,
				strerror (errno));
		}
		else {
			/* Create session for a socket */
			session =
				rspamd_mempool_alloc (task->task_pool,
					sizeof (struct fuzzy_client_session));
			event_set (&session->ev, sock, EV_WRITE, fuzzy_io_callback,
				session);
			msec_to_tv (fuzzy_module_ctx->io_timeout, &session->tv);
			session->state = 0;
			session->h = h;
			session->task = task;
			session->fd = sock;
			session->server = selected;
			session->rule = rule;
			event_add (&session->ev, &session->tv);
			register_async_event (task->s,
				fuzzy_io_fin,
				session,
				g_quark_from_static_string ("fuzzy check"));
		}
	}
}

static void
fuzzy_check_rule (struct rspamd_task *task, struct fuzzy_rule *rule)
{
	struct mime_text_part *part;
	struct mime_part *mime_part;
	struct rspamd_image *image;
	gchar *checksum;
	gsize hashlen;
	GList *cur;
	rspamd_fuzzy_t *fake_fuzzy;

	cur = task->text_parts;

	while (cur) {
		part = cur->data;
		if (part->is_empty) {
			cur = g_list_next (cur);
			continue;
		}

		/* Check length of part */
		if (fuzzy_module_ctx->min_bytes > part->content->len) {
			msg_info ("<%s>, part is shorter than %d symbols, skip fuzzy check",
				task->message_id, fuzzy_module_ctx->min_bytes);
			cur = g_list_next (cur);
			continue;
		}
		/* Check length of hash */
		hashlen = strlen (part->fuzzy->hash_pipe);
		if (hashlen == 0) {
			msg_info ("<%s>, part hash empty, skip fuzzy check",
				task->message_id, fuzzy_module_ctx->min_hash_len);
			cur = g_list_next (cur);
			continue;
		}
		if (fuzzy_module_ctx->min_hash_len != 0 &&
			hashlen * part->fuzzy->block_size <
			fuzzy_module_ctx->min_hash_len) {
			msg_info (
				"<%s>, part hash is shorter than %d symbols, skip fuzzy check",
				task->message_id,
				fuzzy_module_ctx->min_hash_len);
			cur = g_list_next (cur);
			continue;
		}

		register_fuzzy_call (task, rule, part->fuzzy);
		register_fuzzy_call (task, rule, part->double_fuzzy);

		cur = g_list_next (cur);
	}
	/* Process images */
	cur = task->images;
	while (cur) {
		image = cur->data;
		if (image->data->len > 0) {
			if (fuzzy_module_ctx->min_height <= 0 || image->height >=
				fuzzy_module_ctx->min_height) {
				if (fuzzy_module_ctx->min_width <= 0 || image->width >=
					fuzzy_module_ctx->min_width) {
					checksum = g_compute_checksum_for_data (G_CHECKSUM_MD5,
							image->data->data,
							image->data->len);
					/* Construct fake fuzzy hash */
					fake_fuzzy = rspamd_mempool_alloc0 (task->task_pool,
							sizeof (rspamd_fuzzy_t));
					rspamd_strlcpy (fake_fuzzy->hash_pipe, checksum,
						sizeof (fake_fuzzy->hash_pipe));
					register_fuzzy_call (task, rule, fake_fuzzy);
					g_free (checksum);
				}
			}
		}
		cur = g_list_next (cur);
	}
	/* Process other parts */
	cur = task->parts;
	while (cur) {
		mime_part = cur->data;
		if (mime_part->content->len > 0 &&
			fuzzy_check_content_type (rule, mime_part->type)) {
			if (fuzzy_module_ctx->min_bytes <= 0 || mime_part->content->len >=
				fuzzy_module_ctx->min_bytes) {
				checksum = g_compute_checksum_for_data (G_CHECKSUM_MD5,
						mime_part->content->data, mime_part->content->len);
				/* Construct fake fuzzy hash */
				fake_fuzzy =
					rspamd_mempool_alloc0 (task->task_pool,
						sizeof (rspamd_fuzzy_t));
				rspamd_strlcpy (fake_fuzzy->hash_pipe, checksum,
					sizeof (fake_fuzzy->hash_pipe));
				register_fuzzy_call (task, rule, fake_fuzzy);
				g_free (checksum);
			}
		}
		cur = g_list_next (cur);
	}
}

/* This callback is called when we check message via fuzzy hashes storage */
static void
fuzzy_symbol_callback (struct rspamd_task *task, void *unused)
{
	struct fuzzy_rule *rule;
	GList *cur;

	/* Check whitelist */
	if (fuzzy_module_ctx->whitelist) {
		if (radix_find_compressed_addr (fuzzy_module_ctx->whitelist,
				&task->from_addr) != RADIX_NO_VALUE) {
			msg_info ("<%s>, address %s is whitelisted, skip fuzzy check",
				task->message_id,
				rspamd_inet_address_to_string (&task->from_addr));
			return;
		}
	}

	cur = fuzzy_module_ctx->fuzzy_rules;
	while (cur) {
		rule = cur->data;
		fuzzy_check_rule (task, rule);
		cur = g_list_next (cur);
	}
}

static inline gboolean
register_fuzzy_controller_call (struct rspamd_http_connection_entry *entry,
	struct fuzzy_rule *rule, struct rspamd_task *task, rspamd_fuzzy_t *h,
	gint cmd, gint value, gint flag, gint *saved, GError **err)
{
	struct fuzzy_learn_session *s;
	struct upstream *selected;
	gint sock;

	/* Get upstream */
	selected = rspamd_upstream_get (rule->servers, RSPAMD_UPSTREAM_HASHED,
				h->hash_pipe, sizeof (h->hash_pipe));
	if (selected) {
		/* Create UDP socket */
		if ((sock = rspamd_inet_address_connect (rspamd_upstream_addr (selected),
				SOCK_DGRAM, TRUE)) == -1) {
			return FALSE;
		}
		else {
			/* Socket is made, create session */
			s =
				rspamd_mempool_alloc (task->task_pool,
					sizeof (struct fuzzy_learn_session));
			event_set (&s->ev, sock, EV_WRITE, fuzzy_learn_callback, s);
			event_base_set (entry->rt->ev_base, &s->ev);
			msec_to_tv (fuzzy_module_ctx->io_timeout, &s->tv);
			s->task = task;
			s->h =
				rspamd_mempool_alloc (task->task_pool, sizeof (rspamd_fuzzy_t));
			memcpy (s->h, h, sizeof (rspamd_fuzzy_t));
			s->http_entry = entry;
			s->server = selected;
			s->cmd = cmd;
			s->value = value;
			s->flag = flag;
			s->saved = saved;
			s->fd = sock;
			s->err = err;
			s->rule = rule;
			s->map = g_hash_table_lookup (rule->mappings,
					GINT_TO_POINTER (flag));
			/* We ref connection to avoid freeing before we process fuzzy rule */
			rspamd_http_connection_ref (entry->conn);
			event_add (&s->ev, &s->tv);
			(*saved)++;
			return TRUE;
		}
	}

	return FALSE;
}

static int
fuzzy_process_rule (struct rspamd_http_connection_entry *entry,
	struct fuzzy_rule *rule,
	struct rspamd_task *task,
	GError **err,
	gint cmd,
	gint flag,
	gint value,
	gint *saved)
{
	struct mime_text_part *part;
	struct mime_part *mime_part;
	struct rspamd_image *image;
	GList *cur;
	gchar *checksum;
	rspamd_fuzzy_t fake_fuzzy;
	gint processed = 0;

	/* Plan new event for writing */
	cur = task->text_parts;

	while (cur) {
		part = cur->data;
		if (part->is_empty || part->fuzzy == NULL ||
			part->fuzzy->hash_pipe[0] == '\0' ||
			(fuzzy_module_ctx->min_bytes > 0 && part->content->len <
			fuzzy_module_ctx->min_bytes)) {
			/* Skip empty parts */
			msg_info ("<%s>: part %Xd is too short for fuzzy process, skip it",
				task->message_id, part->fuzzy ? part->fuzzy->h : 0);
			cur = g_list_next (cur);
			continue;
		}
		if (!register_fuzzy_controller_call (entry, rule, task,
			part->fuzzy, cmd, value, flag, saved, err)) {
			goto err;
		}
		if (!register_fuzzy_controller_call (entry, rule, task,
			part->double_fuzzy, cmd, value, flag, saved, err)) {
			/* Cannot write hash */
			goto err;
		}
		processed++;
		cur = g_list_next (cur);
	}

	/* Process images */
	cur = task->images;
	while (cur) {
		image = cur->data;
		if (image->data->len > 0) {
			if (fuzzy_module_ctx->min_height <= 0 || image->height >=
				fuzzy_module_ctx->min_height) {
				if (fuzzy_module_ctx->min_width <= 0 || image->width >=
					fuzzy_module_ctx->min_width) {
					checksum = g_compute_checksum_for_data (G_CHECKSUM_MD5,
							image->data->data,
							image->data->len);
					/* Construct fake fuzzy hash */
					fake_fuzzy.block_size = 0;
					memset (fake_fuzzy.hash_pipe, 0,
						sizeof (fake_fuzzy.hash_pipe));
					rspamd_strlcpy (fake_fuzzy.hash_pipe, checksum,
						sizeof (fake_fuzzy.hash_pipe));
					if (!register_fuzzy_controller_call (entry, rule, task,
						&fake_fuzzy, cmd, value, flag, saved, err)) {
						g_free (checksum);
						goto err;
					}

					msg_info ("save hash of image: [%s] to list: %d",
						checksum,
						flag);
					g_free (checksum);
					processed++;
				}
			}
		}
		cur = g_list_next (cur);
	}
	/* Process other parts */
	cur = task->parts;
	while (cur) {
		mime_part = cur->data;
		if (mime_part->content->len > 0 &&
			fuzzy_check_content_type (rule, mime_part->type)) {
			if (fuzzy_module_ctx->min_bytes <= 0 || mime_part->content->len >=
				fuzzy_module_ctx->min_bytes) {
				checksum = g_compute_checksum_for_data (G_CHECKSUM_MD5,
						mime_part->content->data, mime_part->content->len);
				/* Construct fake fuzzy hash */
				fake_fuzzy.block_size = 0;
				memset (fake_fuzzy.hash_pipe, 0, sizeof (fake_fuzzy.hash_pipe));
				rspamd_strlcpy (fake_fuzzy.hash_pipe, checksum,
					sizeof (fake_fuzzy.hash_pipe));
				if (!register_fuzzy_controller_call (entry, rule, task,
					&fake_fuzzy, cmd, value, flag, saved, err)) {
					goto err;
				}
				msg_info ("save hash of part of type: %s/%s: [%s] to list %d",
					mime_part->type->type, mime_part->type->subtype,
					checksum, flag);
				g_free (checksum);
				processed++;
			}
		}
		cur = g_list_next (cur);
	}

	return processed;

err:
	return -1;
}

static void
fuzzy_process_handler (struct rspamd_http_connection_entry *conn_ent,
	struct rspamd_http_message *msg, gint cmd, gint value, gint flag,
	struct fuzzy_ctx *ctx)
{
	struct fuzzy_rule *rule;
	gboolean processed = FALSE, res = TRUE;
	GList *cur;
	struct rspamd_task *task;
	GError **err;
	gint r, *saved, rules = 0;

	/* Prepare task */
	task = rspamd_task_new (NULL);
	task->cfg = ctx->cfg;

	/* Allocate message from string */
	task->msg = msg->body;

	saved = rspamd_mempool_alloc0 (task->task_pool, sizeof (gint));
	err = rspamd_mempool_alloc0 (task->task_pool, sizeof (GError *));
	r = process_message (task);
	if (r == -1) {
		msg_warn ("<%s>: cannot process message for fuzzy", task->message_id);
		rspamd_task_free (task, FALSE);
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
		res = fuzzy_process_rule (conn_ent, rule, task, err, cmd, flag,
				value, saved);

		if (res) {
			processed = TRUE;
		}
		else if (res == -1) {
			break;
		}

		cur = g_list_next (cur);
	}

	if (res == -1) {
		msg_warn ("<%s>: cannot send fuzzy request: %s", task->message_id,
				strerror (errno));
		rspamd_controller_send_error (conn_ent, 400, "Message sending error");
		rspamd_task_free (task, FALSE);
		return;
	}
	else if (!processed) {
		if (rules) {
			msg_warn ("<%s>: no content to generate fuzzy", task->message_id);
			rspamd_controller_send_error (conn_ent, 404,
				"No content to generate fuzzy for flag %d", flag);
		}
		else {
			msg_warn ("<%s>: no fuzzy rules found for flag %d", task->message_id,
				flag);
			rspamd_controller_send_error (conn_ent, 404,
				"No fuzzy rules matched for flag %d", flag);
		}
		rspamd_task_free (task, FALSE);
		return;
	}

	return;
}

static gboolean
fuzzy_controller_handler (struct rspamd_http_connection_entry *conn_ent,
	struct rspamd_http_message *msg, struct module_ctx *ctx, gint cmd)
{
	const gchar *arg;
	gchar *err_str;
	gint value = 1, flag = 0;

	/* Get size */
	arg = rspamd_http_message_find_header (msg, "Weight");
	if (arg) {
		errno = 0;
		value = strtol (arg, &err_str, 10);
		if (errno != 0 || *err_str != '\0') {
			msg_info ("error converting numeric argument %s", arg);
			value = 0;
		}
	}
	arg = rspamd_http_message_find_header (msg, "Flag");
	if (arg) {
		errno = 0;
		flag = strtol (arg, &err_str, 10);
		if (errno != 0 || *err_str != '\0') {
			msg_info ("error converting numeric argument %s", arg);
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
