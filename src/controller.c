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
#include "config.h"
#include "libserver/dynamic_cfg.h"
#include "libutil/rrd.h"
#include "libutil/map.h"
#include "libutil/map_private.h"
#include "libutil/http_private.h"
#include "libstat/stat_api.h"
#include "rspamd.h"
#include "libserver/worker_util.h"
#include "cryptobox.h"
#include "ottery.h"
#include "fuzzy_storage.h"
#include "libutil/rrd.h"
#include "unix-std.h"
#include "utlist.h"
#include <math.h>

/* 60 seconds for worker's IO */
#define DEFAULT_WORKER_IO_TIMEOUT 60000

#define DEFAULT_STATS_PATH RSPAMD_DBDIR "/stats.ucl"

/* HTTP paths */
#define PATH_AUTH "/auth"
#define PATH_SYMBOLS "/symbols"
#define PATH_ACTIONS "/actions"
#define PATH_MAPS "/maps"
#define PATH_GET_MAP "/getmap"
#define PATH_GRAPH "/graph"
#define PATH_PIE_CHART "/pie"
#define PATH_HISTORY "/history"
#define PATH_HISTORY_RESET "/historyreset"
#define PATH_LEARN_SPAM "/learnspam"
#define PATH_LEARN_HAM "/learnham"
#define PATH_SAVE_ACTIONS "/saveactions"
#define PATH_SAVE_SYMBOLS "/savesymbols"
#define PATH_SAVE_MAP "/savemap"
#define PATH_SCAN "/scan"
#define PATH_CHECK "/check"
#define PATH_STAT "/stat"
#define PATH_STAT_RESET "/statreset"
#define PATH_COUNTERS "/counters"


#define msg_err_session(...) rspamd_default_log_function(G_LOG_LEVEL_CRITICAL, \
        session->pool->tag.tagname, session->pool->tag.uid, \
        G_STRFUNC, \
        __VA_ARGS__)
#define msg_warn_session(...)   rspamd_default_log_function (G_LOG_LEVEL_WARNING, \
        session->pool->tag.tagname, session->pool->tag.uid, \
        G_STRFUNC, \
        __VA_ARGS__)
#define msg_info_session(...)   rspamd_default_log_function (G_LOG_LEVEL_INFO, \
        session->pool->tag.tagname, session->pool->tag.uid, \
        G_STRFUNC, \
        __VA_ARGS__)
#define msg_debug_session(...)  rspamd_default_log_function (G_LOG_LEVEL_DEBUG, \
        session->pool->tag.tagname, session->pool->tag.uid, \
        G_STRFUNC, \
        __VA_ARGS__)
#define msg_err_ctx(...) rspamd_default_log_function(G_LOG_LEVEL_CRITICAL, \
        "controller", ctx->cfg->cfg_pool->tag.uid, \
        G_STRFUNC, \
        __VA_ARGS__)
#define msg_warn_ctx(...)   rspamd_default_log_function (G_LOG_LEVEL_WARNING, \
        "controller", ctx->cfg->cfg_pool->tag.uid, \
        G_STRFUNC, \
        __VA_ARGS__)
#define msg_info_ctx(...)   rspamd_default_log_function (G_LOG_LEVEL_INFO, \
        "controller", ctx->cfg->cfg_pool->tag.uid, \
        G_STRFUNC, \
        __VA_ARGS__)
#define msg_debug_ctx(...)  rspamd_default_log_function (G_LOG_LEVEL_DEBUG, \
        "controller", ctx->cfg->cfg_pool->tag.uid, \
        G_STRFUNC, \
        __VA_ARGS__)

/* Graph colors */
#define COLOR_CLEAN "#58A458"
#define COLOR_PROBABLE_SPAM "#D67E7E"
#define COLOR_GREYLIST "#A0A0A0"
#define COLOR_REJECT "#CB4B4B"
#define COLOR_TOTAL "#9440ED"

const struct timeval rrd_update_time = {
		.tv_sec = 1,
		.tv_usec = 0
};

const guint64 rspamd_controller_ctx_magic = 0xf72697805e6941faULL;

extern void fuzzy_stat_command (struct rspamd_task *task);

gpointer init_controller_worker (struct rspamd_config *cfg);
void start_controller_worker (struct rspamd_worker *worker);

worker_t controller_worker = {
	"controller",                   /* Name */
	init_controller_worker,         /* Init function */
	start_controller_worker,        /* Start function */
	RSPAMD_WORKER_HAS_SOCKET | RSPAMD_WORKER_KILLABLE,
	RSPAMD_WORKER_SOCKET_TCP,       /* TCP socket */
	RSPAMD_WORKER_VER       /* Version info */
};
/*
 * Worker's context
 */
struct rspamd_controller_worker_ctx {
	guint64 magic;
	guint32 timeout;
	struct timeval io_tv;
	/* DNS resolver */
	struct rspamd_dns_resolver *resolver;
	/* Events base */
	struct event_base *ev_base;
	/* Whether we use ssl for this server */
	gboolean use_ssl;
	/* Webui password */
	gchar *password;
	/* Privilleged password */
	gchar *enable_password;
	/* Cached versions of the passwords */
	rspamd_ftok_t cached_password;
	rspamd_ftok_t cached_enable_password;
	/* HTTP server */
	struct rspamd_http_connection_router *http;
	/* Server's start time */
	time_t start_time;
	/* Main server */
	struct rspamd_main *srv;
	/* Configuration */
	struct rspamd_config *cfg;
	/* SSL cert */
	gchar *ssl_cert;
	/* SSL private key */
	gchar *ssl_key;
	/* A map of secure IP */
	const ucl_object_t *secure_ip;
	radix_compressed_t *secure_map;

	/* Static files dir */
	gchar *static_files_dir;

	/* Saved statistics path */
	gchar *saved_stats_path;

	/* Custom commands registered by plugins */
	GHashTable *custom_commands;

	/* Worker */
	struct rspamd_worker *worker;

	/* Local keypair */
	gpointer key;

	struct event *rrd_event;
	struct rspamd_rrd_file *rrd;

};

static gboolean
rspamd_is_encrypted_password (const gchar *password,
		struct rspamd_controller_pbkdf const **pbkdf)
{
	const gchar *start, *end;
	gint64 id;
	gsize size, i;
	gboolean ret = FALSE;
	const struct rspamd_controller_pbkdf *p;

	if (password[0] == '$') {
		/* Parse id */
		start = password + 1;
		end = start;
		size = 0;

		while (*end != '\0' && g_ascii_isdigit (*end)) {
			size++;
			end++;
		}

		if (size > 0) {
			gchar *endptr;
			id = strtoul (start, &endptr, 10);

			if ((endptr == NULL || *endptr == *end)) {
				for (i = 0; i < RSPAMD_PBKDF_ID_MAX - 1; i ++) {
					p = &pbkdf_list[i];

					if (p->id == id) {
						ret = TRUE;
						if (pbkdf != NULL) {
							*pbkdf = &pbkdf_list[i];
						}

						break;
					}
				}
			}
		}
	}

	return ret;
}

static const gchar *
rspamd_encrypted_password_get_str (const gchar * password, gsize skip,
		gsize * length)
{
	const gchar *str, *start, *end;
	gsize size;

	start = password + skip;
	end = start;
	size = 0;

	while (*end != '\0' && g_ascii_isalnum (*end)) {
		size++;
		end++;
	}

	if (size) {
		str = start;
		*length = size;
	}
	else {
		str = NULL;
	}

	return str;
}

static gboolean
rspamd_check_encrypted_password (struct rspamd_controller_worker_ctx *ctx,
		const rspamd_ftok_t * password, const gchar * check,
		const struct rspamd_controller_pbkdf *pbkdf,
		gboolean is_enable)
{
	const gchar *salt, *hash;
	gchar *salt_decoded, *key_decoded;
	gsize salt_len = 0, key_len = 0;
	gboolean ret = TRUE;
	guchar *local_key;
	rspamd_ftok_t *cache;
	gpointer m;

	/* First of all check cached versions to save resources */
	if (is_enable && ctx->cached_enable_password.len != 0) {
		if (password->len != ctx->cached_enable_password.len ||
				!rspamd_constant_memcmp (password->begin,
						ctx->cached_enable_password.begin, password->len)) {
			msg_info_ctx ("incorrect or absent enable password has been specified");
			return FALSE;
		}

		return TRUE;
	}
	else if (!is_enable && ctx->cached_password.len != 0) {
		if (password->len != ctx->cached_password.len ||
				!rspamd_constant_memcmp (password->begin,
						ctx->cached_password.begin, password->len)) {
			msg_info_ctx ("incorrect or absent password has been specified");
			return FALSE;
		}

		return TRUE;
	}

	g_assert (pbkdf != NULL);
	/* get salt */
	salt = rspamd_encrypted_password_get_str (check, 3, &salt_len);
	/* get hash */
	hash = rspamd_encrypted_password_get_str (check, 3 + salt_len + 1,
			&key_len);
	if (salt != NULL && hash != NULL) {

		/* decode salt */
		salt_decoded = rspamd_decode_base32 (salt, salt_len, &salt_len);

		if (salt_decoded == NULL || salt_len != pbkdf->salt_len) {
			/* We have some unknown salt here */
			msg_info_ctx ("incorrect salt: %z, while %z expected",
					salt_len, pbkdf->salt_len);
			return FALSE;
		}

		key_decoded = rspamd_decode_base32 (hash, key_len, &key_len);

		if (key_decoded == NULL || key_len != pbkdf->key_len) {
			/* We have some unknown salt here */
			msg_info_ctx ("incorrect key: %z, while %z expected",
					key_len, pbkdf->key_len);
			return FALSE;
		}

		local_key = g_alloca (pbkdf->key_len);
		rspamd_cryptobox_pbkdf (password->begin, password->len,
				salt_decoded, salt_len,
				local_key, pbkdf->key_len, pbkdf->complexity,
				pbkdf->type);

		if (!rspamd_constant_memcmp (key_decoded, local_key, pbkdf->key_len)) {
			msg_info_ctx ("incorrect or absent password has been specified");
			ret = FALSE;
		}

		g_free (salt_decoded);
		g_free (key_decoded);
	}

	if (ret) {
		/* Save cached version */
		cache = is_enable ? &ctx->cached_enable_password : &ctx->cached_password;

		if (cache->len == 0) {
			/* Mmap region */
			m = mmap (NULL, password->len, PROT_WRITE,
					MAP_PRIVATE | MAP_ANON, -1, 0);
			memcpy (m, password->begin, password->len);
			(void)mprotect (m, password->len, PROT_READ);
			(void)mlock (m, password->len);
			cache->begin = m;
			cache->len = password->len;
		}
	}

	return ret;
}

/**
 * Checks for X-Forwarded-For header and update client's address if needed
 *
 * This function is intended to be called for a trusted client to ensure that
 * a request is not proxied through it
 * @return 0 if no forwarded found, 1 if forwarded found and it is yet trusted
 * and -1 if forwarded is denied
 */
static gint
rspamd_controller_check_forwarded (struct rspamd_controller_session *session,
		struct rspamd_http_message *msg,
		struct rspamd_controller_worker_ctx *ctx)
{
	const rspamd_ftok_t *hdr;
	const gchar *comma;
	const char *hdr_name = "X-Forwarded-For", *alt_hdr_name = "X-Real-IP";
	char ip_buf[INET6_ADDRSTRLEN + 1];
	rspamd_inet_addr_t *addr = NULL;
	gint ret = 0;

	hdr = rspamd_http_message_find_header (msg, hdr_name);

	if (hdr) {
		/*
		 * We need to parse and update the header
		 * X-Forwarded-For: client, proxy1, proxy2
		 */
		comma = rspamd_memrchr (hdr->begin, ',', hdr->len);
		if (comma != NULL) {
			while (comma < hdr->begin + hdr->len &&
					(*comma == ',' || g_ascii_isspace (*comma))) {
				comma ++;
			}
		}
		else {
			comma = hdr->begin;
		}
		if (rspamd_parse_inet_address (&addr, comma,
				(hdr->begin + hdr->len) - comma)) {
			/* We have addr now, so check if it is still trusted */
			if (ctx->secure_map &&
					radix_find_compressed_addr (ctx->secure_map,
							addr) != RADIX_NO_VALUE) {
				/* rspamd_inet_address_to_string is not reentrant */
				rspamd_strlcpy (ip_buf, rspamd_inet_address_to_string (addr),
						sizeof (ip_buf));
				msg_info_session ("allow unauthorized proxied connection "
						"from a trusted IP %s via %s",
						ip_buf,
						rspamd_inet_address_to_string (session->from_addr));
				ret = 1;
			}
			else {
				ret = -1;
			}

			rspamd_inet_address_destroy (addr);
		}
		else {
			msg_warn_session ("cannot parse forwarded IP: %T", hdr);
			ret = -1;
		}
	}
	else {
		/* Try also X-Real-IP */
		hdr = rspamd_http_message_find_header (msg, alt_hdr_name);

		if (hdr) {
			if (rspamd_parse_inet_address (&addr, hdr->begin, hdr->len)) {
				/* We have addr now, so check if it is still trusted */
				if (ctx->secure_map &&
						radix_find_compressed_addr (ctx->secure_map,
								addr) != RADIX_NO_VALUE) {
					/* rspamd_inet_address_to_string is not reentrant */
					rspamd_strlcpy (ip_buf, rspamd_inet_address_to_string (addr),
							sizeof (ip_buf));
					msg_info_session ("allow unauthorized proxied connection "
							"from a trusted IP %s via %s",
							ip_buf,
							rspamd_inet_address_to_string (session->from_addr));
					ret = 1;
				}
				else {
					ret = -1;
				}

				rspamd_inet_address_destroy (addr);
			}
			else {
				msg_warn_session ("cannot parse real IP: %T", hdr);
				ret = -1;
			}
		}
	}

	return ret;
}

/* Check for password if it is required by configuration */
static gboolean rspamd_controller_check_password(
		struct rspamd_http_connection_entry *entry,
		struct rspamd_controller_session *session,
		struct rspamd_http_message *msg, gboolean is_enable)
{
	const gchar *check;
	const rspamd_ftok_t *password;
	rspamd_ftok_t lookup;
	GHashTable *query_args = NULL;
	struct rspamd_controller_worker_ctx *ctx = session->ctx;
	gboolean check_normal = TRUE, check_enable = TRUE, ret = TRUE,
		use_enable = FALSE;
	const struct rspamd_controller_pbkdf *pbkdf = NULL;

	/* Access list logic */
	if (rspamd_inet_address_get_af (session->from_addr) == AF_UNIX) {
		ret = rspamd_controller_check_forwarded (session, msg, ctx);

		if (ret == 1) {
			return TRUE;
		}
		else if (ret == 0) {
			/* No forwarded found */
			msg_info_session ("allow unauthorized connection from a unix socket");
			return TRUE;
		}
	}
	else if (ctx->secure_map
			&& radix_find_compressed_addr (ctx->secure_map, session->from_addr)
					!= RADIX_NO_VALUE) {
		ret = rspamd_controller_check_forwarded (session, msg, ctx);

		if (ret == 1) {
			return TRUE;
		}
		else if (ret == 0) {
			/* No forwarded found */
			msg_info_session ("allow unauthorized connection from a trusted IP %s",
							rspamd_inet_address_to_string (session->from_addr));
			return TRUE;
		}
	}

	/* Password logic */
	password = rspamd_http_message_find_header (msg, "Password");

	if (password == NULL) {
		/* Try to get password from query args */
		query_args = rspamd_http_message_parse_query (msg);

		lookup.begin = (gchar *)"password";
		lookup.len = sizeof ("password") - 1;

		password = g_hash_table_lookup (query_args, &lookup);
	}

	if (password == NULL) {
		if (ctx->secure_map == NULL) {
			if (ctx->password == NULL && !is_enable) {
				return TRUE;
			}
			else if (is_enable && (ctx->password == NULL &&
					ctx->enable_password == NULL)) {
				return TRUE;
			}
		}
		msg_info_session ("absent password has been specified");
		ret = FALSE;
	}
	else {
		if (is_enable) {
			/* For privileged commands we strictly require enable password */
			if (ctx->enable_password != NULL) {
				check = ctx->enable_password;
				use_enable = TRUE;
			}
			else {
				/* Use just a password (legacy mode) */
				msg_info(
						"using password as enable_password for a privileged command");
				check = ctx->password;
			}

			if (check != NULL) {
				if (!rspamd_is_encrypted_password (check, &pbkdf)) {
					ret = FALSE;

					if (strlen (check) == password->len) {
						ret = rspamd_constant_memcmp (password->begin, check,
								password->len);
					}
				}
				else {
					ret = rspamd_check_encrypted_password (ctx, password, check,
							pbkdf, use_enable);
				}
			}
			else {
				msg_warn_session (
						"no password to check while executing a privileged command");
				if (ctx->secure_map) {
					msg_info("deny unauthorized connection");
					ret = FALSE;
				}
				ret = FALSE;
			}
		}
		else {
			/* Accept both normal and enable passwords */
			if (ctx->password != NULL) {
				check = ctx->password;

				if (!rspamd_is_encrypted_password (check, &pbkdf)) {
					check_normal = FALSE;

					if (strlen (check) == password->len) {
						check_normal = rspamd_constant_memcmp (password->begin,
								check,
								password->len);
					}
				}
				else {
					check_normal = rspamd_check_encrypted_password (ctx,
							password,
							check, pbkdf, FALSE);
				}

			}
			else {
				check_normal = FALSE;
			}

			if (ctx->enable_password != NULL) {
				check = ctx->enable_password;

				if (!rspamd_is_encrypted_password (check, &pbkdf)) {
					check_enable = FALSE;

					if (strlen (check) == password->len) {
						check_enable = rspamd_constant_memcmp (password->begin,
								check,
								password->len);
					}
				}
				else {
					check_enable = rspamd_check_encrypted_password (ctx,
							password,
							check, pbkdf, TRUE);
				}
			}
			else {
				check_enable = FALSE;
			}
		}
	}

	if (query_args != NULL) {
		g_hash_table_unref (query_args);
	}

	if (check_normal == FALSE && check_enable == FALSE) {
		msg_info ("absent or incorrect password has been specified");
		ret = FALSE;
	}

	if (!ret) {
		rspamd_controller_send_error (entry, 403, "Unauthorized");
	}

	return ret;
}

/* Command handlers */

/*
 * Auth command handler:
 * request: /auth
 * headers: Password
 * reply: json {"auth": "ok", "version": "0.5.2", "uptime": "some uptime", "error": "none"}
 */
static int
rspamd_controller_handle_auth (struct rspamd_http_connection_entry *conn_ent,
	struct rspamd_http_message *msg)
{
	struct rspamd_controller_session *session = conn_ent->ud;
	struct rspamd_stat *st;
	int64_t uptime;
	gulong data[4];
	ucl_object_t *obj;

	if (!rspamd_controller_check_password (conn_ent, session, msg, FALSE)) {
		return 0;
	}

	obj = ucl_object_typed_new (UCL_OBJECT);
	st = session->ctx->srv->stat;
	data[0] = st->actions_stat[METRIC_ACTION_NOACTION];
	data[1] = st->actions_stat[METRIC_ACTION_ADD_HEADER] +
		st->actions_stat[METRIC_ACTION_REWRITE_SUBJECT];
	data[2] = st->actions_stat[METRIC_ACTION_GREYLIST];
	data[3] = st->actions_stat[METRIC_ACTION_REJECT];

	/* Get uptime */
	uptime = time (NULL) - session->ctx->start_time;

	ucl_object_insert_key (obj, ucl_object_fromstring (
			RVERSION),			   "version",  0, false);
	ucl_object_insert_key (obj, ucl_object_fromstring (
			"ok"),				   "auth",	   0, false);
	ucl_object_insert_key (obj,	   ucl_object_fromint (
			uptime),			   "uptime",   0, false);
	ucl_object_insert_key (obj,	   ucl_object_fromint (
			data[0]),			   "clean",	   0, false);
	ucl_object_insert_key (obj,	   ucl_object_fromint (
			data[1]),			   "probable", 0, false);
	ucl_object_insert_key (obj,	   ucl_object_fromint (
			data[2]),			   "greylist", 0, false);
	ucl_object_insert_key (obj,	   ucl_object_fromint (
			data[3]),			   "reject",   0, false);
	ucl_object_insert_key (obj,	   ucl_object_fromint (
			st->messages_scanned), "scanned",  0, false);
	ucl_object_insert_key (obj,	   ucl_object_fromint (
			st->messages_learned), "learned",  0, false);

	rspamd_controller_send_ucl (conn_ent, obj);
	ucl_object_unref (obj);

	return 0;
}

/*
 * Symbols command handler:
 * request: /symbols
 * reply: json [{
 *  "name": "group_name",
 *  "symbols": [
 *      {
 *      "name": "name",
 *      "weight": 0.1,
 *      "description": "description of symbol"
 *      },
 *      {...}
 * },
 * {...}]
 */
static int
rspamd_controller_handle_symbols (struct rspamd_http_connection_entry *conn_ent,
	struct rspamd_http_message *msg)
{
	struct rspamd_controller_session *session = conn_ent->ud;
	GHashTableIter it, sit;
	struct rspamd_symbols_group *gr;
	struct rspamd_symbol_def *sym;
	struct metric *metric;
	ucl_object_t *obj, *top, *sym_obj, *group_symbols;
	gpointer k, v;

	if (!rspamd_controller_check_password (conn_ent, session, msg, FALSE)) {
		return 0;
	}

	top = ucl_object_typed_new (UCL_ARRAY);

	/* Go through all symbols groups in the default metric */
	metric = g_hash_table_lookup (session->ctx->cfg->metrics, DEFAULT_METRIC);
	g_assert (metric != NULL);
	g_hash_table_iter_init (&it, metric->groups);

	while (g_hash_table_iter_next (&it, &k, &v)) {
		gr = v;
		obj = ucl_object_typed_new (UCL_OBJECT);
		ucl_object_insert_key (obj, ucl_object_fromstring (
				gr->name), "group", 0, false);
		/* Iterate through all symbols */

		g_hash_table_iter_init (&sit, gr->symbols);
		group_symbols = ucl_object_typed_new (UCL_ARRAY);

		while (g_hash_table_iter_next (&sit, &k, &v)) {
			sym = v;
			sym_obj = ucl_object_typed_new (UCL_OBJECT);

			ucl_object_insert_key (sym_obj, ucl_object_fromstring (sym->name),
				"symbol", 0, false);
			ucl_object_insert_key (sym_obj,
				ucl_object_fromdouble (*sym->weight_ptr),
				"weight", 0, false);
			if (sym->description) {
				ucl_object_insert_key (sym_obj,
					ucl_object_fromstring (sym->description),
					"description", 0, false);
			}

			ucl_array_append (group_symbols, sym_obj);
		}

		ucl_object_insert_key (obj, group_symbols, "rules", 0, false);
		ucl_array_append (top, obj);
	}

	rspamd_controller_send_ucl (conn_ent, top);
	ucl_object_unref (top);

	return 0;
}

/*
 * Actions command handler:
 * request: /actions
 * reply: json [{
 *  "action": "no action",
 *  "value": 1.1
 * },
 * {...}]
 */
static int
rspamd_controller_handle_actions (struct rspamd_http_connection_entry *conn_ent,
	struct rspamd_http_message *msg)
{
	struct rspamd_controller_session *session = conn_ent->ud;
	struct metric *metric;
	struct metric_action *act;
	gint i;
	ucl_object_t *obj, *top;

	if (!rspamd_controller_check_password (conn_ent, session, msg, FALSE)) {
		return 0;
	}

	top = ucl_object_typed_new (UCL_ARRAY);

	/* Get actions for default metric */
	metric = g_hash_table_lookup (session->ctx->cfg->metrics, DEFAULT_METRIC);
	if (metric != NULL) {
		for (i = METRIC_ACTION_REJECT; i < METRIC_ACTION_MAX; i++) {
			act = &metric->actions[i];
			if (act->score >= 0) {
				obj = ucl_object_typed_new (UCL_OBJECT);
				ucl_object_insert_key (obj,
					ucl_object_fromstring (rspamd_action_to_str (
						act->action)), "action", 0, false);
				ucl_object_insert_key (obj, ucl_object_fromdouble (
						act->score), "value", 0, false);
				ucl_array_append (top, obj);
			}
		}
	}

	rspamd_controller_send_ucl (conn_ent, top);
	ucl_object_unref (top);

	return 0;
}
/*
 * Maps command handler:
 * request: /maps
 * headers: Password
 * reply: json [
 *      {
 *      "map": "name",
 *      "description": "description",
 *      "editable": true
 *      },
 *      {...}
 * ]
 */
static int
rspamd_controller_handle_maps (struct rspamd_http_connection_entry *conn_ent,
	struct rspamd_http_message *msg)
{
	struct rspamd_controller_session *session = conn_ent->ud;
	GList *cur, *tmp = NULL;
	struct rspamd_map *map;
	struct rspamd_map_backend *bk;
	gboolean editable;
	ucl_object_t *obj, *top;

	if (!rspamd_controller_check_password (conn_ent, session, msg, FALSE)) {
		return 0;
	}

	top = ucl_object_typed_new (UCL_ARRAY);
	/* Iterate over all maps */
	cur = session->ctx->cfg->maps;
	while (cur) {
		map = cur->data;
		bk = g_ptr_array_index (map->backends, 0);

		if (bk->protocol == MAP_PROTO_FILE) {
			if (access (bk->uri, R_OK) == 0) {
				tmp = g_list_prepend (tmp, map);
			}
		}
		cur = g_list_next (cur);
	}
	/* Iterate over selected maps */
	cur = tmp;
	while (cur) {
		map = cur->data;
		bk = g_ptr_array_index (map->backends, 0);
		editable = (access (bk->uri, W_OK) == 0);

		obj = ucl_object_typed_new (UCL_OBJECT);
		ucl_object_insert_key (obj,	   ucl_object_fromint (map->id),
				"map", 0, false);
		if (map->description) {
			ucl_object_insert_key (obj, ucl_object_fromstring (map->description),
					"description", 0, false);
		}
		ucl_object_insert_key (obj, ucl_object_fromstring (bk->uri),
				"uri", 0, false);
		ucl_object_insert_key (obj,	  ucl_object_frombool (editable),
				"editable", 0, false);
		ucl_array_append (top, obj);

		cur = g_list_next (cur);
	}

	if (tmp) {
		g_list_free (tmp);
	}

	rspamd_controller_send_ucl (conn_ent, top);
	ucl_object_unref (top);

	return 0;
}

/*
 * Get map command handler:
 * request: /getmap
 * headers: Password, Map
 * reply: plain-text
 */
static int
rspamd_controller_handle_get_map (struct rspamd_http_connection_entry *conn_ent,
	struct rspamd_http_message *msg)
{
	struct rspamd_controller_session *session = conn_ent->ud;
	GList *cur;
	struct rspamd_map *map;
	struct rspamd_map_backend *bk;
	const rspamd_ftok_t *idstr;
	struct stat st;
	gint fd;
	gulong id;
	gboolean found = FALSE;
	struct rspamd_http_message *reply;

	if (!rspamd_controller_check_password (conn_ent, session, msg, FALSE)) {
		return 0;
	}

	idstr = rspamd_http_message_find_header (msg, "Map");

	if (idstr == NULL) {
		msg_info_session ("absent map id");
		rspamd_controller_send_error (conn_ent, 400, "400 id header missing");
		return 0;
	}

	if (!rspamd_strtoul (idstr->begin, idstr->len, &id)) {
		msg_info_session ("invalid map id");
		rspamd_controller_send_error (conn_ent, 400, "400 invalid map id");
		return 0;
	}

	/* Now let's be sure that we have map defined in configuration */
	cur = session->ctx->cfg->maps;
	while (cur) {
		map = cur->data;
		bk = g_ptr_array_index (map->backends, 0);
		if (map->id == id && bk->protocol == MAP_PROTO_FILE) {
			found = TRUE;
			break;
		}
		cur = g_list_next (cur);
	}

	if (!found) {
		msg_info_session ("map not found");
		rspamd_controller_send_error (conn_ent, 404, "404 map not found");
		return 0;
	}

	bk = g_ptr_array_index (map->backends, 0);

	if (stat (bk->uri, &st) == -1 || (fd = open (bk->uri, O_RDONLY)) == -1) {
		msg_err_session ("cannot open map %s: %s", bk->uri, strerror (errno));
		rspamd_controller_send_error (conn_ent, 500, "500 map open error");
		return 0;
	}

	reply = rspamd_http_new_message (HTTP_RESPONSE);
	reply->date = time (NULL);
	reply->code = 200;

	if (!rspamd_http_message_set_body_from_fd (reply, fd)) {
		close (fd);
		rspamd_http_message_unref (reply);
		msg_err_session ("cannot read map %s: %s", bk->uri, strerror (errno));
		rspamd_controller_send_error (conn_ent, 500, "500 map read error");
		return 0;
	}

	close (fd);

	rspamd_http_connection_reset (conn_ent->conn);
	rspamd_http_connection_write_message (conn_ent->conn, reply, NULL,
		"text/plain", conn_ent, conn_ent->conn->fd,
		conn_ent->rt->ptv, conn_ent->rt->ev_base);
	conn_ent->is_reply = TRUE;

	return 0;
}

static ucl_object_t *
rspamd_controller_pie_element (enum rspamd_metric_action action,
		const char *label, gdouble data)
{
	ucl_object_t *res = ucl_object_typed_new (UCL_OBJECT);
	const char *colors[METRIC_ACTION_MAX] = {
		[METRIC_ACTION_REJECT] = "#FF0000",
		[METRIC_ACTION_SOFT_REJECT] = "#cc9966",
		[METRIC_ACTION_REWRITE_SUBJECT] = "#ff6600",
		[METRIC_ACTION_ADD_HEADER] = "#FFD700",
		[METRIC_ACTION_GREYLIST] = "#436EEE",
		[METRIC_ACTION_NOACTION] = "#66cc00"
	};

	ucl_object_insert_key (res, ucl_object_fromstring (colors[action]),
			"color", 0, false);
	ucl_object_insert_key (res, ucl_object_fromstring (label), "label", 0, false);
	ucl_object_insert_key (res, ucl_object_fromdouble (data), "data", 0, false);
	ucl_object_insert_key (res, ucl_object_fromdouble (data), "value", 0, false);

	return res;
}

/*
 * Pie chart command handler:
 * request: /pie
 * headers: Password
 * reply: json [
 *      { label: "Foo", data: 11 },
 *      { label: "Bar", data: 20 },
 *      {...}
 * ]
 */
static int
rspamd_controller_handle_pie_chart (
	struct rspamd_http_connection_entry *conn_ent,
	struct rspamd_http_message *msg)
{
	struct rspamd_controller_session *session = conn_ent->ud;
	struct rspamd_controller_worker_ctx *ctx;
	gdouble data[5], total;
	ucl_object_t *top;

	ctx = session->ctx;

	if (!rspamd_controller_check_password (conn_ent, session, msg, FALSE)) {
		return 0;
	}

	top = ucl_object_typed_new (UCL_ARRAY);
	total = ctx->srv->stat->messages_scanned;
	if (total != 0) {

		data[0] = ctx->srv->stat->actions_stat[METRIC_ACTION_NOACTION];
		data[1] = ctx->srv->stat->actions_stat[METRIC_ACTION_SOFT_REJECT];
		data[2] = (ctx->srv->stat->actions_stat[METRIC_ACTION_ADD_HEADER] +
			ctx->srv->stat->actions_stat[METRIC_ACTION_REWRITE_SUBJECT]);
		data[3] = ctx->srv->stat->actions_stat[METRIC_ACTION_GREYLIST];
		data[4] = ctx->srv->stat->actions_stat[METRIC_ACTION_REJECT];
	}
	else {
		memset (data, 0, sizeof (data));
	}
	ucl_array_append (top, rspamd_controller_pie_element (
			METRIC_ACTION_NOACTION, "Clean", data[0]));
	ucl_array_append (top, rspamd_controller_pie_element (
			METRIC_ACTION_SOFT_REJECT, "Temporary rejected", data[1]));
	ucl_array_append (top, rspamd_controller_pie_element (
			METRIC_ACTION_ADD_HEADER, "Probable spam", data[2]));
	ucl_array_append (top, rspamd_controller_pie_element (
			METRIC_ACTION_GREYLIST, "Greylisted", data[3]));
	ucl_array_append (top, rspamd_controller_pie_element (
			METRIC_ACTION_REJECT, "Rejected", data[4]));

	rspamd_controller_send_ucl (conn_ent, top);
	ucl_object_unref (top);

	return 0;
}

void
rspamd_controller_graph_point (gulong t, gulong step,
		struct rspamd_rrd_query_result* rrd_result,
		gdouble *acc,
		ucl_object_t **elt)
{
	guint nan_cnt;
	gdouble sum = 0.0, yval;
	ucl_object_t* data_elt;
	guint i, j;

	for (i = 0; i < rrd_result->ds_count; i++) {
		sum = 0.0;
		nan_cnt = 0;
		data_elt = ucl_object_typed_new (UCL_OBJECT);
		ucl_object_insert_key (data_elt, ucl_object_fromint (t), "x", 1, false);

		for (j = 0; j < step; j++) {
			yval = acc[i + j * rrd_result->ds_count];
			if (isnan (yval)) {
				nan_cnt++;
			}
			else {
				sum += yval;
			}
		}
		if (nan_cnt == step) {
			ucl_object_insert_key (data_elt, ucl_object_typed_new (UCL_NULL),
					"y", 1, false);
		}
		else {
			ucl_object_insert_key (data_elt,
					ucl_object_fromdouble (sum / (gdouble) step), "y", 1,
					false);
		}
		ucl_array_append (elt[i], data_elt);
	}
}

/*
 * Graph command handler:
 * request: /graph?type=<hourly|daily|weekly|monthly>
 * headers: Password
 * reply: json [
 *      { label: "Foo", data: 11 },
 *      { label: "Bar", data: 20 },
 *      {...}
 * ]
 */
static int
rspamd_controller_handle_graph (
		struct rspamd_http_connection_entry *conn_ent,
		struct rspamd_http_message *msg)
{
	GHashTable *query;
	struct rspamd_controller_session *session = conn_ent->ud;
	struct rspamd_controller_worker_ctx *ctx;
	rspamd_ftok_t srch, *value;
	struct rspamd_rrd_query_result *rrd_result;
	gulong i, k, start_row, cnt, t, ts, step;
	gdouble *acc;
	ucl_object_t *res, *elt[4];
	enum {
		rra_hourly = 0,
		rra_daily,
		rra_weekly,
		rra_monthly,
		rra_invalid
	} rra_num = rra_invalid;
	/* How many points are we going to send to display */
	static const guint desired_points = 500;

	ctx = session->ctx;

	if (!rspamd_controller_check_password (conn_ent, session, msg, FALSE)) {
		return 0;
	}

	if (ctx->rrd == NULL) {
		msg_err_session ("no rrd configured");
		rspamd_controller_send_error (conn_ent, 404, "no rrd configured for graphs");

		return 0;
	}

	query = rspamd_http_message_parse_query (msg);
	srch.begin = (gchar *)"type";
	srch.len = 4;

	if (query == NULL || (value = g_hash_table_lookup (query, &srch)) == NULL) {
		msg_err_session ("absent graph type query");
		rspamd_controller_send_error (conn_ent, 400, "absent graph type");

		if (query) {
			g_hash_table_unref (query);
		}

		return 0;
	}

	if (value->len == 6 && rspamd_lc_cmp (value->begin, "hourly", value->len) == 0) {
		rra_num = rra_hourly;
	}
	else if (value->len == 5 && rspamd_lc_cmp (value->begin, "daily", value->len) == 0) {
		rra_num = rra_daily;
	}
	else if (value->len == 6 && rspamd_lc_cmp (value->begin, "weekly", value->len) == 0) {
		rra_num = rra_weekly;
	}
	else if (value->len == 7 && rspamd_lc_cmp (value->begin, "monthly", value->len) == 0) {
		rra_num = rra_monthly;
	}

	g_hash_table_unref (query);

	if (rra_num == rra_invalid) {
		msg_err_session ("invalid graph type query");
		rspamd_controller_send_error (conn_ent, 400, "invalid graph type");

		return 0;
	}

	rrd_result = rspamd_rrd_query (ctx->rrd, rra_num);

	if (rrd_result == NULL) {
		msg_err_session ("cannot query rrd");
		rspamd_controller_send_error (conn_ent, 500, "cannot query rrd");

		return 0;
	}

	g_assert (rrd_result->ds_count == G_N_ELEMENTS (elt));

	res = ucl_object_typed_new (UCL_ARRAY);
	/* How much full updates happened since the last update */
	ts = rrd_result->last_update / rrd_result->pdp_per_cdp - rrd_result->rra_rows;

	for (i = 0; i < rrd_result->ds_count; i ++) {
		elt[i] = ucl_object_typed_new (UCL_ARRAY);
	}

	start_row = rrd_result->cur_row == rrd_result->rra_rows - 1 ?
				0 : rrd_result->cur_row;
	t = ts * rrd_result->pdp_per_cdp;
	k = 0;

	/* Create window */
	step = (rrd_result->rra_rows / desired_points + 0.5);
	g_assert (step >= 1);
	acc = g_malloc0 (sizeof (double) * rrd_result->ds_count * step);

	for (i = start_row, cnt = 0; cnt < rrd_result->rra_rows;
			cnt ++) {

		memcpy (&acc[k * rrd_result->ds_count],
				&rrd_result->data[i * rrd_result->ds_count],
				sizeof (gdouble) * rrd_result->ds_count);

		if (k < step - 1) {
			k ++;
		}
		else {
			t = ts * rrd_result->pdp_per_cdp;

			/* Need a fresh point */
			rspamd_controller_graph_point (t, step, rrd_result, acc, elt);
			k = 0;
		}

		if (i == rrd_result->rra_rows - 1) {
			i = 0;
		}
		else {
			i ++;
		}

		ts ++;
	}

	if (k > 0) {
		rspamd_controller_graph_point (t, k, rrd_result, acc, elt);
	}

	for (i = 0; i < rrd_result->ds_count; i++) {
		ucl_array_append (res, elt[i]);
	}

	rspamd_controller_send_ucl (conn_ent, res);
	ucl_object_unref (res);
	g_free (acc);

	return 0;
}

/*
 * History command handler:
 * request: /history
 * headers: Password
 * reply: json [
 *      { label: "Foo", data: 11 },
 *      { label: "Bar", data: 20 },
 *      {...}
 * ]
 */
static int
rspamd_controller_handle_history (struct rspamd_http_connection_entry *conn_ent,
	struct rspamd_http_message *msg)
{
	struct rspamd_controller_session *session = conn_ent->ud;
	struct rspamd_controller_worker_ctx *ctx;
	struct roll_history_row *row, *copied_rows;
	guint i, rows_proc, row_num;
	struct tm *tm;
	gchar timebuf[32];
	ucl_object_t *top, *obj;

	ctx = session->ctx;

	if (!rspamd_controller_check_password (conn_ent, session, msg, FALSE)) {
		return 0;
	}

	top = ucl_object_typed_new (UCL_ARRAY);

	/* Set lock on history */
	copied_rows = g_slice_alloc (sizeof (*copied_rows) * ctx->srv->history->nrows);
	memcpy (copied_rows, ctx->srv->history->rows,
			sizeof (*copied_rows) * ctx->srv->history->nrows);

	/* Go through all rows */
	row_num = ctx->srv->history->cur_row;

	for (i = 0, rows_proc = 0; i < ctx->srv->history->nrows; i++, row_num++) {
		if (row_num == ctx->srv->history->nrows) {
			row_num = 0;
		}
		row = &copied_rows[row_num];
		/* Get only completed rows */
		if (row->completed) {
			tm = localtime (&row->tv.tv_sec);
			strftime (timebuf, sizeof (timebuf) - 1, "%Y-%m-%d %H:%M:%S", tm);
			obj = ucl_object_typed_new (UCL_OBJECT);
			ucl_object_insert_key (obj, ucl_object_fromstring (
					timebuf),		  "time", 0, false);
			ucl_object_insert_key (obj, ucl_object_fromint (
					row->tv.tv_sec), "unix_time", 0, false);
			ucl_object_insert_key (obj, ucl_object_fromstring (
					row->message_id), "id",	  0, false);
			ucl_object_insert_key (obj, ucl_object_fromstring (row->from_addr),
					"ip", 0, false);
			ucl_object_insert_key (obj,
				ucl_object_fromstring (rspamd_action_to_str (
					row->action)), "action", 0, false);

			if (!isnan (row->score)) {
				ucl_object_insert_key (obj, ucl_object_fromdouble (
						row->score),		  "score",			0, false);
			}
			else {
				ucl_object_insert_key (obj,
						ucl_object_fromdouble (0.0), "score", 0, false);
			}

			if (!isnan (row->required_score)) {
				ucl_object_insert_key (obj,
						ucl_object_fromdouble (
								row->required_score), "required_score", 0, false);
			}
			else {
				ucl_object_insert_key (obj,
						ucl_object_fromdouble (0.0), "required_score", 0, false);
			}

			ucl_object_insert_key (obj, ucl_object_fromstring (
					row->symbols),		  "symbols",		0, false);
			ucl_object_insert_key (obj,	   ucl_object_fromint (
					row->len),			  "size",			0, false);
			ucl_object_insert_key (obj,	   ucl_object_fromdouble (
					row->scan_time),	  "scan_time",		0, false);
			if (row->user[0] != '\0') {
				ucl_object_insert_key (obj, ucl_object_fromstring (
						row->user), "user", 0, false);
			}
			if (row->from_addr[0] != '\0') {
				ucl_object_insert_key (obj, ucl_object_fromstring (
						row->from_addr), "from", 0, false);
			}
			ucl_array_append (top, obj);
			rows_proc++;
		}
	}

	rspamd_controller_send_ucl (conn_ent, top);
	ucl_object_unref (top);

	return 0;
}

static int
rspamd_controller_handle_history_reset (struct rspamd_http_connection_entry *conn_ent,
		struct rspamd_http_message *msg)
{
	struct rspamd_controller_session *session = conn_ent->ud;
	struct rspamd_controller_worker_ctx *ctx;
	struct roll_history_row *row;
	guint start_row, i, t;

	ctx = session->ctx;

	if (!rspamd_controller_check_password (conn_ent, session, msg, TRUE)) {
		return 0;
	}

	/* Clean from start to the current row */
	start_row = g_atomic_int_get (&ctx->srv->history->cur_row);

	for (i = 0; i < start_row; i ++) {
		t = g_atomic_int_get (&ctx->srv->history->cur_row);

		/* We somehow come to the race condition */
		if (i >= t) {
			break;
		}

		row = &ctx->srv->history->rows[i];
		memset (row, 0, sizeof (*row));
	}

	start_row = g_atomic_int_get (&ctx->srv->history->cur_row);
	/* Optimistically set all bytes to zero (might cause race) */
	memset (ctx->srv->history->rows,
			0,
			sizeof (*row) * (ctx->srv->history->nrows - start_row));

	msg_info_session ("<%s> reseted history",
			rspamd_inet_address_to_string (session->from_addr));
	rspamd_controller_send_string (conn_ent, "{\"success\":true}");

	return 0;
}

static gboolean
rspamd_controller_learn_fin_task (void *ud)
{
	struct rspamd_task *task = ud;
	struct rspamd_controller_session *session;
	struct rspamd_http_connection_entry *conn_ent;

	conn_ent = task->fin_arg;
	session = conn_ent->ud;

	if (task->err != NULL) {
		msg_info_session ("cannot learn <%s>: %e", task->message_id, task->err);
		rspamd_controller_send_error (conn_ent, task->err->code,
				task->err->message);

		return TRUE;
	}

	if (RSPAMD_TASK_IS_PROCESSED (task)) {
		/* Successful learn */
		msg_info_session ("<%s> learned message as %s: %s",
				rspamd_inet_address_to_string (session->from_addr),
				session->is_spam ? "spam" : "ham",
						task->message_id);
		rspamd_controller_send_string (conn_ent, "{\"success\":true}");
		return TRUE;
	}

	if (!rspamd_task_process (task, RSPAMD_TASK_PROCESS_LEARN)) {
		msg_info_session ("cannot learn <%s>: %e", task->message_id, task->err);

		if (task->err) {
			rspamd_controller_send_error (conn_ent, task->err->code,
					task->err->message);
		}
		else {
			rspamd_controller_send_error (conn_ent, 500,
								"Internal error");
		}
	}

	if (RSPAMD_TASK_IS_PROCESSED (task)) {
		if (task->err) {
			rspamd_controller_send_error (conn_ent, task->err->code,
					task->err->message);
		}
		else {
			msg_info_session ("<%s> learned message as %s: %s",
					rspamd_inet_address_to_string (session->from_addr),
					session->is_spam ? "spam" : "ham",
							task->message_id);
			rspamd_controller_send_string (conn_ent, "{\"success\":true}");
		}

		return TRUE;
	}

	/* One more iteration */
	return FALSE;
}

static void
rspamd_controller_scan_reply (struct rspamd_task *task)
{
	struct rspamd_http_message *msg;
	struct rspamd_http_connection_entry *conn_ent = task->fin_arg;

	conn_ent = task->fin_arg;
	msg = rspamd_http_new_message (HTTP_RESPONSE);
	msg->date = time (NULL);
	msg->code = 200;
	rspamd_protocol_http_reply (msg, task);
	rspamd_http_connection_reset (conn_ent->conn);
	rspamd_http_connection_write_message (conn_ent->conn, msg, NULL,
			"application/json", conn_ent, conn_ent->conn->fd, conn_ent->rt->ptv,
			conn_ent->rt->ev_base);
	conn_ent->is_reply = TRUE;
}

static gboolean
rspamd_controller_check_fin_task (void *ud)
{
	struct rspamd_task *task = ud;

	msg_debug_task ("finish task");

	if (RSPAMD_TASK_IS_PROCESSED (task)) {
		rspamd_controller_scan_reply (task);
		return TRUE;
	}

	if (!rspamd_task_process (task, RSPAMD_TASK_PROCESS_ALL)) {
		rspamd_controller_scan_reply (task);
		return TRUE;
	}

	if (RSPAMD_TASK_IS_PROCESSED (task)) {
		rspamd_controller_scan_reply (task);
		return TRUE;
	}

	/* One more iteration */
	return FALSE;
}

static int
rspamd_controller_handle_learn_common (
	struct rspamd_http_connection_entry *conn_ent,
	struct rspamd_http_message *msg,
	gboolean is_spam)
{
	struct rspamd_controller_session *session = conn_ent->ud;
	struct rspamd_controller_worker_ctx *ctx;
	struct rspamd_task *task;
	const rspamd_ftok_t *cl_header;

	ctx = session->ctx;

	if (!rspamd_controller_check_password (conn_ent, session, msg, TRUE)) {
		return 0;
	}

	if (rspamd_http_message_get_body (msg, NULL) == NULL) {
		msg_err_session ("got zero length body, cannot continue");
		rspamd_controller_send_error (conn_ent,
			400,
			"Empty body is not permitted");
		return 0;
	}

	task = rspamd_task_new (session->ctx->worker, session->cfg);

	task->resolver = ctx->resolver;
	task->ev_base = ctx->ev_base;


	task->s = rspamd_session_create (session->pool,
			rspamd_controller_learn_fin_task,
			NULL,
			(event_finalizer_t )rspamd_task_free,
			task);
	task->fin_arg = conn_ent;
	task->http_conn = rspamd_http_connection_ref (conn_ent->conn);;
	task->sock = -1;
	session->task = task;

	cl_header = rspamd_http_message_find_header (msg, "classifier");
	if (cl_header) {
		session->classifier = rspamd_mempool_ftokdup (session->pool, cl_header);
	}
	else {
		session->classifier = NULL;
	}

	if (!rspamd_task_load_message (task, msg, msg->body_buf.begin, msg->body_buf.len)) {
		rspamd_controller_send_error (conn_ent, task->err->code, task->err->message);
		return 0;
	}

	rspamd_learn_task_spam (task, is_spam, session->classifier, NULL);

	if (!rspamd_task_process (task, RSPAMD_TASK_PROCESS_LEARN)) {
		msg_warn_session ("<%s> message cannot be processed", task->message_id);
		rspamd_controller_send_error (conn_ent, task->err->code, task->err->message);
		return 0;
	}

	session->is_spam = is_spam;
	rspamd_session_pending (task->s);

	return 0;
}

/*
 * Learn spam command handler:
 * request: /learnspam
 * headers: Password
 * input: plaintext data
 * reply: json {"success":true} or {"error":"error message"}
 */
static int
rspamd_controller_handle_learnspam (
	struct rspamd_http_connection_entry *conn_ent,
	struct rspamd_http_message *msg)
{
	return rspamd_controller_handle_learn_common (conn_ent, msg, TRUE);
}
/*
 * Learn ham command handler:
 * request: /learnham
 * headers: Password
 * input: plaintext data
 * reply: json {"success":true} or {"error":"error message"}
 */
static int
rspamd_controller_handle_learnham (
	struct rspamd_http_connection_entry *conn_ent,
	struct rspamd_http_message *msg)
{
	return rspamd_controller_handle_learn_common (conn_ent, msg, FALSE);
}

/*
 * Scan command handler:
 * request: /scan
 * headers: Password
 * input: plaintext data
 * reply: json {scan data} or {"error":"error message"}
 */
static int
rspamd_controller_handle_scan (struct rspamd_http_connection_entry *conn_ent,
	struct rspamd_http_message *msg)
{
	struct rspamd_controller_session *session = conn_ent->ud;
	struct rspamd_controller_worker_ctx *ctx;
	struct rspamd_task *task;

	ctx = session->ctx;

	if (!rspamd_controller_check_password (conn_ent, session, msg, FALSE)) {
		return 0;
	}

	if (rspamd_http_message_get_body (msg, NULL) == NULL) {
		msg_err_session ("got zero length body, cannot continue");
		rspamd_controller_send_error (conn_ent,
			400,
			"Empty body is not permitted");
		return 0;
	}

	task = rspamd_task_new (session->ctx->worker, session->cfg);
	task->ev_base = session->ctx->ev_base;

	task->resolver = ctx->resolver;
	task->ev_base = ctx->ev_base;

	task->s = rspamd_session_create (session->pool,
			rspamd_controller_check_fin_task,
			NULL,
			(event_finalizer_t )rspamd_task_free,
			task);
	task->fin_arg = conn_ent;
	task->http_conn = rspamd_http_connection_ref (conn_ent->conn);
	task->sock = conn_ent->conn->fd;
	task->flags |= RSPAMD_TASK_FLAG_MIME;
	task->resolver = ctx->resolver;

	if (!rspamd_task_load_message (task, msg, msg->body_buf.begin, msg->body_buf.len)) {
		rspamd_controller_send_error (conn_ent, task->err->code, task->err->message);
		rspamd_session_destroy (task->s);
		return 0;
	}

	if (!rspamd_task_process (task, RSPAMD_TASK_PROCESS_ALL)) {
		msg_warn_session ("message cannot be processed for %s", task->message_id);
		rspamd_controller_send_error (conn_ent, task->err->code, task->err->message);
		rspamd_session_destroy (task->s);
		return 0;
	}

	session->task = task;
	rspamd_session_pending (task->s);

	return 0;
}

/*
 * Save actions command handler:
 * request: /saveactions
 * headers: Password
 * input: json array [<spam>,<probable spam>,<greylist>]
 * reply: json {"success":true} or {"error":"error message"}
 */
static int
rspamd_controller_handle_saveactions (
	struct rspamd_http_connection_entry *conn_ent,
	struct rspamd_http_message *msg)
{
	struct rspamd_controller_session *session = conn_ent->ud;
	struct ucl_parser *parser;
	struct metric *metric;
	ucl_object_t *obj;
	const ucl_object_t *cur;
	struct rspamd_controller_worker_ctx *ctx;
	const gchar *error;
	gdouble score;
	gint i, added = 0;
	enum rspamd_metric_action act;
	ucl_object_iter_t it = NULL;

	ctx = session->ctx;

	if (!rspamd_controller_check_password (conn_ent, session, msg, TRUE)) {
		return 0;
	}

	if (rspamd_http_message_get_body (msg, NULL) == NULL) {
		msg_err_session ("got zero length body, cannot continue");
		rspamd_controller_send_error (conn_ent,
			400,
			"Empty body is not permitted");
		return 0;
	}

	metric = g_hash_table_lookup (ctx->cfg->metrics, DEFAULT_METRIC);
	if (metric == NULL) {
		msg_err_session ("cannot find default metric");
		rspamd_controller_send_error (conn_ent, 500,
			"Default metric is absent");
		return 0;
	}

	/* Now check for dynamic config */
	if (!ctx->cfg->dynamic_conf) {
		msg_err_session ("dynamic conf has not been defined");
		rspamd_controller_send_error (conn_ent,
			500,
			"No dynamic_rules setting defined");
		return 0;
	}

	parser = ucl_parser_new (0);
	ucl_parser_add_chunk (parser, msg->body_buf.begin, msg->body_buf.len);

	if ((error = ucl_parser_get_error (parser)) != NULL) {
		msg_err_session ("cannot parse input: %s", error);
		rspamd_controller_send_error (conn_ent, 400, "Cannot parse input");
		ucl_parser_free (parser);
		return 0;
	}

	obj = ucl_parser_get_object (parser);
	ucl_parser_free (parser);

	if (obj->type != UCL_ARRAY || obj->len != 3) {
		msg_err_session ("input is not an array of 3 elements");
		rspamd_controller_send_error (conn_ent, 400, "Cannot parse input");
		ucl_object_unref (obj);
		return 0;
	}

	for (i = 0; i < 3; i++) {
		cur = ucl_object_iterate (obj, &it, TRUE);
		if (cur == NULL) {
			break;
		}
		switch (i) {
		case 0:
			act = METRIC_ACTION_REJECT;
			break;
		case 1:
			act = METRIC_ACTION_ADD_HEADER;
			break;
		case 2:
			act = METRIC_ACTION_GREYLIST;
			break;
		}
		score = ucl_object_todouble (cur);
		if (metric->actions[act].score != score) {
			add_dynamic_action (ctx->cfg, DEFAULT_METRIC, act, score);
			added ++;
		}
		else {
			if (remove_dynamic_action (ctx->cfg, DEFAULT_METRIC, act)) {
				added ++;
			}
		}
	}

	if (dump_dynamic_config (ctx->cfg)) {
		msg_info_session ("<%s> modified %d actions",
			rspamd_inet_address_to_string (session->from_addr),
			added);

		rspamd_controller_send_string (conn_ent, "{\"success\":true}");
	}
	else {
		rspamd_controller_send_error (conn_ent, 500, "Save error");
	}

	ucl_object_unref (obj);

	return 0;
}

/*
 * Save symbols command handler:
 * request: /savesymbols
 * headers: Password
 * input: json data
 * reply: json {"success":true} or {"error":"error message"}
 */
static int
rspamd_controller_handle_savesymbols (
	struct rspamd_http_connection_entry *conn_ent,
	struct rspamd_http_message *msg)
{
	struct rspamd_controller_session *session = conn_ent->ud;
	struct ucl_parser *parser;
	struct metric *metric;
	ucl_object_t *obj;
	const ucl_object_t *cur, *jname, *jvalue;
	ucl_object_iter_t iter = NULL;
	struct rspamd_controller_worker_ctx *ctx;
	const gchar *error;
	gdouble val;
	struct rspamd_symbol_def *sym;
	int added = 0;

	ctx = session->ctx;

	if (!rspamd_controller_check_password (conn_ent, session, msg, TRUE)) {
		return 0;
	}

	if (rspamd_http_message_get_body (msg, NULL) == NULL) {
		msg_err_session ("got zero length body, cannot continue");
		rspamd_controller_send_error (conn_ent,
			400,
			"Empty body is not permitted");
		return 0;
	}

	metric = g_hash_table_lookup (ctx->cfg->metrics, DEFAULT_METRIC);
	if (metric == NULL) {
		msg_err_session ("cannot find default metric");
		rspamd_controller_send_error (conn_ent, 500,
			"Default metric is absent");
		return 0;
	}

	/* Now check for dynamic config */
	if (!ctx->cfg->dynamic_conf) {
		msg_err_session ("dynamic conf has not been defined");
		rspamd_controller_send_error (conn_ent,
			500,
			"No dynamic_rules setting defined");
		return 0;
	}

	parser = ucl_parser_new (0);
	ucl_parser_add_chunk (parser, msg->body_buf.begin, msg->body_buf.len);

	if ((error = ucl_parser_get_error (parser)) != NULL) {
		msg_err_session ("cannot parse input: %s", error);
		rspamd_controller_send_error (conn_ent, 400, "Cannot parse input");
		ucl_parser_free (parser);
		return 0;
	}

	obj = ucl_parser_get_object (parser);
	ucl_parser_free (parser);

	if (obj->type != UCL_ARRAY) {
		msg_err_session ("input is not an array");
		rspamd_controller_send_error (conn_ent, 400, "Cannot parse input");
		ucl_object_unref (obj);
		return 0;
	}

	while ((cur = ucl_object_iterate (obj, &iter, true))) {
		if (cur->type != UCL_OBJECT) {
			msg_err_session ("json array data error");
			rspamd_controller_send_error (conn_ent, 400, "Cannot parse input");
			ucl_object_unref (obj);
			return 0;
		}
		jname = ucl_object_lookup (cur, "name");
		jvalue = ucl_object_lookup (cur, "value");
		val = ucl_object_todouble (jvalue);
		sym =
			g_hash_table_lookup (metric->symbols, ucl_object_tostring (jname));
		if (sym && fabs (*sym->weight_ptr - val) > 0.01) {
			if (!add_dynamic_symbol (ctx->cfg, DEFAULT_METRIC,
				ucl_object_tostring (jname), val)) {
				msg_err_session ("add symbol failed for %s",
					ucl_object_tostring (jname));
				rspamd_controller_send_error (conn_ent, 506,
					"Add symbol failed");
				ucl_object_unref (obj);
				return 0;
			}
			added ++;
		}
		else if (sym) {
			if (remove_dynamic_symbol (ctx->cfg, DEFAULT_METRIC,
					ucl_object_tostring (jname))) {
				added ++;
			}
		}
	}

	if (added > 0) {
		if (dump_dynamic_config (ctx->cfg)) {
			msg_info_session ("<%s> modified %d symbols",
					rspamd_inet_address_to_string (session->from_addr),
					added);

			rspamd_controller_send_string (conn_ent, "{\"success\":true}");
		}
		else {
			rspamd_controller_send_error (conn_ent, 500, "Save error");
		}
	}
	else {
		msg_err_session ("no symbols to save");
		rspamd_controller_send_error (conn_ent, 404, "No symbols to save");
	}

	ucl_object_unref (obj);

	return 0;
}

/*
 * Save map command handler:
 * request: /savemap
 * headers: Password, Map
 * input: plaintext data
 * reply: json {"success":true} or {"error":"error message"}
 */
static int
rspamd_controller_handle_savemap (struct rspamd_http_connection_entry *conn_ent,
	struct rspamd_http_message *msg)
{
	struct rspamd_controller_session *session = conn_ent->ud;
	GList *cur;
	struct rspamd_map *map;
	struct rspamd_map_backend *bk;
	struct rspamd_controller_worker_ctx *ctx;
	const rspamd_ftok_t *idstr;
	gulong id;
	gboolean found = FALSE;
	gint fd;

	ctx = session->ctx;

	if (!rspamd_controller_check_password (conn_ent, session, msg, TRUE)) {
		return 0;
	}

	if (rspamd_http_message_get_body (msg, NULL) == NULL) {
		msg_err_session ("got zero length body, cannot continue");
		rspamd_controller_send_error (conn_ent,
			400,
			"Empty body is not permitted");
		return 0;
	}

	idstr = rspamd_http_message_find_header (msg, "Map");

	if (idstr == NULL) {
		msg_info_session ("absent map id");
		rspamd_controller_send_error (conn_ent, 400, "Map id not specified");
		return 0;
	}

	if (!rspamd_strtoul (idstr->begin, idstr->len, &id)) {
		msg_info_session ("invalid map id: %T", idstr);
		rspamd_controller_send_error (conn_ent, 400, "Map id is invalid");
		return 0;
	}

	/* Now let's be sure that we have map defined in configuration */
	cur = ctx->cfg->maps;
	while (cur) {
		map = cur->data;
		bk = g_ptr_array_index (map->backends, 0);
		if (map->id == id && bk->protocol == MAP_PROTO_FILE) {
			found = TRUE;
			break;
		}
		cur = g_list_next (cur);
	}

	if (!found) {
		msg_info_session ("map not found: %L", id);
		rspamd_controller_send_error (conn_ent, 404, "Map id not found");
		return 0;
	}

	bk = g_ptr_array_index (map->backends, 0);
	if (g_atomic_int_compare_and_exchange (map->locked, 0, 1)) {
		msg_info_session ("map locked: %s", bk->uri);
		rspamd_controller_send_error (conn_ent, 404, "Map is locked");
		return 0;
	}

	/* Set lock */
	fd = open (bk->uri, O_WRONLY | O_TRUNC);
	if (fd == -1) {
		g_atomic_int_set (map->locked, 0);
		msg_info_session ("map %s open error: %s", bk->uri, strerror (errno));
		rspamd_controller_send_error (conn_ent, 404, "Map id not found");
		return 0;
	}

	if (write (fd, msg->body_buf.begin, msg->body_buf.len) == -1) {
		msg_info_session ("map %s write error: %s", bk->uri, strerror (errno));
		close (fd);
		g_atomic_int_set (map->locked, 0);
		rspamd_controller_send_error (conn_ent, 500, "Map write error");
		return 0;
	}

	msg_info_session ("<%s>, map %s saved",
		rspamd_inet_address_to_string (session->from_addr),
		bk->uri);
	/* Close and unlock */
	close (fd);
	g_atomic_int_set (map->locked, 0);

	rspamd_controller_send_string (conn_ent, "{\"success\":true}");

	return 0;
}

struct rspamd_stat_cbdata {
	struct rspamd_http_connection_entry *conn_ent;
	ucl_object_t *top;
	ucl_object_t *stat;
	struct rspamd_task *task;
	guint64 learned;
};

static gboolean
rspamd_controller_stat_fin_task (void *ud)
{
	struct rspamd_stat_cbdata *cbdata = ud;
	struct rspamd_http_connection_entry *conn_ent;
	ucl_object_t *top, *ar;
	GList *fuzzy_elts, *cur;
	struct rspamd_fuzzy_stat_entry *entry;

	conn_ent = cbdata->conn_ent;
	top = cbdata->top;

	ucl_object_insert_key (top,
			ucl_object_fromint (cbdata->learned), "total_learns", 0, false);

	if (cbdata->stat) {
		ucl_object_insert_key (top, cbdata->stat, "statfiles", 0, false);
	}

	fuzzy_elts = rspamd_mempool_get_variable (cbdata->task->task_pool, "fuzzy_stat");

	if (fuzzy_elts) {
		ar = ucl_object_typed_new (UCL_OBJECT);

		for (cur = fuzzy_elts; cur != NULL; cur = g_list_next (cur)) {
			entry = cur->data;

			if (entry->name) {
				ucl_object_insert_key (ar, ucl_object_fromint (entry->fuzzy_cnt),
						entry->name, 0, true);
			}
		}

		ucl_object_insert_key (top, ar, "fuzzy_hashes", 0, false);
	}

	rspamd_controller_send_ucl (conn_ent, top);


	return TRUE;
}

static void
rspamd_controller_stat_cleanup_task (void *ud)
{
	struct rspamd_stat_cbdata *cbdata = ud;

	rspamd_task_free (cbdata->task);
	ucl_object_unref (cbdata->top);
}

/*
 * Stat command handler:
 * request: /stat (/resetstat)
 * headers: Password
 * reply: json data
 */
static int
rspamd_controller_handle_stat_common (
	struct rspamd_http_connection_entry *conn_ent,
	struct rspamd_http_message *msg,
	gboolean do_reset)
{
	struct rspamd_controller_session *session = conn_ent->ud;
	ucl_object_t *top, *sub;
	gint i;
	guint64 spam = 0, ham = 0;
	rspamd_mempool_stat_t mem_st;
	struct rspamd_stat *stat, stat_copy;
	struct rspamd_controller_worker_ctx *ctx;
	struct rspamd_task *task;
	struct rspamd_stat_cbdata *cbdata;

	memset (&mem_st, 0, sizeof (mem_st));
	rspamd_mempool_stat (&mem_st);
	memcpy (&stat_copy, session->ctx->worker->srv->stat, sizeof (stat_copy));
	stat = &stat_copy;
	task = rspamd_task_new (session->ctx->worker, session->cfg);

	ctx = session->ctx;
	task->resolver = ctx->resolver;
	task->ev_base = ctx->ev_base;
	cbdata = rspamd_mempool_alloc0 (session->pool, sizeof (*cbdata));
	cbdata->conn_ent = conn_ent;
	cbdata->task = task;
	top = ucl_object_typed_new (UCL_OBJECT);
	cbdata->top = top;

	task->s = rspamd_session_create (session->pool,
			rspamd_controller_stat_fin_task,
			NULL,
			rspamd_controller_stat_cleanup_task,
			cbdata);
	task->fin_arg = cbdata;
	task->http_conn = rspamd_http_connection_ref (conn_ent->conn);;
	task->sock = conn_ent->conn->fd;

	ucl_object_insert_key (top, ucl_object_fromint (
			stat->messages_scanned), "scanned", 0, false);
	ucl_object_insert_key (top, ucl_object_fromint (
			stat->messages_learned), "learned", 0, false);

	if (stat->messages_scanned > 0) {
		sub = ucl_object_typed_new (UCL_OBJECT);
		for (i = METRIC_ACTION_REJECT; i <= METRIC_ACTION_NOACTION; i++) {
			ucl_object_insert_key (sub,
				ucl_object_fromint (stat->actions_stat[i]),
				rspamd_action_to_str (i), 0, false);
			if (i < METRIC_ACTION_GREYLIST) {
				spam += stat->actions_stat[i];
			}
			else {
				ham += stat->actions_stat[i];
			}
			if (do_reset) {
#ifndef HAVE_ATOMIC_BUILTINS
				session->ctx->worker->srv->stat->actions_stat[i] = 0;
#else
				__atomic_store_n(&session->ctx->worker->srv->stat->actions_stat[i],
						0, __ATOMIC_RELEASE);
#endif
			}
		}
		ucl_object_insert_key (top, sub, "actions", 0, false);
	}

	ucl_object_insert_key (top, ucl_object_fromint (
			spam), "spam_count", 0, false);
	ucl_object_insert_key (top, ucl_object_fromint (
			ham),  "ham_count",	 0, false);
	ucl_object_insert_key (top,
		ucl_object_fromint (stat->connections_count), "connections", 0, false);
	ucl_object_insert_key (top,
		ucl_object_fromint (stat->control_connections_count),
		"control_connections", 0, false);

	ucl_object_insert_key (top,
		ucl_object_fromint (mem_st.pools_allocated), "pools_allocated", 0,
		false);
	ucl_object_insert_key (top,
		ucl_object_fromint (mem_st.pools_freed), "pools_freed", 0, false);
	ucl_object_insert_key (top,
		ucl_object_fromint (mem_st.bytes_allocated), "bytes_allocated", 0,
		false);
	ucl_object_insert_key (top,
		ucl_object_fromint (
			mem_st.chunks_allocated), "chunks_allocated", 0, false);
	ucl_object_insert_key (top,
		ucl_object_fromint (mem_st.shared_chunks_allocated),
		"shared_chunks_allocated", 0, false);
	ucl_object_insert_key (top,
		ucl_object_fromint (mem_st.chunks_freed), "chunks_freed", 0, false);
	ucl_object_insert_key (top,
		ucl_object_fromint (
			mem_st.oversized_chunks), "chunks_oversized", 0, false);

	if (do_reset) {
		session->ctx->srv->stat->messages_scanned = 0;
		session->ctx->srv->stat->messages_learned = 0;
		session->ctx->srv->stat->connections_count = 0;
		session->ctx->srv->stat->control_connections_count = 0;
		rspamd_mempool_stat_reset ();
	}

	fuzzy_stat_command (task);

	/* Now write statistics for each statfile */
	rspamd_stat_statistics (task, session->ctx->cfg, &cbdata->learned,
			&cbdata->stat);
	session->task = task;
	rspamd_session_pending (task->s);

	return 0;
}

static int
rspamd_controller_handle_stat (struct rspamd_http_connection_entry *conn_ent,
	struct rspamd_http_message *msg)
{
	struct rspamd_controller_session *session = conn_ent->ud;

	if (!rspamd_controller_check_password (conn_ent, session, msg, FALSE)) {
		return 0;
	}

	return rspamd_controller_handle_stat_common (conn_ent, msg, FALSE);
}

static int
rspamd_controller_handle_statreset (
	struct rspamd_http_connection_entry *conn_ent,
	struct rspamd_http_message *msg)
{
	struct rspamd_controller_session *session = conn_ent->ud;

	if (!rspamd_controller_check_password (conn_ent, session, msg, TRUE)) {
		return 0;
	}

	msg_info_session ("<%s> reset stat",
			rspamd_inet_address_to_string (session->from_addr));
	return rspamd_controller_handle_stat_common (conn_ent, msg, TRUE);
}


/*
 * Counters command handler:
 * request: /counters
 * headers: Password
 * reply: json array of all counters
 */
static int
rspamd_controller_handle_counters (
	struct rspamd_http_connection_entry *conn_ent,
	struct rspamd_http_message *msg)
{
	struct rspamd_controller_session *session = conn_ent->ud;
	ucl_object_t *top;
	struct symbols_cache *cache;

	if (!rspamd_controller_check_password (conn_ent, session, msg, FALSE)) {
		return 0;
	}

	cache = session->ctx->cfg->cache;

	if (cache != NULL) {
		top = rspamd_symbols_cache_counters (cache);
		rspamd_controller_send_ucl (conn_ent, top);
		ucl_object_unref (top);
	}
	else {
		rspamd_controller_send_error (conn_ent, 500, "Invalid cache");
	}

	return 0;
}

static int
rspamd_controller_handle_custom (struct rspamd_http_connection_entry *conn_ent,
	struct rspamd_http_message *msg)
{
	struct rspamd_controller_session *session = conn_ent->ud;
	struct rspamd_custom_controller_command *cmd;
	gchar *url_str;

	url_str = rspamd_fstring_cstr (msg->url);
	cmd = g_hash_table_lookup (session->ctx->custom_commands, url_str);
	g_free (url_str);

	if (cmd == NULL || cmd->handler == NULL) {
		msg_err_session ("custom command %V has not been found", msg->url);
		rspamd_controller_send_error (conn_ent, 404, "No command associated");
		return 0;
	}

	if (!rspamd_controller_check_password (conn_ent, session, msg,
		cmd->privilleged)) {
		return 0;
	}
	if (cmd->require_message && (rspamd_http_message_get_body (msg, NULL) == NULL)) {
		msg_err_session ("got zero length body, cannot continue");
		rspamd_controller_send_error (conn_ent,
			400,
			"Empty body is not permitted");
		return 0;
	}

	return cmd->handler (conn_ent, msg, cmd->ctx);
}

static void
rspamd_controller_error_handler (struct rspamd_http_connection_entry *conn_ent,
	GError *err)
{
	struct rspamd_controller_session *session = conn_ent->ud;

	msg_err_session ("http error occurred: %s", err->message);
}

static void
rspamd_controller_finish_handler (struct rspamd_http_connection_entry *conn_ent)
{
	struct rspamd_controller_session *session = conn_ent->ud;

	session->ctx->worker->srv->stat->control_connections_count++;
	msg_debug_session ("destroy session %p", session);

	if (session->task != NULL) {
		rspamd_session_destroy (session->task->s);
	}

	if (session->pool) {
		rspamd_mempool_delete (session->pool);
	}

	session->wrk->nconns --;
	rspamd_inet_address_destroy (session->from_addr);
	REF_RELEASE (session->cfg);
	g_slice_free1 (sizeof (struct rspamd_controller_session), session);
}

static void
rspamd_controller_accept_socket (gint fd, short what, void *arg)
{
	struct rspamd_worker *worker = (struct rspamd_worker *) arg;
	struct rspamd_controller_worker_ctx *ctx;
	struct rspamd_controller_session *session;
	rspamd_inet_addr_t *addr;
	gint nfd;

	ctx = worker->ctx;

	if ((nfd =
		rspamd_accept_from_socket (fd, &addr, worker->accept_events)) == -1) {
		msg_warn_ctx ("accept failed: %s", strerror (errno));
		return;
	}
	/* Check for EAGAIN */
	if (nfd == 0) {
		return;
	}

	session = g_slice_alloc0 (sizeof (struct rspamd_controller_session));
	session->pool = rspamd_mempool_new (rspamd_mempool_suggest_size (),
			"csession");
	session->ctx = ctx;
	session->cfg = ctx->cfg;
	REF_RETAIN (session->cfg);

	session->from_addr = addr;
	session->wrk = worker;
	worker->nconns ++;

	rspamd_http_router_handle_socket (ctx->http, nfd, session);
}

static void
rspamd_controller_rrd_update (gint fd, short what, void *arg)
{
	struct rspamd_controller_worker_ctx *ctx = arg;
	struct rspamd_stat *stat;
	GArray ar;
	gdouble points[4];
	GError *err = NULL;
	guint i, j;
	gdouble val;

	g_assert (ctx->rrd != NULL);
	stat = ctx->srv->stat;

	for (i = METRIC_ACTION_REJECT, j = 0;
		 i <= METRIC_ACTION_NOACTION && j < G_N_ELEMENTS (points);
		 i++) {
		switch (i) {
		case METRIC_ACTION_SOFT_REJECT:
			break;
		case METRIC_ACTION_REWRITE_SUBJECT:
			val = stat->actions_stat[i];
			break;
		case METRIC_ACTION_ADD_HEADER:
			val += stat->actions_stat[i];
			points[j++] = val;
			break;
		default:
			val = stat->actions_stat[i];
			points[j++] = val;
		}
	}

	ar.data = (gchar *)points;
	ar.len = sizeof (points);

	if (!rspamd_rrd_add_record (ctx->rrd, &ar, rspamd_get_calendar_ticks (),
			&err)) {
		msg_err_ctx ("cannot update rrd file: %e", err);
		g_error_free (err);
	}

	/* Plan new event */
	event_del (ctx->rrd_event);
	evtimer_add (ctx->rrd_event, &rrd_update_time);
}

static void
rspamd_controller_load_saved_stats (struct rspamd_controller_worker_ctx *ctx)
{
	struct ucl_parser *parser;
	ucl_object_t *obj;
	const ucl_object_t *elt, *subelt;
	struct rspamd_stat *stat, stat_copy;
	gint i;

	g_assert (ctx->saved_stats_path != NULL);

	if (access (ctx->saved_stats_path, R_OK) == -1) {
		msg_err_ctx ("cannot load controller stats from %s: %s",
				ctx->saved_stats_path, strerror (errno));
		return;
	}

	parser = ucl_parser_new (0);

	if (!ucl_parser_add_file (parser, ctx->saved_stats_path)) {
		msg_err_ctx ("cannot parse controller stats from %s: %s",
				ctx->saved_stats_path, ucl_parser_get_error (parser));
		ucl_parser_free (parser);

		return;
	}

	obj = ucl_parser_get_object (parser);
	ucl_parser_free (parser);

	stat = ctx->srv->stat;
	memcpy (&stat_copy, stat, sizeof (stat_copy));

	elt = ucl_object_lookup (obj, "scanned");

	if (elt != NULL && ucl_object_type (elt) == UCL_INT) {
		stat_copy.messages_scanned = ucl_object_toint (elt);
	}

	elt = ucl_object_lookup (obj, "learned");

	if (elt != NULL && ucl_object_type (elt) == UCL_INT) {
		stat_copy.messages_learned = ucl_object_toint (elt);
	}

	elt = ucl_object_lookup (obj, "actions");

	if (elt != NULL) {
		for (i = METRIC_ACTION_REJECT; i <= METRIC_ACTION_NOACTION; i++) {
			subelt = ucl_object_lookup (elt, rspamd_action_to_str (i));

			if (subelt && ucl_object_type (subelt) == UCL_INT) {
				stat_copy.actions_stat[i] = ucl_object_toint (subelt);
			}
		}
	}

	elt = ucl_object_lookup (obj, "connections_count");

	if (elt != NULL && ucl_object_type (elt) == UCL_INT) {
		stat_copy.connections_count = ucl_object_toint (elt);
	}

	elt = ucl_object_lookup (obj, "control_connections_count");

	if (elt != NULL && ucl_object_type (elt) == UCL_INT) {
		stat_copy.control_connections_count = ucl_object_toint (elt);
	}

	ucl_object_unref (obj);
	memcpy (stat, &stat_copy, sizeof (stat_copy));
}

static void
rspamd_controller_store_saved_stats (struct rspamd_controller_worker_ctx *ctx)
{
	struct rspamd_stat *stat;
	ucl_object_t *top, *sub;
	gint i, fd;

	g_assert (ctx->saved_stats_path != NULL);

	fd = open (ctx->saved_stats_path, O_WRONLY|O_CREAT|O_TRUNC, 00644);

	if (fd == -1) {
		msg_err_ctx ("cannot open for writing controller stats from %s: %s",
				ctx->saved_stats_path, strerror (errno));
		return;
	}

	if (rspamd_file_lock (fd, FALSE) == -1) {
		msg_err_ctx ("cannot lock controller stats in %s: %s",
				ctx->saved_stats_path, strerror (errno));
		close (fd);

		return;
	}

	stat = ctx->srv->stat;

	top = ucl_object_typed_new (UCL_OBJECT);
	ucl_object_insert_key (top, ucl_object_fromint (
			stat->messages_scanned), "scanned", 0, false);
	ucl_object_insert_key (top, ucl_object_fromint (
			stat->messages_learned), "learned", 0, false);

	if (stat->messages_scanned > 0) {
		sub = ucl_object_typed_new (UCL_OBJECT);
		for (i = METRIC_ACTION_REJECT; i <= METRIC_ACTION_NOACTION; i++) {
			ucl_object_insert_key (sub,
					ucl_object_fromint (stat->actions_stat[i]),
					rspamd_action_to_str (i), 0, false);
		}
		ucl_object_insert_key (top, sub, "actions", 0, false);
	}

	ucl_object_insert_key (top,
			ucl_object_fromint (stat->connections_count), "connections", 0, false);
	ucl_object_insert_key (top,
			ucl_object_fromint (stat->control_connections_count),
			"control_connections", 0, false);


	ucl_object_emit_full (top, UCL_EMIT_JSON_COMPACT,
			ucl_object_emit_fd_funcs (fd), NULL);

	rspamd_file_unlock (fd, FALSE);
	close (fd);
}

static void
rspamd_controller_password_sane (struct rspamd_controller_worker_ctx *ctx,
		const gchar *password, const gchar *type)
{
	const struct rspamd_controller_pbkdf *pbkdf = &pbkdf_list[0];

	if (password == NULL) {
		msg_warn_ctx ("%s is not set, so you should filter controller "
				"availability "
				"by using of firewall or `secure_ip` option", type);
		return;
	}

	g_assert (pbkdf != NULL);

	if (!rspamd_is_encrypted_password (password, NULL)) {
		/* Suggest encryption to a user */

		msg_warn_ctx ("your %s is not encrypted, we strongly "
				"recommend to replace it with the encrypted one", type);
	}
}

gpointer
init_controller_worker (struct rspamd_config *cfg)
{
	struct rspamd_controller_worker_ctx *ctx;
	GQuark type;

	type = g_quark_try_string ("controller");

	ctx = g_malloc0 (sizeof (struct rspamd_controller_worker_ctx));

	ctx->magic = rspamd_controller_ctx_magic;
	ctx->timeout = DEFAULT_WORKER_IO_TIMEOUT;

	rspamd_rcl_register_worker_option (cfg,
			type,
			"password",
			rspamd_rcl_parse_struct_string,
			ctx,
			G_STRUCT_OFFSET (struct rspamd_controller_worker_ctx, password),
			0,
			"Password for read-only commands");

	rspamd_rcl_register_worker_option (cfg,
			type,
			"enable_password",
			rspamd_rcl_parse_struct_string,
			ctx,
			G_STRUCT_OFFSET (struct rspamd_controller_worker_ctx,
					enable_password),
			0,
			"Password for read and write commands");

	rspamd_rcl_register_worker_option (cfg,
			type,
			"ssl",
			rspamd_rcl_parse_struct_boolean,
			ctx,
			G_STRUCT_OFFSET (struct rspamd_controller_worker_ctx, use_ssl),
			0,
			"Unimplemented");

	rspamd_rcl_register_worker_option (cfg,
			type,
			"ssl_cert",
			rspamd_rcl_parse_struct_string,
			ctx,
			G_STRUCT_OFFSET (struct rspamd_controller_worker_ctx, ssl_cert),
			0,
			"Unimplemented");

	rspamd_rcl_register_worker_option (cfg,
			type,
			"ssl_key",
			rspamd_rcl_parse_struct_string,
			ctx,
			G_STRUCT_OFFSET (struct rspamd_controller_worker_ctx, ssl_key),
			0,
			"Unimplemented");
	rspamd_rcl_register_worker_option (cfg,
			type,
			"timeout",
			rspamd_rcl_parse_struct_time,
			ctx,
			G_STRUCT_OFFSET (struct rspamd_controller_worker_ctx,
					timeout),
			RSPAMD_CL_FLAG_TIME_INTEGER,
			"Protocol timeout");

	rspamd_rcl_register_worker_option (cfg,
			type,
			"secure_ip",
			rspamd_rcl_parse_struct_ucl,
			ctx,
			G_STRUCT_OFFSET (struct rspamd_controller_worker_ctx, secure_ip),
			0,
			"List of IP addresses that are allowed for password-less access");

	rspamd_rcl_register_worker_option (cfg,
			type,
			"trusted_ips",
			rspamd_rcl_parse_struct_ucl,
			ctx,
			G_STRUCT_OFFSET (struct rspamd_controller_worker_ctx, secure_ip),
			0,
			"List of IP addresses that are allowed for password-less access");

	rspamd_rcl_register_worker_option (cfg,
			type,
			"static_dir",
			rspamd_rcl_parse_struct_string,
			ctx,
			G_STRUCT_OFFSET (struct rspamd_controller_worker_ctx,
					static_files_dir),
			0,
			"Directory for static files served by controller's HTTP server");

	rspamd_rcl_register_worker_option (cfg,
			type,
			"keypair",
			rspamd_rcl_parse_struct_keypair,
			ctx,
			G_STRUCT_OFFSET (struct rspamd_controller_worker_ctx,
					key),
			0,
			"Encryption keypair");

	rspamd_rcl_register_worker_option (cfg,
			type,
			"stats_path",
			rspamd_rcl_parse_struct_string,
			ctx,
			G_STRUCT_OFFSET (struct rspamd_controller_worker_ctx,
					saved_stats_path),
			0,
			"Directory where controller saves server's statistics between restarts");

	return ctx;
}

static void
rspamd_controller_on_terminate (struct rspamd_worker *worker)
{
	struct rspamd_controller_worker_ctx *ctx = worker->ctx;

	rspamd_controller_store_saved_stats (ctx);

	if (ctx->rrd) {
		msg_info ("closing rrd file: %s", ctx->rrd->filename);
		event_del (ctx->rrd_event);
		rspamd_rrd_close (ctx->rrd);
	}
}

/*
 * Start worker process
 */
void
start_controller_worker (struct rspamd_worker *worker)
{
	struct rspamd_controller_worker_ctx *ctx = worker->ctx;
	struct module_ctx *mctx;
	GHashTableIter iter;
	gpointer key, value;
	struct rspamd_keypair_cache *cache;
	gpointer m;

	ctx->ev_base = rspamd_prepare_worker (worker,
			"controller",
			rspamd_controller_accept_socket);
	msec_to_tv (ctx->timeout, &ctx->io_tv);

	ctx->start_time = time (NULL);
	ctx->worker = worker;
	ctx->cfg = worker->srv->cfg;
	ctx->srv = worker->srv;
	ctx->custom_commands = g_hash_table_new (rspamd_strcase_hash,
			rspamd_strcase_equal);

	if (ctx->secure_ip != NULL) {
		rspamd_config_radix_from_ucl (ctx->cfg, ctx->secure_ip,
				"Allow unauthenticated requests from these addresses",
				&ctx->secure_map, NULL);
	}

	if (ctx->saved_stats_path == NULL) {
		/* Assume default path */
		ctx->saved_stats_path = rspamd_mempool_strdup (worker->srv->cfg->cfg_pool,
				DEFAULT_STATS_PATH);
	}

	g_ptr_array_add (worker->finish_actions,
			(gpointer)rspamd_controller_on_terminate);
	rspamd_controller_load_saved_stats (ctx);

	/* RRD collector */
	if (ctx->cfg->rrd_file && worker->index == 0) {
		GError *rrd_err = NULL;

		ctx->rrd = rspamd_rrd_file_default (ctx->cfg->rrd_file, &rrd_err);

		if (ctx->rrd) {
			ctx->rrd_event = g_slice_alloc0 (sizeof (*ctx->rrd_event));
			evtimer_set (ctx->rrd_event, rspamd_controller_rrd_update, ctx);
			event_base_set (ctx->ev_base, ctx->rrd_event);
			event_add (ctx->rrd_event, &rrd_update_time);
		}
		else if (rrd_err) {
			msg_err ("cannot load rrd from %s: %e", ctx->cfg->rrd_file,
					rrd_err);
			g_error_free (rrd_err);
		}
		else {
			msg_err ("cannot load rrd from %s: unknown error", ctx->cfg->rrd_file);
		}
	}
	else {
		ctx->rrd = NULL;
	}

	rspamd_controller_password_sane (ctx, ctx->password, "normal password");
	rspamd_controller_password_sane (ctx, ctx->enable_password, "enable "
			"password");

	/* Accept event */
	cache = rspamd_keypair_cache_new (256);
	ctx->http = rspamd_http_router_new (rspamd_controller_error_handler,
			rspamd_controller_finish_handler, &ctx->io_tv, ctx->ev_base,
			ctx->static_files_dir, cache);

	/* Add callbacks for different methods */
	rspamd_http_router_add_path (ctx->http,
			PATH_AUTH,
			rspamd_controller_handle_auth);
	rspamd_http_router_add_path (ctx->http,
			PATH_SYMBOLS,
			rspamd_controller_handle_symbols);
	rspamd_http_router_add_path (ctx->http,
			PATH_ACTIONS,
			rspamd_controller_handle_actions);
	rspamd_http_router_add_path (ctx->http,
			PATH_MAPS,
			rspamd_controller_handle_maps);
	rspamd_http_router_add_path (ctx->http,
			PATH_GET_MAP,
			rspamd_controller_handle_get_map);
	rspamd_http_router_add_path (ctx->http,
			PATH_PIE_CHART,
			rspamd_controller_handle_pie_chart);
	rspamd_http_router_add_path (ctx->http,
			PATH_GRAPH,
			rspamd_controller_handle_graph);
	rspamd_http_router_add_path (ctx->http,
			PATH_HISTORY,
			rspamd_controller_handle_history);
	rspamd_http_router_add_path (ctx->http,
			PATH_HISTORY_RESET,
			rspamd_controller_handle_history_reset);
	rspamd_http_router_add_path (ctx->http,
			PATH_LEARN_SPAM,
			rspamd_controller_handle_learnspam);
	rspamd_http_router_add_path (ctx->http,
			PATH_LEARN_HAM,
			rspamd_controller_handle_learnham);
	rspamd_http_router_add_path (ctx->http,
			PATH_SAVE_ACTIONS,
			rspamd_controller_handle_saveactions);
	rspamd_http_router_add_path (ctx->http,
			PATH_SAVE_SYMBOLS,
			rspamd_controller_handle_savesymbols);
	rspamd_http_router_add_path (ctx->http,
			PATH_SAVE_MAP,
			rspamd_controller_handle_savemap);
	rspamd_http_router_add_path (ctx->http,
			PATH_SCAN,
			rspamd_controller_handle_scan);
	rspamd_http_router_add_path (ctx->http,
			PATH_CHECK,
			rspamd_controller_handle_scan);
	rspamd_http_router_add_path (ctx->http,
			PATH_STAT,
			rspamd_controller_handle_stat);
	rspamd_http_router_add_path (ctx->http,
			PATH_STAT_RESET,
			rspamd_controller_handle_statreset);
	rspamd_http_router_add_path (ctx->http,
			PATH_COUNTERS,
			rspamd_controller_handle_counters);

	if (ctx->key) {
		rspamd_http_router_set_key (ctx->http, ctx->key);
	}

	g_hash_table_iter_init (&iter, ctx->cfg->c_modules);
	while (g_hash_table_iter_next (&iter, &key, &value)) {
		mctx = value;
		if (mctx->mod->module_attach_controller_func != NULL) {
			mctx->mod->module_attach_controller_func (mctx,
					ctx->custom_commands);
		}
	}

	g_hash_table_iter_init (&iter, ctx->custom_commands);
	while (g_hash_table_iter_next (&iter, &key, &value)) {
		rspamd_http_router_add_path (ctx->http,
			key,
			rspamd_controller_handle_custom);
	}


	ctx->resolver = dns_resolver_init (worker->srv->logger,
			ctx->ev_base,
			worker->srv->cfg);

	rspamd_upstreams_library_config (worker->srv->cfg, worker->srv->cfg->ups_ctx,
			ctx->ev_base, ctx->resolver->r);
	/* Maps events */
	rspamd_map_watch (worker->srv->cfg, ctx->ev_base, ctx->resolver);
	rspamd_symbols_cache_start_refresh (worker->srv->cfg->cache, ctx->ev_base);
	rspamd_stat_init (worker->srv->cfg, ctx->ev_base);

	event_base_loop (ctx->ev_base, 0);
	rspamd_worker_block_signals ();

	g_mime_shutdown ();
	rspamd_stat_close ();
	rspamd_http_router_free (ctx->http);
	rspamd_log_close (worker->srv->logger);

	if (ctx->cached_password.len > 0) {
		m = (gpointer)ctx->cached_password.begin;
		munmap (m, ctx->cached_password.len);
	}

	if (ctx->cached_enable_password.len > 0) {
		m = (gpointer) ctx->cached_enable_password.begin;
		munmap (m, ctx->cached_enable_password.len);
	}

	exit (EXIT_SUCCESS);
}
