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

#include "cfg_file.h"
#include "rspamd.h"
#include "cfg_file_private.h"
#include "scan_result.h"
#include "lua/lua_common.h"
#include "lua/lua_thread_pool.h"
#include "maps/map.h"
#include "maps/map_helpers.h"
#include "maps/map_private.h"
#include "dynamic_cfg.h"
#include "utlist.h"
#include "stat_api.h"
#include "unix-std.h"
#include "libutil/multipattern.h"
#include "monitored.h"
#include "ref.h"
#include "cryptobox.h"
#include "ssl_util.h"
#include "contrib/libottery/ottery.h"
#include "contrib/fastutf8/fastutf8.h"

#ifdef SYS_ZSTD
#  include "zstd.h"
#else
#  define ZSTD_STATIC_LINKING_ONLY
#  include "contrib/zstd/zstd.h"
#endif

#ifdef HAVE_OPENSSL
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/conf.h>
#endif
#ifdef HAVE_LOCALE_H
#include <locale.h>
#endif
#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif
#include <math.h>
#include "libserver/composites/composites.h"

#include "blas-config.h"

#define DEFAULT_SCORE 10.0

#define DEFAULT_RLIMIT_NOFILE 2048
#define DEFAULT_RLIMIT_MAXCORE 0
#define DEFAULT_MAP_TIMEOUT 60.0 * 5
#define DEFAULT_MAP_FILE_WATCH_MULTIPLIER 1
#define DEFAULT_MIN_WORD 0
#define DEFAULT_MAX_WORD 40
#define DEFAULT_WORDS_DECAY 600
#define DEFAULT_MAX_MESSAGE (50 * 1024 * 1024)
#define DEFAULT_MAX_PIC (1 * 1024 * 1024)
#define DEFAULT_MAX_SHOTS 100
#define DEFAULT_MAX_SESSIONS 100
#define DEFAULT_MAX_WORKERS 4
/* Timeout for task processing */
#define DEFAULT_TASK_TIMEOUT 8.0
#define DEFAULT_LUA_GC_STEP 200
#define DEFAULT_LUA_GC_PAUSE 200
#define DEFAULT_GC_MAXITERS 0

struct rspamd_ucl_map_cbdata {
	struct rspamd_config *cfg;
	GString *buf;
};
static gchar * rspamd_ucl_read_cb (gchar * chunk,
	gint len,
	struct map_cb_data *data,
	gboolean final);
static void rspamd_ucl_fin_cb (struct map_cb_data *data, void **target);
static void rspamd_ucl_dtor_cb (struct map_cb_data *data);

guint rspamd_config_log_id = (guint)-1;
RSPAMD_CONSTRUCTOR(rspamd_config_log_init)
{
	rspamd_config_log_id = rspamd_logger_add_debug_module("config");
}

gboolean
rspamd_parse_bind_line (struct rspamd_config *cfg,
	struct rspamd_worker_conf *cf,
	const gchar *str)
{
	struct rspamd_worker_bind_conf *cnf;
	const gchar *fdname;
	gboolean ret = TRUE;

	if (str == NULL) {
		return FALSE;
	}

	cnf = g_malloc0 (sizeof (struct rspamd_worker_bind_conf));

	cnf->cnt = 1024;
	cnf->bind_line = g_strdup (str);

	if (g_ascii_strncasecmp (str, "systemd:", sizeof ("systemd:") - 1) == 0) {
		/* The actual socket will be passed by systemd environment */
		fdname = str + sizeof ("systemd:") - 1;
		cnf->is_systemd = TRUE;
		cnf->addrs = g_ptr_array_new_full (1, g_free);

		if (fdname[0]) {
			g_ptr_array_add (cnf->addrs, g_strdup (fdname));
			cnf->cnt = cnf->addrs->len;
			cnf->name = g_strdup (str);
			LL_PREPEND (cf->bind_conf, cnf);
		}
		else {
			msg_err_config ("cannot parse bind line: %s", str);
			ret = FALSE;
		}
	}
	else {
		if (rspamd_parse_host_port_priority (str, &cnf->addrs,
				NULL, &cnf->name, DEFAULT_BIND_PORT, TRUE, NULL) == RSPAMD_PARSE_ADDR_FAIL) {
			msg_err_config ("cannot parse bind line: %s", str);
			ret = FALSE;
		}
		else {
			cnf->cnt = cnf->addrs->len;
			LL_PREPEND (cf->bind_conf, cnf);
		}
	}

	if (!ret) {
		if (cnf->addrs) {
			g_ptr_array_free (cnf->addrs, TRUE);
		}

		g_free (cnf->name);
		g_free (cnf);
	}

	return ret;
}

struct rspamd_config *
rspamd_config_new (enum rspamd_config_init_flags flags)
{
	struct rspamd_config *cfg;
	rspamd_mempool_t *pool;

	pool = rspamd_mempool_new (8 * 1024 * 1024, "cfg", 0);
	cfg = rspamd_mempool_alloc0 (pool, sizeof (*cfg));
	/* Allocate larger pool for cfg */
	cfg->cfg_pool = pool;
	cfg->dns_timeout = 1.0;
	cfg->dns_retransmits = 5;
	/* 16 sockets per DNS server */
	cfg->dns_io_per_server = 16;

	/* Add all internal actions to keep compatibility */
	for (int i = METRIC_ACTION_REJECT; i < METRIC_ACTION_MAX; i ++) {
		struct rspamd_action *action;

		action = rspamd_mempool_alloc0 (cfg->cfg_pool, sizeof (*action));
		action->threshold = NAN;
		action->name = rspamd_mempool_strdup (cfg->cfg_pool,
				rspamd_action_to_str (i));
		action->action_type = i;

		if (i == METRIC_ACTION_SOFT_REJECT) {
			action->flags |= RSPAMD_ACTION_NO_THRESHOLD|RSPAMD_ACTION_HAM;
		}
		else if (i == METRIC_ACTION_GREYLIST) {
			action->flags |= RSPAMD_ACTION_THRESHOLD_ONLY|RSPAMD_ACTION_HAM;
		}
		else if (i == METRIC_ACTION_NOACTION) {
			action->flags |= RSPAMD_ACTION_HAM;
		}

		HASH_ADD_KEYPTR (hh, cfg->actions,
				action->name, strlen (action->name), action);
	}

	/* Disable timeout */
	cfg->task_timeout = DEFAULT_TASK_TIMEOUT;


	rspamd_config_init_metric (cfg);
	cfg->composites_manager = rspamd_composites_manager_create(cfg);
	cfg->classifiers_symbols = g_hash_table_new (rspamd_str_hash,
			rspamd_str_equal);
	cfg->cfg_params = g_hash_table_new (rspamd_str_hash, rspamd_str_equal);
	cfg->debug_modules = g_hash_table_new (rspamd_str_hash, rspamd_str_equal);
	cfg->explicit_modules = g_hash_table_new (rspamd_str_hash, rspamd_str_equal);
	cfg->wrk_parsers = g_hash_table_new (g_int_hash, g_int_equal);
	cfg->trusted_keys = g_hash_table_new (rspamd_str_hash,
				rspamd_str_equal);

	cfg->map_timeout = DEFAULT_MAP_TIMEOUT;
	cfg->map_file_watch_multiplier = DEFAULT_MAP_FILE_WATCH_MULTIPLIER;

	cfg->log_level = G_LOG_LEVEL_WARNING;
	cfg->log_flags = RSPAMD_LOG_FLAG_DEFAULT;

	cfg->check_text_attachements = TRUE;

	cfg->dns_max_requests = 64;
	cfg->history_rows = 200;
	cfg->log_error_elts = 10;
	cfg->log_error_elt_maxlen = 1000;
	cfg->cache_reload_time = 30.0;
	cfg->max_lua_urls = 1024;
	cfg->max_urls = cfg->max_lua_urls * 10;
	cfg->max_recipients = 1024;
	cfg->max_blas_threads = 1;
	cfg->max_opts_len = 4096;

	/* Default log line */
	cfg->log_format_str = "id: <$mid>,$if_qid{ qid: <$>,}$if_ip{ ip: $,}"
			"$if_user{ user: $,}$if_smtp_from{ from: <$>,} (default: $is_spam "
			"($action): [$scores] [$symbols_scores_params]), len: $len, time: $time_real, "
			"dns req: $dns_req, digest: <$digest>"
			"$if_smtp_rcpts{ rcpts: <$>, }$if_mime_rcpt{ mime_rcpt: <$>, }";
	/* Allow non-mime input by default */
	cfg->allow_raw_input = TRUE;
	/* Default maximum words processed */
	cfg->words_decay = DEFAULT_WORDS_DECAY;
	cfg->min_word_len = DEFAULT_MIN_WORD;
	cfg->max_word_len = DEFAULT_MAX_WORD;

	/* GC limits */
	cfg->lua_gc_pause = DEFAULT_LUA_GC_PAUSE;
	cfg->lua_gc_step = DEFAULT_LUA_GC_STEP;
	cfg->full_gc_iters = DEFAULT_GC_MAXITERS;

	if (!(flags & RSPAMD_CONFIG_INIT_SKIP_LUA)) {
		cfg->lua_state = rspamd_lua_init (flags & RSPAMD_CONFIG_INIT_WIPE_LUA_MEM);
		cfg->own_lua_state = TRUE;
		cfg->lua_thread_pool = lua_thread_pool_new (cfg->lua_state);
	}

	cfg->cache = rspamd_symcache_new (cfg);
	cfg->ups_ctx = rspamd_upstreams_library_init ();
	cfg->re_cache = rspamd_re_cache_new ();
	cfg->doc_strings = ucl_object_typed_new (UCL_OBJECT);
	/*
	 * Unless exim is fixed
	 */
	cfg->enable_shutdown_workaround = TRUE;

	cfg->ssl_ciphers = "HIGH:!aNULL:!kRSA:!PSK:!SRP:!MD5:!RC4";
	cfg->max_message = DEFAULT_MAX_MESSAGE;
	cfg->max_pic_size = DEFAULT_MAX_PIC;
	cfg->images_cache_size = 256;
	cfg->monitored_ctx = rspamd_monitored_ctx_init ();
	cfg->neighbours = ucl_object_typed_new (UCL_OBJECT);
	cfg->redis_pool = rspamd_redis_pool_init ();
	cfg->default_max_shots = DEFAULT_MAX_SHOTS;
	cfg->max_sessions_cache = DEFAULT_MAX_SESSIONS;
	cfg->maps_cache_dir = rspamd_mempool_strdup (cfg->cfg_pool, RSPAMD_DBDIR);
	cfg->c_modules = g_ptr_array_new ();
	cfg->heartbeat_interval = 10.0;

	cfg->enable_css_parser = true;

	REF_INIT_RETAIN (cfg, rspamd_config_free);

	return cfg;
}

void
rspamd_config_free (struct rspamd_config *cfg)
{
	struct rspamd_config_cfg_lua_script *sc, *sctmp;
	struct rspamd_config_settings_elt *set, *stmp;
	struct rspamd_worker_log_pipe *lp, *ltmp;

	rspamd_lua_run_config_unload (cfg->lua_state, cfg);

	/* Scripts part */
	DL_FOREACH_SAFE (cfg->on_term_scripts, sc, sctmp) {
		luaL_unref (cfg->lua_state, LUA_REGISTRYINDEX, sc->cbref);
	}

	DL_FOREACH_SAFE (cfg->on_load_scripts, sc, sctmp) {
		luaL_unref (cfg->lua_state, LUA_REGISTRYINDEX, sc->cbref);
	}

	DL_FOREACH_SAFE (cfg->post_init_scripts, sc, sctmp) {
		luaL_unref (cfg->lua_state, LUA_REGISTRYINDEX, sc->cbref);
	}

	DL_FOREACH_SAFE (cfg->config_unload_scripts, sc, sctmp) {
		luaL_unref (cfg->lua_state, LUA_REGISTRYINDEX, sc->cbref);
	}

	DL_FOREACH_SAFE (cfg->setting_ids, set, stmp) {
		REF_RELEASE (set);
	}

	rspamd_map_remove_all (cfg);
	rspamd_mempool_destructors_enforce (cfg->cfg_pool);

	g_list_free (cfg->classifiers);
	g_list_free (cfg->workers);
	rspamd_symcache_destroy (cfg->cache);
	ucl_object_unref (cfg->rcl_obj);
	ucl_object_unref (cfg->config_comments);
	ucl_object_unref (cfg->doc_strings);
	ucl_object_unref (cfg->neighbours);
	g_hash_table_remove_all (cfg->cfg_params);
	g_hash_table_unref (cfg->cfg_params);
	g_hash_table_unref (cfg->classifiers_symbols);
	g_hash_table_unref (cfg->debug_modules);
	g_hash_table_unref (cfg->explicit_modules);
	g_hash_table_unref (cfg->wrk_parsers);
	g_hash_table_unref (cfg->trusted_keys);

	rspamd_re_cache_unref (cfg->re_cache);
	g_ptr_array_free (cfg->c_modules, TRUE);

	if (cfg->monitored_ctx) {
		rspamd_monitored_ctx_destroy (cfg->monitored_ctx);
	}

	if (cfg->lua_state && cfg->own_lua_state) {
		lua_thread_pool_free (cfg->lua_thread_pool);
		lua_close (cfg->lua_state);
	}

	if (cfg->redis_pool) {
		rspamd_redis_pool_destroy (cfg->redis_pool);
	}

	rspamd_upstreams_library_unref (cfg->ups_ctx);
	HASH_CLEAR (hh, cfg->actions);

	rspamd_mempool_destructors_enforce (cfg->cfg_pool);

	if (cfg->checksum) {
		g_free (cfg->checksum);
	}

	REF_RELEASE (cfg->libs_ctx);

	DL_FOREACH_SAFE (cfg->log_pipes, lp, ltmp) {
		close (lp->fd);
		g_free (lp);
	}

	rspamd_mempool_delete (cfg->cfg_pool);
}

const ucl_object_t *
rspamd_config_get_module_opt (struct rspamd_config *cfg,
	const gchar *module_name,
	const gchar *opt_name)
{
	const ucl_object_t *res = NULL, *sec;

	sec = ucl_obj_get_key (cfg->rcl_obj, module_name);
	if (sec != NULL) {
		res = ucl_obj_get_key (sec, opt_name);
	}

	return res;
}

gchar
rspamd_config_parse_flag (const gchar *str, guint len)
{
	gchar c;

	if (!str || !*str) {
		return -1;
	}

	if (len == 0) {
		len = strlen (str);
	}

	switch (len) {
	case 1:
		c = g_ascii_tolower (*str);
		if (c == 'y' || c == '1') {
			return 1;
		}
		else if (c == 'n' || c == '0') {
			return 0;
		}
		break;
	case 2:
		if (g_ascii_strncasecmp (str, "no", len) == 0) {
			return 0;
		}
		else if (g_ascii_strncasecmp (str, "on", len) == 0) {
			return 1;
		}
		break;
	case 3:
		if (g_ascii_strncasecmp (str, "yes", len) == 0) {
			return 1;
		}
		else if (g_ascii_strncasecmp (str, "off", len) == 0) {
			return 0;
		}
		break;
	case 4:
		if (g_ascii_strncasecmp (str, "true", len) == 0) {
			return 1;
		}
		break;
	case 5:
		if (g_ascii_strncasecmp (str, "false", len) == 0) {
			return 0;
		}
		break;
	}

	return -1;
}

static gboolean
rspamd_config_process_var (struct rspamd_config *cfg, const rspamd_ftok_t *var,
		const rspamd_ftok_t *content)
{
	guint flags = RSPAMD_LOG_FLAG_DEFAULT;
	struct rspamd_log_format *lf;
	enum rspamd_log_format_type type;
	rspamd_ftok_t tok;
	gint id;

	g_assert (var != NULL);

	if (var->len > 3 && rspamd_lc_cmp (var->begin, "if_", 3) == 0) {
		flags |= RSPAMD_LOG_FMT_FLAG_CONDITION;
		tok.begin = var->begin + 3;
		tok.len = var->len - 3;
	}
	else {
		tok.begin = var->begin;
		tok.len = var->len;
	}

	/* Now compare variable and check what we have */
	if (rspamd_ftok_cstr_equal (&tok, "mid", TRUE)) {
		type = RSPAMD_LOG_MID;
	}
	else if (rspamd_ftok_cstr_equal (&tok, "qid", TRUE)) {
		type = RSPAMD_LOG_QID;
	}
	else if (rspamd_ftok_cstr_equal (&tok, "user", TRUE)) {
		type = RSPAMD_LOG_USER;
	}
	else if (rspamd_ftok_cstr_equal (&tok, "is_spam", TRUE)) {
		type = RSPAMD_LOG_ISSPAM;
	}
	else if (rspamd_ftok_cstr_equal (&tok, "action", TRUE)) {
		type = RSPAMD_LOG_ACTION;
	}
	else if (rspamd_ftok_cstr_equal (&tok, "scores", TRUE)) {
		type = RSPAMD_LOG_SCORES;
	}
	else if (rspamd_ftok_cstr_equal (&tok, "symbols", TRUE)) {
		type = RSPAMD_LOG_SYMBOLS;
	}
	else if (rspamd_ftok_cstr_equal (&tok, "symbols_scores", TRUE)) {
		type = RSPAMD_LOG_SYMBOLS;
		flags |= RSPAMD_LOG_FMT_FLAG_SYMBOLS_SCORES;
	}
	else if (rspamd_ftok_cstr_equal (&tok, "symbols_params", TRUE)) {
		type = RSPAMD_LOG_SYMBOLS;
		flags |= RSPAMD_LOG_FMT_FLAG_SYMBOLS_PARAMS;
	}
	else if (rspamd_ftok_cstr_equal (&tok, "symbols_scores_params", TRUE)) {
		type = RSPAMD_LOG_SYMBOLS;
		flags |= RSPAMD_LOG_FMT_FLAG_SYMBOLS_PARAMS|RSPAMD_LOG_FMT_FLAG_SYMBOLS_SCORES;
	}
	else if (rspamd_ftok_cstr_equal (&tok, "groups", TRUE)) {
		type = RSPAMD_LOG_GROUPS;
	}
	else if (rspamd_ftok_cstr_equal (&tok, "public_groups", TRUE)) {
		type = RSPAMD_LOG_PUBLIC_GROUPS;
	}
	else if (rspamd_ftok_cstr_equal (&tok, "ip", TRUE)) {
		type = RSPAMD_LOG_IP;
	}
	else if (rspamd_ftok_cstr_equal (&tok, "len", TRUE)) {
		type = RSPAMD_LOG_LEN;
	}
	else if (rspamd_ftok_cstr_equal (&tok, "dns_req", TRUE)) {
		type = RSPAMD_LOG_DNS_REQ;
	}
	else if (rspamd_ftok_cstr_equal (&tok, "smtp_from", TRUE)) {
		type = RSPAMD_LOG_SMTP_FROM;
	}
	else if (rspamd_ftok_cstr_equal (&tok, "mime_from", TRUE)) {
		type = RSPAMD_LOG_MIME_FROM;
	}
	else if (rspamd_ftok_cstr_equal (&tok, "smtp_rcpt", TRUE)) {
		type = RSPAMD_LOG_SMTP_RCPT;
	}
	else if (rspamd_ftok_cstr_equal (&tok, "mime_rcpt", TRUE)) {
		type = RSPAMD_LOG_MIME_RCPT;
	}
	else if (rspamd_ftok_cstr_equal (&tok, "smtp_rcpts", TRUE)) {
		type = RSPAMD_LOG_SMTP_RCPTS;
	}
	else if (rspamd_ftok_cstr_equal (&tok, "mime_rcpts", TRUE)) {
		type = RSPAMD_LOG_MIME_RCPTS;
	}
	else if (rspamd_ftok_cstr_equal (&tok, "time_real", TRUE)) {
		type = RSPAMD_LOG_TIME_REAL;
	}
	else if (rspamd_ftok_cstr_equal (&tok, "time_virtual", TRUE)) {
		type = RSPAMD_LOG_TIME_VIRTUAL;
	}
	else if (rspamd_ftok_cstr_equal (&tok, "lua", TRUE)) {
		type = RSPAMD_LOG_LUA;
	}
	else if (rspamd_ftok_cstr_equal (&tok, "digest", TRUE) ||
			rspamd_ftok_cstr_equal (&tok, "checksum", TRUE)) {
		type = RSPAMD_LOG_DIGEST;
	}
	else if (rspamd_ftok_cstr_equal (&tok, "filename", TRUE)) {
		type = RSPAMD_LOG_FILENAME;
	}
	else if (rspamd_ftok_cstr_equal (&tok, "forced_action", TRUE)) {
		type = RSPAMD_LOG_FORCED_ACTION;
	}
	else if (rspamd_ftok_cstr_equal (&tok, "settings_id", TRUE)) {
		type = RSPAMD_LOG_SETTINGS_ID;
	}
	else if (rspamd_ftok_cstr_equal (&tok, "mempool_size", TRUE)) {
		type = RSPAMD_LOG_MEMPOOL_SIZE;
	}
	else if (rspamd_ftok_cstr_equal (&tok, "mempool_waste", TRUE)) {
		type = RSPAMD_LOG_MEMPOOL_WASTE;
	}
	else {
		msg_err_config ("unknown log variable: %T", &tok);
		return FALSE;
	}

	lf = rspamd_mempool_alloc0 (cfg->cfg_pool, sizeof (*lf));
	lf->type = type;
	lf->flags = flags;

	if (type != RSPAMD_LOG_LUA) {
		if (content && content->len > 0) {
			lf->data = rspamd_mempool_alloc0 (cfg->cfg_pool,
					sizeof (rspamd_ftok_t));
			memcpy (lf->data, content, sizeof (*content));
			lf->len = sizeof (*content);
		}
	}
	else {
		/* Load lua code and ensure that we have function ref returned */
		if (!content || content->len == 0) {
			msg_err_config ("lua variable needs content: %T", &tok);
			return FALSE;
		}

		if (luaL_loadbuffer (cfg->lua_state, content->begin, content->len,
				"lua log variable") != 0) {
			msg_err_config ("error loading lua code: '%T': %s", content,
					lua_tostring (cfg->lua_state, -1));
			return FALSE;
		}
		if (lua_pcall (cfg->lua_state, 0, 1, 0) != 0) {
			msg_err_config ("error executing lua code: '%T': %s", content,
					lua_tostring (cfg->lua_state, -1));
			lua_pop (cfg->lua_state, 1);

			return FALSE;
		}

		if (lua_type (cfg->lua_state, -1) != LUA_TFUNCTION) {
			msg_err_config ("lua variable should return function: %T", content);
			lua_pop (cfg->lua_state, 1);
			return FALSE;
		}

		id = luaL_ref (cfg->lua_state, LUA_REGISTRYINDEX);
		lf->data = GINT_TO_POINTER (id);
		lf->len = 0;
	}

	DL_APPEND (cfg->log_format, lf);

	return TRUE;
}

static gboolean
rspamd_config_parse_log_format (struct rspamd_config *cfg)
{
	const gchar *p, *c, *end, *s;
	gchar *d;
	struct rspamd_log_format *lf = NULL;
	rspamd_ftok_t var, var_content;
	enum {
		parse_str,
		parse_dollar,
		parse_var_name,
		parse_var_content,
	} state = parse_str;
	gint braces = 0;

	g_assert (cfg != NULL);
	c = cfg->log_format_str;

	if (c == NULL) {
		return FALSE;
	}

	p = c;
	end = p + strlen (p);

	while (p < end) {
		switch (state) {
		case parse_str:
			if (*p == '$') {
				state = parse_dollar;
			}
			else {
				p ++;
			}
			break;
		case parse_dollar:
			if (p > c) {
				/* We have string element that we need to store */
				lf = rspamd_mempool_alloc0 (cfg->cfg_pool, sizeof (*lf));
				lf->type = RSPAMD_LOG_STRING;
				lf->data = rspamd_mempool_alloc (cfg->cfg_pool, p - c + 1);
				/* Filter \r\n from the destination */
				s = c;
				d = lf->data;

				while (s < p) {
					if (*s != '\r' && *s != '\n') {
						*d++ = *s++;
					}
					else {
						*d ++ = ' ';
						s++;
					}
				}
				*d = '\0';

				lf->len = d - (char *) lf->data;
				DL_APPEND (cfg->log_format, lf);
				lf = NULL;
			}
			p++;
			c = p;
			state = parse_var_name;
			break;
		case parse_var_name:
			if (*p == '{') {
				var.begin = c;
				var.len = p - c;
				p ++;
				c = p;
				state = parse_var_content;
				braces = 1;
			}
			else if (*p != '_' && *p != '-' && !g_ascii_isalnum (*p)) {
				/* Variable with no content */
				var.begin = c;
				var.len = p - c;
				c = p;

				if (!rspamd_config_process_var (cfg, &var, NULL)) {
					return FALSE;
				}

				state = parse_str;
			}
			else {
				p++;
			}
			break;
		case parse_var_content:
			if (*p == '}' && --braces == 0) {
				var_content.begin = c;
				var_content.len = p - c;
				p ++;
				c = p;

				if (!rspamd_config_process_var (cfg, &var, &var_content)) {
					return FALSE;
				}

				state = parse_str;
			}
			else if (*p == '{') {
				braces ++;
				p ++;
			}
			else {
				p++;
			}
			break;
		}
	}

	/* Last state */
	switch (state) {
	case parse_str:
		if (p > c) {
			/* We have string element that we need to store */
			lf = rspamd_mempool_alloc0 (cfg->cfg_pool, sizeof (*lf));
			lf->type = RSPAMD_LOG_STRING;
			lf->data = rspamd_mempool_alloc (cfg->cfg_pool, p - c + 1);
			/* Filter \r\n from the destination */
			s = c;
			d = lf->data;

			while (s < p) {
				if (*s != '\r' && *s != '\n') {
					*d++ = *s++;
				}
				else {
					*d++ = ' ';
					s++;
				}
			}
			*d = '\0';

			lf->len = d - (char *)lf->data;
			DL_APPEND (cfg->log_format, lf);
			lf = NULL;
		}
		break;

	case parse_var_name:
		var.begin = c;
		var.len = p - c;

		if (!rspamd_config_process_var (cfg, &var, NULL)) {
			return FALSE;
		}
		break;
	case parse_dollar:
	case parse_var_content:
		msg_err_config ("cannot parse log format %s: incomplete string",
			cfg->log_format_str);
		return FALSE;
		break;
	}

	return TRUE;
}

static void
rspamd_urls_config_dtor (gpointer _unused)
{
	rspamd_url_deinit ();
}

/*
 * Perform post load actions
 */
gboolean
rspamd_config_post_load (struct rspamd_config *cfg,
		enum rspamd_post_load_options opts)
{
#ifdef HAVE_CLOCK_GETTIME
	struct timespec ts;
#endif
	gboolean ret = TRUE;

#ifdef HAVE_CLOCK_GETTIME
#ifdef HAVE_CLOCK_PROCESS_CPUTIME_ID
	clock_getres (CLOCK_PROCESS_CPUTIME_ID, &ts);
# elif defined(HAVE_CLOCK_VIRTUAL)
	clock_getres (CLOCK_VIRTUAL,			&ts);
# else
	clock_getres (CLOCK_REALTIME,			&ts);
# endif
	rspamd_logger_configure_modules (cfg->debug_modules);

	cfg->clock_res = log10 (1000000. / ts.tv_nsec);
	if (cfg->clock_res < 0) {
		cfg->clock_res = 0;
	}
	if (cfg->clock_res > 3) {
		cfg->clock_res = 3;
	}
#else
	/* For gettimeofday */
	cfg->clock_res = 1;
#endif

	if (cfg->one_shot_mode) {
		msg_info_config ("enabling one shot mode (was %d max shots)",
				cfg->default_max_shots);
		cfg->default_max_shots = 1;
	}

	rspamd_regexp_library_init (cfg);
	rspamd_multipattern_library_init (cfg->hs_cache_dir);

#if defined(WITH_HYPERSCAN) && !defined(__aarch64__)
	if (!cfg->disable_hyperscan) {
		if (!(cfg->libs_ctx->crypto_ctx->cpu_config & CPUID_SSSE3)) {
			msg_warn_config ("CPU doesn't have SSSE3 instructions set "
					"required for hyperscan, disable it");
			cfg->disable_hyperscan = TRUE;
		}
	}
#endif

	if (opts & RSPAMD_CONFIG_INIT_URL) {
		if (cfg->tld_file == NULL) {
			/* Try to guess tld file */
			GString *fpath = g_string_new (NULL);

			rspamd_printf_gstring (fpath, "%s%c%s", RSPAMD_SHAREDIR,
					G_DIR_SEPARATOR, "effective_tld_names.dat");

			if (access (fpath->str, R_OK) != -1) {
				msg_debug_config ("url_tld option is not specified but %s is available,"
						" therefore this file is assumed as TLD file for URL"
						" extraction", fpath->str);
				cfg->tld_file = rspamd_mempool_strdup (cfg->cfg_pool, fpath->str);
			}
			else {
				if (opts & RSPAMD_CONFIG_INIT_VALIDATE) {
					msg_err_config ("no url_tld option has been specified");
					ret = FALSE;
				}
			}

			g_string_free (fpath, TRUE);
		}
		else {
			if (access (cfg->tld_file, R_OK) == -1) {
				if (opts & RSPAMD_CONFIG_INIT_VALIDATE) {
					ret = FALSE;
					msg_err_config ("cannot access tld file %s: %s", cfg->tld_file,
							strerror (errno));
				}
				else {
					msg_debug_config ("cannot access tld file %s: %s", cfg->tld_file,
							strerror (errno));
					cfg->tld_file = NULL;
				}
			}
		}

		if (opts & RSPAMD_CONFIG_INIT_NO_TLD) {
			rspamd_url_init (NULL);
		}
		else {
			rspamd_url_init (cfg->tld_file);
		}

		rspamd_mempool_add_destructor (cfg->cfg_pool, rspamd_urls_config_dtor,
				NULL);
	}

	init_dynamic_config (cfg);
	/* Insert classifiers symbols */
	rspamd_config_insert_classify_symbols (cfg);

	/* Parse format string that we have */
	if (!rspamd_config_parse_log_format (cfg)) {
		msg_err_config ("cannot parse log format, task logging will not be available");
	}

	if (opts & RSPAMD_CONFIG_INIT_SYMCACHE) {
		/* Init config cache */
		rspamd_symcache_init (cfg->cache);

		/* Init re cache */
		rspamd_re_cache_init (cfg->re_cache, cfg);

		/* Try load Hypersan */
		rspamd_re_cache_load_hyperscan (cfg->re_cache,
				cfg->hs_cache_dir ? cfg->hs_cache_dir :  RSPAMD_DBDIR "/",
				true);
	}

	if (opts & RSPAMD_CONFIG_INIT_LIBS) {
		/* Config other libraries */
		rspamd_config_libs (cfg->libs_ctx, cfg);
	}

	/* Validate cache */
	if (opts & RSPAMD_CONFIG_INIT_VALIDATE) {
		/* Check for actions sanity */
		gboolean seen_controller = FALSE;
		GList *cur;
		struct rspamd_worker_conf *wcf;

		cur = cfg->workers;
		while (cur) {
			wcf = cur->data;

			if (wcf->type == g_quark_from_static_string ("controller")) {
				seen_controller = TRUE;
				break;
			}

			cur = g_list_next (cur);
		}

		if (!seen_controller) {
			msg_warn_config ("controller worker is unconfigured: learning,"
					" periodic scripts, maps watching and many other"
					" Rspamd features will be broken");
		}

		ret = rspamd_symcache_validate (cfg->cache, cfg, FALSE) && ret;
	}

	if (opts & RSPAMD_CONFIG_INIT_POST_LOAD_LUA) {
		rspamd_lua_run_config_post_init (cfg->lua_state, cfg);
	}

	if (opts & RSPAMD_CONFIG_INIT_PRELOAD_MAPS) {
		rspamd_map_preload (cfg);
	}

	return ret;
}

struct rspamd_classifier_config *
rspamd_config_new_classifier (struct rspamd_config *cfg,
	struct rspamd_classifier_config *c)
{
	if (c == NULL) {
		c =
			rspamd_mempool_alloc0 (cfg->cfg_pool,
				sizeof (struct rspamd_classifier_config));
		c->min_prob_strength = 0.05;
		c->min_token_hits = 2;
	}

	if (c->labels == NULL) {
		c->labels = g_hash_table_new_full (rspamd_str_hash,
				rspamd_str_equal,
				NULL,
				(GDestroyNotify)g_list_free);
		rspamd_mempool_add_destructor (cfg->cfg_pool,
			(rspamd_mempool_destruct_t) g_hash_table_destroy,
			c->labels);
	}

	return c;
}

struct rspamd_statfile_config *
rspamd_config_new_statfile (struct rspamd_config *cfg,
	struct rspamd_statfile_config *c)
{
	if (c == NULL) {
		c =
			rspamd_mempool_alloc0 (cfg->cfg_pool,
				sizeof (struct rspamd_statfile_config));
	}

	return c;
}

void
rspamd_config_init_metric (struct rspamd_config *cfg)
{
	cfg->grow_factor = 1.0;
	cfg->symbols = g_hash_table_new (rspamd_str_hash, rspamd_str_equal);
	cfg->groups = g_hash_table_new (rspamd_strcase_hash, rspamd_strcase_equal);

	cfg->subject = SPAM_SUBJECT;
	rspamd_mempool_add_destructor (cfg->cfg_pool,
			(rspamd_mempool_destruct_t) g_hash_table_unref,
			cfg->symbols);
	rspamd_mempool_add_destructor (cfg->cfg_pool,
			(rspamd_mempool_destruct_t) g_hash_table_unref,
			cfg->groups);
}

struct rspamd_symbols_group *
rspamd_config_new_group (struct rspamd_config *cfg, const gchar *name)
{
	struct rspamd_symbols_group *gr;

	gr = rspamd_mempool_alloc0 (cfg->cfg_pool, sizeof (*gr));
	gr->symbols = g_hash_table_new (rspamd_strcase_hash,
			rspamd_strcase_equal);
	rspamd_mempool_add_destructor (cfg->cfg_pool,
			(rspamd_mempool_destruct_t)g_hash_table_unref, gr->symbols);
	gr->name = rspamd_mempool_strdup (cfg->cfg_pool, name);

	if (strcmp (gr->name, "ungrouped") == 0) {
		gr->flags |= RSPAMD_SYMBOL_GROUP_UNGROUPED;
	}

	g_hash_table_insert (cfg->groups, gr->name, gr);

	return gr;
}

static void
rspamd_worker_conf_dtor (struct rspamd_worker_conf *wcf)
{
	if (wcf) {
		struct rspamd_worker_bind_conf *cnf, *tmp;

		LL_FOREACH_SAFE (wcf->bind_conf, cnf, tmp) {
			g_free (cnf->name);
			g_free (cnf->bind_line);
			g_ptr_array_free (cnf->addrs, TRUE);
			g_free (cnf);
		}

		ucl_object_unref (wcf->options);
		g_queue_free (wcf->active_workers);
		g_hash_table_unref (wcf->params);
		g_free (wcf);
	}
}

static void
rspamd_worker_conf_cfg_fin (gpointer d)
{
	struct rspamd_worker_conf *wcf = d;

	REF_RELEASE (wcf);
}

struct rspamd_worker_conf *
rspamd_config_new_worker (struct rspamd_config *cfg,
	struct rspamd_worker_conf *c)
{
	if (c == NULL) {
		c = g_malloc0 (sizeof (struct rspamd_worker_conf));
		c->params = g_hash_table_new (rspamd_str_hash, rspamd_str_equal);
		c->active_workers = g_queue_new ();
#ifdef HAVE_SC_NPROCESSORS_ONLN
		c->count = MIN (DEFAULT_MAX_WORKERS,
				MAX (1, sysconf (_SC_NPROCESSORS_ONLN) - 2));
#else
		c->count = DEFAULT_MAX_WORKERS;
#endif
		c->rlimit_nofile = 0;
		c->rlimit_maxcore = 0;
		c->enabled = TRUE;

		REF_INIT_RETAIN (c, rspamd_worker_conf_dtor);
		rspamd_mempool_add_destructor (cfg->cfg_pool,
				rspamd_worker_conf_cfg_fin, c);
	}

	return c;
}


static bool
rspamd_include_map_handler (const guchar *data, gsize len,
		const ucl_object_t *args, void * ud)
{
	struct rspamd_config *cfg = (struct rspamd_config *)ud;
	struct rspamd_ucl_map_cbdata *cbdata, **pcbdata;
	gchar *map_line;

	map_line = rspamd_mempool_alloc (cfg->cfg_pool, len + 1);
	rspamd_strlcpy (map_line, data, len + 1);

	cbdata = g_malloc (sizeof (struct rspamd_ucl_map_cbdata));
	pcbdata = g_malloc (sizeof (struct rspamd_ucl_map_cbdata *));
	cbdata->buf = NULL;
	cbdata->cfg = cfg;
	*pcbdata = cbdata;

	return rspamd_map_add (cfg,
			   map_line,
			   "ucl include",
			   rspamd_ucl_read_cb,
			   rspamd_ucl_fin_cb,
			   rspamd_ucl_dtor_cb,
			   (void **)pcbdata,
			   NULL, RSPAMD_MAP_DEFAULT) != NULL;
}

/*
 * Variables:
 * $CONFDIR - configuration directory
 * $LOCAL_CONFDIR - local configuration directory
 * $RUNDIR - local states directory
 * $DBDIR - databases dir
 * $LOGDIR - logs dir
 * $PLUGINSDIR - pluggins dir
 * $PREFIX - installation prefix
 * $VERSION - rspamd version
 */

#define RSPAMD_CONFDIR_MACRO "CONFDIR"
#define RSPAMD_LOCAL_CONFDIR_MACRO "LOCAL_CONFDIR"
#define RSPAMD_RUNDIR_MACRO "RUNDIR"
#define RSPAMD_DBDIR_MACRO "DBDIR"
#define RSPAMD_LOGDIR_MACRO "LOGDIR"
#define RSPAMD_PLUGINSDIR_MACRO "PLUGINSDIR"
#define RSPAMD_SHAREDIR_MACRO "SHAREDIR"
#define RSPAMD_RULESDIR_MACRO "RULESDIR"
#define RSPAMD_WWWDIR_MACRO "WWWDIR"
#define RSPAMD_PREFIX_MACRO "PREFIX"
#define RSPAMD_VERSION_MACRO "VERSION"
#define RSPAMD_VERSION_MAJOR_MACRO "VERSION_MAJOR"
#define RSPAMD_VERSION_MINOR_MACRO "VERSION_MINOR"
#define RSPAMD_BRANCH_VERSION_MACRO "BRANCH_VERSION"
#define RSPAMD_HOSTNAME_MACRO "HOSTNAME"

void
rspamd_ucl_add_conf_variables (struct ucl_parser *parser, GHashTable *vars)
{
	GHashTableIter it;
	gpointer k, v;
	gchar *hostbuf;
	gsize hostlen;

	ucl_parser_register_variable (parser,
			RSPAMD_CONFDIR_MACRO,
			RSPAMD_CONFDIR);
	ucl_parser_register_variable (parser,
			RSPAMD_LOCAL_CONFDIR_MACRO,
			RSPAMD_LOCAL_CONFDIR);
	ucl_parser_register_variable (parser, RSPAMD_RUNDIR_MACRO,
			RSPAMD_RUNDIR);
	ucl_parser_register_variable (parser,  RSPAMD_DBDIR_MACRO,
			RSPAMD_DBDIR);
	ucl_parser_register_variable (parser, RSPAMD_LOGDIR_MACRO,
			RSPAMD_LOGDIR);
	ucl_parser_register_variable (parser,
			RSPAMD_PLUGINSDIR_MACRO,
			RSPAMD_PLUGINSDIR);
	ucl_parser_register_variable (parser,
			RSPAMD_SHAREDIR_MACRO,
			RSPAMD_SHAREDIR);
	ucl_parser_register_variable (parser,
			RSPAMD_RULESDIR_MACRO,
			RSPAMD_RULESDIR);
	ucl_parser_register_variable (parser,  RSPAMD_WWWDIR_MACRO,
			RSPAMD_WWWDIR);
	ucl_parser_register_variable (parser,  RSPAMD_PREFIX_MACRO,
			RSPAMD_PREFIX);
	ucl_parser_register_variable (parser, RSPAMD_VERSION_MACRO, RVERSION);
	ucl_parser_register_variable (parser, RSPAMD_VERSION_MAJOR_MACRO,
			RSPAMD_VERSION_MAJOR);
	ucl_parser_register_variable (parser, RSPAMD_VERSION_MINOR_MACRO,
			RSPAMD_VERSION_MINOR);
	ucl_parser_register_variable (parser, RSPAMD_BRANCH_VERSION_MACRO,
			RSPAMD_VERSION_BRANCH);

	hostlen = sysconf (_SC_HOST_NAME_MAX);

	if (hostlen <= 0) {
		hostlen = 256;
	}
	else {
		hostlen ++;
	}

	hostbuf = g_alloca (hostlen);
	memset (hostbuf, 0, hostlen);
	gethostname (hostbuf, hostlen - 1);

	/* UCL copies variables, so it is safe to pass an ephemeral buffer here */
	ucl_parser_register_variable (parser, RSPAMD_HOSTNAME_MACRO,
			hostbuf);

	if (vars != NULL) {
		g_hash_table_iter_init (&it, vars);

		while (g_hash_table_iter_next (&it, &k, &v)) {
			ucl_parser_register_variable (parser, k, v);
		}
	}
}

void
rspamd_ucl_add_conf_macros (struct ucl_parser *parser,
	struct rspamd_config *cfg)
{
	ucl_parser_register_macro (parser,
		"include_map",
		rspamd_include_map_handler,
		cfg);
}

static void
symbols_classifiers_callback (gpointer key, gpointer value, gpointer ud)
{
	struct rspamd_config *cfg = ud;

	/* Actually, statistics should act like any ordinary symbol */
	rspamd_symcache_add_symbol (cfg->cache, key, 0, NULL, NULL,
			SYMBOL_TYPE_CLASSIFIER | SYMBOL_TYPE_NOSTAT, -1);
}

void
rspamd_config_insert_classify_symbols (struct rspamd_config *cfg)
{
	g_hash_table_foreach (cfg->classifiers_symbols,
		symbols_classifiers_callback,
		cfg);
}

struct rspamd_classifier_config *
rspamd_config_find_classifier (struct rspamd_config *cfg, const gchar *name)
{
	GList *cur;
	struct rspamd_classifier_config *cf;

	if (name == NULL) {
		return NULL;
	}

	cur = cfg->classifiers;
	while (cur) {
		cf = cur->data;

		if (g_ascii_strcasecmp (cf->name, name) == 0) {
			return cf;
		}

		cur = g_list_next (cur);
	}

	return NULL;
}

gboolean
rspamd_config_check_statfiles (struct rspamd_classifier_config *cf)
{
	struct rspamd_statfile_config *st;
	gboolean has_other = FALSE, res = FALSE, cur_class = FALSE;
	GList *cur;

	/* First check classes directly */
	cur = cf->statfiles;
	while (cur) {
		st = cur->data;
		if (!has_other) {
			cur_class = st->is_spam;
			has_other = TRUE;
		}
		else {
			if (cur_class != st->is_spam) {
				return TRUE;
			}
		}

		cur = g_list_next (cur);
	}

	if (!has_other) {
		/* We have only one statfile */
		return FALSE;
	}
	/* We have not detected any statfile that has different class, so turn on euristic based on symbol's name */
	has_other = FALSE;
	cur = cf->statfiles;
	while (cur) {
		st = cur->data;
		if (rspamd_substring_search_caseless (st->symbol,
				strlen (st->symbol),"spam", 4) != -1) {
			st->is_spam = TRUE;
		}
		else if (rspamd_substring_search_caseless (st->symbol,
				strlen (st->symbol),"ham", 3) != -1) {
			st->is_spam = FALSE;
		}

		if (!has_other) {
			cur_class = st->is_spam;
			has_other = TRUE;
		}
		else {
			if (cur_class != st->is_spam) {
				res = TRUE;
			}
		}

		cur = g_list_next (cur);
	}

	return res;
}

static gchar *
rspamd_ucl_read_cb (gchar * chunk,
	gint len,
	struct map_cb_data *data,
	gboolean final)
{
	struct rspamd_ucl_map_cbdata *cbdata = data->cur_data, *prev;

	if (cbdata == NULL) {
		cbdata = g_malloc (sizeof (struct rspamd_ucl_map_cbdata));
		prev = data->prev_data;
		cbdata->buf = g_string_sized_new (BUFSIZ);
		cbdata->cfg = prev->cfg;
		data->cur_data = cbdata;
	}
	g_string_append_len (cbdata->buf, chunk, len);

	/* Say not to copy any part of this buffer */
	return NULL;
}

static void
rspamd_ucl_fin_cb (struct map_cb_data *data, void **target)
{
	struct rspamd_ucl_map_cbdata *cbdata = data->cur_data, *prev =
		data->prev_data;
	ucl_object_t *obj;
	struct ucl_parser *parser;
	ucl_object_iter_t it = NULL;
	const ucl_object_t *cur;
	struct rspamd_config *cfg = data->map->cfg;

	if (cbdata == NULL) {
		msg_err_config ("map fin error: new data is NULL");
		return;
	}

	/* New data available */
	parser = ucl_parser_new (0);
	if (!ucl_parser_add_chunk (parser, cbdata->buf->str,
			cbdata->buf->len)) {
		msg_err_config ("cannot parse map %s: %s",
				data->map->name,
				ucl_parser_get_error (parser));
		ucl_parser_free (parser);
	}
	else {
		obj = ucl_parser_get_object (parser);
		ucl_parser_free (parser);
		it = NULL;

		while ((cur = ucl_object_iterate (obj, &it, true))) {
			ucl_object_replace_key (cbdata->cfg->rcl_obj, (ucl_object_t *)cur,
					cur->key, cur->keylen, false);
		}
		ucl_object_unref (obj);
	}

	if (target) {
		*target = data->cur_data;
	}

	if (prev != NULL) {
		if (prev->buf != NULL) {
			g_string_free (prev->buf, TRUE);
		}
		g_free (prev);
	}
}

static void
rspamd_ucl_dtor_cb (struct map_cb_data *data)
{
	struct rspamd_ucl_map_cbdata *cbdata = data->cur_data;

	if (cbdata != NULL) {
		if (cbdata->buf != NULL) {
			g_string_free (cbdata->buf, TRUE);
		}
		g_free (cbdata);
	}
}

gboolean
rspamd_check_module (struct rspamd_config *cfg, module_t *mod)
{
	gboolean ret = TRUE;

	if (mod != NULL) {
		if (mod->module_version != RSPAMD_CUR_MODULE_VERSION) {
			msg_err_config ("module %s has incorrect version %xd (%xd expected)",
					mod->name, (gint)mod->module_version, RSPAMD_CUR_MODULE_VERSION);
			ret = FALSE;
		}
		if (ret && mod->rspamd_version != RSPAMD_VERSION_NUM) {
			msg_err_config ("module %s has incorrect rspamd version %xL (%xL expected)",
					mod->name, mod->rspamd_version, RSPAMD_VERSION_NUM);
			ret = FALSE;
		}
		if (ret && strcmp (mod->rspamd_features, RSPAMD_FEATURES) != 0) {
			msg_err_config ("module %s has incorrect rspamd features '%s' ('%s' expected)",
					mod->name, mod->rspamd_features, RSPAMD_FEATURES);
			ret = FALSE;
		}
	}
	else {
		ret = FALSE;
	}

	return ret;
}

gboolean
rspamd_check_worker (struct rspamd_config *cfg, worker_t *wrk)
{
	gboolean ret = TRUE;

	if (wrk != NULL) {
		if (wrk->worker_version != RSPAMD_CUR_WORKER_VERSION) {
			msg_err_config ("worker %s has incorrect version %xd (%xd expected)",
					wrk->name, wrk->worker_version, RSPAMD_CUR_WORKER_VERSION);
			ret = FALSE;
		}
		if (ret && wrk->rspamd_version != RSPAMD_VERSION_NUM) {
			msg_err_config ("worker %s has incorrect rspamd version %xL (%xL expected)",
					wrk->name, wrk->rspamd_version, RSPAMD_VERSION_NUM);
			ret = FALSE;
		}
		if (ret && strcmp (wrk->rspamd_features, RSPAMD_FEATURES) != 0) {
			msg_err_config ("worker %s has incorrect rspamd features '%s' ('%s' expected)",
					wrk->name, wrk->rspamd_features, RSPAMD_FEATURES);
			ret = FALSE;
		}
	}
	else {
		ret = FALSE;
	}

	return ret;
}

gboolean
rspamd_init_filters (struct rspamd_config *cfg, bool reconfig, bool strict)
{
	GList *cur;
	module_t *mod, **pmod;
	guint i = 0;
	struct module_ctx *mod_ctx, *cur_ctx;
	gboolean ret = TRUE;

	/* Init all compiled modules */

	for (pmod = cfg->compiled_modules; pmod != NULL && *pmod != NULL; pmod ++) {
		mod = *pmod;
		if (rspamd_check_module (cfg, mod)) {
			if (mod->module_init_func (cfg, &mod_ctx) == 0) {
				g_assert (mod_ctx != NULL);
				g_ptr_array_add (cfg->c_modules, mod_ctx);
				mod_ctx->mod = mod;
				mod->ctx_offset = i ++;
			}
		}
	}

	/* Now check what's enabled */
	cur = g_list_first (cfg->filters);

	while (cur) {
		/* Perform modules configuring */
		mod_ctx = NULL;
		PTR_ARRAY_FOREACH (cfg->c_modules, i, cur_ctx) {
			if (g_ascii_strcasecmp (cur_ctx->mod->name,
					(const gchar *)cur->data) == 0) {
				mod_ctx = cur_ctx;
				break;
			}
		}

		if (mod_ctx) {
			mod = mod_ctx->mod;
			mod_ctx->enabled = rspamd_config_is_module_enabled (cfg, mod->name);

			if (reconfig) {
				if (!mod->module_reconfig_func (cfg)) {
					msg_err_config ("reconfig of %s failed!", mod->name);
				}
				else {
					msg_info_config ("reconfig of %s", mod->name);
				}

			}
			else {
				if (!mod->module_config_func (cfg, strict)) {
					msg_err_config ("config of %s failed", mod->name);
					ret = FALSE;

					if (strict) {
						return FALSE;
					}
				}
			}
		}

		if (mod_ctx == NULL) {
			msg_warn_config ("requested unknown module %s", cur->data);
		}

		cur = g_list_next (cur);
	}

	ret = rspamd_init_lua_filters (cfg, 0, strict) && ret;

	return ret;
}

static void
rspamd_config_new_symbol (struct rspamd_config *cfg, const gchar *symbol,
		gdouble score, const gchar *description, const gchar *group,
		guint flags, guint priority, gint nshots)
{
	struct rspamd_symbols_group *sym_group;
	struct rspamd_symbol *sym_def;
	gdouble *score_ptr;

	sym_def =
		rspamd_mempool_alloc0 (cfg->cfg_pool, sizeof (struct rspamd_symbol));
	score_ptr = rspamd_mempool_alloc (cfg->cfg_pool, sizeof (gdouble));

	if (isnan (score)) {
		/* In fact, it could be defined later */
		msg_debug_config ("score is not defined for symbol %s, set it to zero",
				symbol);
		score = 0.0;
		/* Also set priority to 0 to allow override by anything */
		sym_def->priority = 0;
		flags |= RSPAMD_SYMBOL_FLAG_UNSCORED;
	}
	else {
		sym_def->priority = priority;
	}

	*score_ptr = score;
	sym_def->score = score;
	sym_def->weight_ptr = score_ptr;
	sym_def->name = rspamd_mempool_strdup (cfg->cfg_pool, symbol);
	sym_def->flags = flags;
	sym_def->nshots = nshots != 0 ? nshots : cfg->default_max_shots;
	sym_def->groups = g_ptr_array_sized_new (1);
	rspamd_mempool_add_destructor (cfg->cfg_pool, rspamd_ptr_array_free_hard,
			sym_def->groups);

	if (description) {
		sym_def->description = rspamd_mempool_strdup (cfg->cfg_pool, description);
	}

	msg_debug_config ("registered symbol %s with weight %.2f in and group %s",
			sym_def->name, score, group);

	g_hash_table_insert (cfg->symbols, sym_def->name, sym_def);

	/* Search for symbol group */
	if (group == NULL) {
		group = "ungrouped";
		sym_def->flags |= RSPAMD_SYMBOL_FLAG_UNGROUPPED;
	}
	else {
		if (strcmp (group, "ungrouped") == 0) {
			sym_def->flags |= RSPAMD_SYMBOL_FLAG_UNGROUPPED;
		}
	}

	sym_group = g_hash_table_lookup (cfg->groups, group);
	if (sym_group == NULL) {
		/* Create new group */
		sym_group = rspamd_config_new_group (cfg, group);
	}

	sym_def->gr = sym_group;
	g_hash_table_insert (sym_group->symbols, sym_def->name, sym_def);

	if (!(sym_def->flags & RSPAMD_SYMBOL_FLAG_UNGROUPPED)) {
		g_ptr_array_add (sym_def->groups, sym_group);
	}
}


gboolean
rspamd_config_add_symbol (struct rspamd_config *cfg,
						  const gchar *symbol,
						  gdouble score,
						  const gchar *description,
						  const gchar *group,
						  guint flags,
						  guint priority,
						  gint nshots)
{
	struct rspamd_symbol *sym_def;
	struct rspamd_symbols_group *sym_group;
	guint i;

	g_assert (cfg != NULL);
	g_assert (symbol != NULL);

	sym_def = g_hash_table_lookup (cfg->symbols, symbol);

	if (sym_def != NULL) {
		if (group != NULL) {
			gboolean has_group = FALSE;

			PTR_ARRAY_FOREACH (sym_def->groups, i, sym_group) {
				if (g_ascii_strcasecmp (sym_group->name, group) == 0) {
					/* Group is already here */
					has_group = TRUE;
					break;
				}
			}

			if (!has_group) {
				/* Non-empty group has a priority over non-groupped one */
				sym_group = g_hash_table_lookup (cfg->groups, group);

				if (sym_group == NULL) {
					/* Create new group */
					sym_group = rspamd_config_new_group (cfg, group);
				}

				if (!sym_def->gr) {
					sym_def->gr = sym_group;
				}

				g_hash_table_insert (sym_group->symbols, sym_def->name, sym_def);
				sym_def->flags &= ~(RSPAMD_SYMBOL_FLAG_UNGROUPPED);
				g_ptr_array_add (sym_def->groups, sym_group);
			}
		}

		if (sym_def->priority > priority &&
			(isnan(score) || !(sym_def->flags & RSPAMD_SYMBOL_FLAG_UNSCORED))) {
			msg_debug_config ("symbol %s has been already registered with "
					"priority %ud, do not override (new priority: %ud)",
					symbol,
					sym_def->priority,
					priority);
			/* But we can still add description */
			if (!sym_def->description && description) {
				sym_def->description = rspamd_mempool_strdup (cfg->cfg_pool,
						description);
			}

			/* Or nshots in case of non-default setting */
			if (nshots != 0 && sym_def->nshots == cfg->default_max_shots) {
				sym_def->nshots = nshots;
			}

			return FALSE;
		}
		else {

			if (!isnan (score)) {
				msg_debug_config ("symbol %s has been already registered with "
								  "priority %ud, override it with new priority: %ud, "
								  "old score: %.2f, new score: %.2f",
						symbol,
						sym_def->priority,
						priority,
						sym_def->score,
						score);

				*sym_def->weight_ptr = score;
				sym_def->score = score;
				sym_def->priority = priority;
				sym_def->flags &= ~RSPAMD_SYMBOL_FLAG_UNSCORED;
			}

			sym_def->flags = flags;

			if (nshots != 0) {
				sym_def->nshots = nshots;
			}
			else {
				/* Do not reset unless we have exactly lower priority */
				if (sym_def->priority < priority) {
					sym_def->nshots = cfg->default_max_shots;
				}
			}

			if (description) {
				sym_def->description = rspamd_mempool_strdup (cfg->cfg_pool,
						description);
			}


			/* We also check group information in this case */
			if (group != NULL && sym_def->gr != NULL &&
					strcmp (group, sym_def->gr->name) != 0) {

				sym_group = g_hash_table_lookup (cfg->groups, group);

				if (sym_group == NULL) {
					/* Create new group */
					sym_group = rspamd_config_new_group (cfg, group);
				}

				if (!(sym_group->flags & RSPAMD_SYMBOL_GROUP_UNGROUPED)) {
					msg_debug_config ("move symbol %s from group %s to %s",
							sym_def->name, sym_def->gr->name, group);
					g_hash_table_remove (sym_def->gr->symbols, sym_def->name);
					sym_def->gr = sym_group;
					g_hash_table_insert (sym_group->symbols, sym_def->name, sym_def);
				}
			}

			return TRUE;
		}
	}

	/* This is called merely when we have an undefined symbol */
	rspamd_config_new_symbol (cfg, symbol, score, description,
			group, flags, priority, nshots);

	return TRUE;
}

gboolean
rspamd_config_add_symbol_group (struct rspamd_config *cfg,
								const gchar *symbol,
								const gchar *group)
{
	struct rspamd_symbol *sym_def;
	struct rspamd_symbols_group *sym_group;
	guint i;

	g_assert (cfg != NULL);
	g_assert (symbol != NULL);
	g_assert (group != NULL);

	sym_def = g_hash_table_lookup (cfg->symbols, symbol);

	if (sym_def != NULL) {
		gboolean has_group = FALSE;

		PTR_ARRAY_FOREACH (sym_def->groups, i, sym_group) {
			if (g_ascii_strcasecmp (sym_group->name, group) == 0) {
				/* Group is already here */
				has_group = TRUE;
				break;
			}
		}

		if (!has_group) {
			/* Non-empty group has a priority over non-groupped one */
			sym_group = g_hash_table_lookup (cfg->groups, group);

			if (sym_group == NULL) {
				/* Create new group */
				sym_group = rspamd_config_new_group (cfg, group);
			}

			if (!sym_def->gr) {
				sym_def->gr = sym_group;
			}

			g_hash_table_insert (sym_group->symbols, sym_def->name, sym_def);
			sym_def->flags &= ~(RSPAMD_SYMBOL_FLAG_UNGROUPPED);
			g_ptr_array_add (sym_def->groups, sym_group);

			return TRUE;
		}
	}

	return FALSE;
}


gboolean
rspamd_config_is_module_enabled (struct rspamd_config *cfg,
		const gchar *module_name)
{
	gboolean is_c = FALSE;
	const ucl_object_t *conf, *enabled;
	GList *cur;
	struct rspamd_symbols_group *gr;
	lua_State *L = cfg->lua_state;
	struct module_ctx *cur_ctx;
	guint i;

	PTR_ARRAY_FOREACH (cfg->c_modules, i, cur_ctx) {
		if (g_ascii_strcasecmp (cur_ctx->mod->name, module_name) == 0) {
			is_c = TRUE;
			break;
		}
	}

	if (g_hash_table_lookup (cfg->explicit_modules, module_name) != NULL) {
		/* Always load module */
		rspamd_plugins_table_push_elt (L, "enabled", module_name);

		return TRUE;
	}

	if (is_c) {
		gboolean found = FALSE;

		cur = g_list_first (cfg->filters);

		while (cur) {
			if (strcmp (cur->data, module_name) == 0) {
				found = TRUE;
				break;
			}

			cur = g_list_next (cur);
		}

		if (!found) {
			msg_info_config ("internal module %s is disable in `filters` line",
					module_name);
			rspamd_plugins_table_push_elt (L,
					"disabled_explicitly", module_name);

			return FALSE;
		}
	}

	conf = ucl_object_lookup (cfg->rcl_obj, module_name);

	if (conf == NULL) {
		rspamd_plugins_table_push_elt (L, "disabled_unconfigured", module_name);

		msg_info_config ("%s module %s is enabled but has not been configured",
				is_c ? "internal" : "lua", module_name);

		if (!is_c) {
			msg_info_config ("%s disabling unconfigured lua module", module_name);
			return FALSE;
		}
	}
	else {
		enabled = ucl_object_lookup (conf, "enabled");

		if (enabled) {
			if (ucl_object_type (enabled) == UCL_BOOLEAN) {
				if (!ucl_object_toboolean (enabled)) {
					rspamd_plugins_table_push_elt (L,
							"disabled_explicitly", module_name);

					msg_info_config (
							"%s module %s is disabled in the configuration",
							is_c ? "internal" : "lua", module_name);
					return FALSE;
				}
			}
			else if (ucl_object_type (enabled) == UCL_STRING) {
				gint ret;

				ret = rspamd_config_parse_flag (ucl_object_tostring (enabled), 0);

				if (ret == 0) {
					rspamd_plugins_table_push_elt (L,
							"disabled_explicitly", module_name);

					msg_info_config (
							"%s module %s is disabled in the configuration",
							is_c ? "internal" : "lua", module_name);
					return FALSE;
				}
				else if (ret == -1) {
					rspamd_plugins_table_push_elt (L,
							"disabled_failed", module_name);

					msg_info_config (
							"%s module %s has wrong enabled flag (%s) in the configuration",
							is_c ? "internal" : "lua", module_name,
							ucl_object_tostring (enabled));
					return FALSE;
				}
			}
		}
	}

	/* Now we check symbols group */
	gr = g_hash_table_lookup (cfg->groups, module_name);

	if (gr) {
		if (gr->flags & RSPAMD_SYMBOL_GROUP_DISABLED) {
			rspamd_plugins_table_push_elt (L,
					"disabled_explicitly", module_name);
			msg_info_config ("%s module %s is disabled in the configuration as "
					"its group has been disabled",
					is_c ? "internal" : "lua", module_name);

			return FALSE;
		}
	}

	rspamd_plugins_table_push_elt (L, "enabled", module_name);

	return TRUE;
}

static gboolean
rspamd_config_action_from_ucl (struct rspamd_config *cfg,
							   struct rspamd_action *act,
							   const ucl_object_t *obj,
							   guint priority)
{
	const ucl_object_t *elt;
	gdouble threshold = NAN;
	guint flags = 0, std_act, obj_type;

	obj_type = ucl_object_type (obj);

	if (obj_type == UCL_OBJECT) {
		obj_type = ucl_object_type (obj);

		elt = ucl_object_lookup_any (obj, "score", "threshold", NULL);

		if (elt) {
			threshold = ucl_object_todouble (elt);
		}

		elt = ucl_object_lookup (obj, "flags");

		if (elt && ucl_object_type (elt) == UCL_ARRAY) {
			const ucl_object_t *cur;
			ucl_object_iter_t it = NULL;

			while ((cur = ucl_object_iterate (elt, &it, true)) != NULL) {
				if (ucl_object_type (cur) == UCL_STRING) {
					const gchar *fl_str = ucl_object_tostring (cur);

					if (g_ascii_strcasecmp (fl_str, "no_threshold") == 0) {
						flags |= RSPAMD_ACTION_NO_THRESHOLD;
					} else if (g_ascii_strcasecmp (fl_str, "threshold_only") == 0) {
						flags |= RSPAMD_ACTION_THRESHOLD_ONLY;
					} else if (g_ascii_strcasecmp (fl_str, "ham") == 0) {
						flags |= RSPAMD_ACTION_HAM;
					} else {
						msg_warn_config ("unknown action flag: %s", fl_str);
					}
				}
			}
		}

		elt = ucl_object_lookup (obj, "milter");

		if (elt) {
			const gchar *milter_action = ucl_object_tostring (elt);

			if (strcmp (milter_action, "discard") == 0) {
				flags |= RSPAMD_ACTION_MILTER;
				act->action_type = METRIC_ACTION_DISCARD;
			}
			else if (strcmp (milter_action, "quarantine") == 0) {
				flags |= RSPAMD_ACTION_MILTER;
				act->action_type = METRIC_ACTION_QUARANTINE;
			}
			else {
				msg_warn_config ("unknown milter action: %s", milter_action);
			}
		}
	}
	else if (obj_type == UCL_FLOAT || obj_type == UCL_INT) {
		threshold = ucl_object_todouble (obj);
	}

	/* TODO: add lua references support */

	if (isnan (threshold) && !(flags & RSPAMD_ACTION_NO_THRESHOLD)) {
		msg_err_config ("action %s has no threshold being set and it is not"
				  " a no threshold action", act->name);

		return FALSE;
	}

	act->threshold = threshold;
	act->flags = flags;

	if (!(flags & RSPAMD_ACTION_MILTER)) {
		if (rspamd_action_from_str (act->name, &std_act)) {
			act->action_type = std_act;
		} else {
			act->action_type = METRIC_ACTION_CUSTOM;
		}
	}

	return TRUE;
}

gboolean
rspamd_config_set_action_score (struct rspamd_config *cfg,
		const gchar *action_name,
		const ucl_object_t *obj)
{
	struct rspamd_action *act;
	enum rspamd_action_type std_act;
	const ucl_object_t *elt;
	guint priority = ucl_object_get_priority (obj), obj_type;

	g_assert (cfg != NULL);
	g_assert (action_name != NULL);

	obj_type = ucl_object_type (obj);

	if (obj_type == UCL_OBJECT) {
		elt = ucl_object_lookup (obj, "priority");

		if (elt) {
			priority = ucl_object_toint (elt);
		}
	}

	/* Here are dragons:
	 * We have `canonical` name for actions, such as `soft reject` and
	 * configuration names for actions (used to be more convenient), such
	 * as `soft_reject`. Unfortunately, we must have heuristic for this
	 * variance of names.
	 */

	if (rspamd_action_from_str (action_name, (gint *)&std_act)) {
		action_name = rspamd_action_to_str (std_act);
	}

	HASH_FIND_STR (cfg->actions, action_name, act);

	if (act) {
		/* Existing element */
		if (act->priority <= priority) {
			/* We can replace data */
			msg_info_config ("action %s has been already registered with "
							 "priority %ud, override it with new priority: %ud, "
							 "old score: %.2f",
					action_name,
					act->priority,
					priority,
					act->threshold);
			if (rspamd_config_action_from_ucl (cfg, act, obj, priority)) {
				rspamd_actions_sort (cfg);
			}
			else {
				return FALSE;
			}
		}
		else {
			msg_info_config ("action %s has been already registered with "
							 "priority %ud, do not override (new priority: %ud)",
					action_name,
					act->priority,
					priority);
		}
	}
	else {
		/* Add new element */
		act = rspamd_mempool_alloc0 (cfg->cfg_pool, sizeof (*act));
		act->name = rspamd_mempool_strdup (cfg->cfg_pool, action_name);

		if (rspamd_config_action_from_ucl (cfg, act, obj, priority)) {
			HASH_ADD_KEYPTR (hh, cfg->actions,
					act->name, strlen (act->name), act);
			rspamd_actions_sort (cfg);
		}
		else {
			return FALSE;
		}
	}

	return TRUE;
}

gboolean
rspamd_config_maybe_disable_action (struct rspamd_config *cfg,
											 const gchar *action_name,
											 guint priority)
{
	struct rspamd_action *act;

	HASH_FIND_STR (cfg->actions, action_name, act);

	if (act) {
		if (priority >= act->priority) {
			msg_info_config ("disable action %s; old priority: %ud, new priority: %ud",
					action_name,
					act->priority,
					priority);

			act->threshold = NAN;
			act->priority = priority;
			act->flags |= RSPAMD_ACTION_NO_THRESHOLD;

			return TRUE;
		}
		else {
			msg_info_config ("action %s has been already registered with "
							 "priority %ud, cannot disable it with new priority: %ud",
					action_name,
					act->priority,
					priority);
		}
	}

	return FALSE;
}

struct rspamd_action *
rspamd_config_get_action (struct rspamd_config *cfg, const gchar *name)
{
	struct rspamd_action *res = NULL;

	HASH_FIND_STR (cfg->actions, name, res);

	return res;
}

struct rspamd_action *
rspamd_config_get_action_by_type (struct rspamd_config *cfg,
								  enum rspamd_action_type type)
{
	struct rspamd_action *cur, *tmp;

	HASH_ITER (hh, cfg->actions, cur, tmp) {
		if (cur->action_type == type) {
			return cur;
		}
	}

	return NULL;
}

gboolean
rspamd_config_radix_from_ucl (struct rspamd_config *cfg, const ucl_object_t *obj, const gchar *description,
							  struct rspamd_radix_map_helper **target, GError **err,
							  struct rspamd_worker *worker, const gchar *map_name)
{
	ucl_type_t type;
	ucl_object_iter_t it = NULL;
	const ucl_object_t *cur, *cur_elt;
	const gchar *str;

	/* Cleanup */
	*target = NULL;

	LL_FOREACH (obj, cur_elt) {
		type = ucl_object_type (cur_elt);

		switch (type) {
		case UCL_STRING:
			/* Either map or a list of IPs */
			str = ucl_object_tostring (cur_elt);

			if (rspamd_map_is_map (str)) {
				if (rspamd_map_add_from_ucl (cfg, cur_elt,
						description,
						rspamd_radix_read,
						rspamd_radix_fin,
						rspamd_radix_dtor,
						(void **)target,
						worker, RSPAMD_MAP_DEFAULT) == NULL) {
					g_set_error (err,
							g_quark_from_static_string ("rspamd-config"),
							EINVAL, "bad map definition %s for %s", str,
							ucl_object_key (obj));
					return FALSE;
				}

				return TRUE;
			}
			else {
				/* Just a list */
				if (!*target) {
					*target = rspamd_map_helper_new_radix (
							rspamd_map_add_fake (cfg, description, map_name));
				}

				rspamd_map_helper_insert_radix_resolve (*target, str, "");
			}
			break;
		case UCL_OBJECT:
			/* Should be a map description */
			if (rspamd_map_add_from_ucl (cfg, cur_elt,
					description,
					rspamd_radix_read,
					rspamd_radix_fin,
					rspamd_radix_dtor,
					(void **)target,
					worker, RSPAMD_MAP_DEFAULT) == NULL) {
				g_set_error (err,
						g_quark_from_static_string ("rspamd-config"),
						EINVAL, "bad map object for %s", ucl_object_key (obj));
				return FALSE;
			}

			return TRUE;
			break;
		case UCL_ARRAY:
			/* List of IP addresses */
			it = ucl_object_iterate_new (cur_elt);

			while ((cur = ucl_object_iterate_safe (it, true)) != NULL) {
				str = ucl_object_tostring (cur);

				if (!*target) {
					*target = rspamd_map_helper_new_radix (
							rspamd_map_add_fake (cfg, description, map_name));
				}

				rspamd_map_helper_insert_radix_resolve (*target, str, "");
			}

			ucl_object_iterate_free (it);
			break;
		default:
			g_set_error (err, g_quark_from_static_string ("rspamd-config"),
					EINVAL, "bad map type %s for %s",
					ucl_object_type_to_string (type),
					ucl_object_key (obj));
			return FALSE;
		}
	}

	/* Destroy on cfg cleanup */
	rspamd_mempool_add_destructor (cfg->cfg_pool,
			(rspamd_mempool_destruct_t)rspamd_map_helper_destroy_radix,
			*target);

	return TRUE;
}

gboolean
rspamd_action_from_str (const gchar *data, gint *result)
{
	guint64 h;

	h = rspamd_cryptobox_fast_hash_specific (RSPAMD_CRYPTOBOX_XXHASH64,
			data, strlen (data), 0xdeadbabe);

	switch (h) {
	case 0x9917BFDB46332B8CULL: /* reject */
		*result = METRIC_ACTION_REJECT;
		break;
	case 0x7130EE37D07B3715ULL: /* greylist */
		*result = METRIC_ACTION_GREYLIST;
		break;
	case 0xCA6087E05480C60CULL: /* add_header */
	case 0x87A3D27783B16241ULL: /* add header */
		*result = METRIC_ACTION_ADD_HEADER;
		break;
	case 0x4963374ED8B90449ULL: /* rewrite_subject */
	case 0x5C9FC4679C025948ULL: /* rewrite subject */
		*result = METRIC_ACTION_REWRITE_SUBJECT;
		break;
	case 0xFC7D6502EE71FDD9ULL: /* soft reject */
	case 0x73576567C262A82DULL: /* soft_reject */
		*result = METRIC_ACTION_SOFT_REJECT;
		break;
	case 0x207091B927D1EC0DULL: /* no action */
	case 0xB7D92D002CD46325ULL: /* no_action */
	case 0x167C0DF4BAA9BCECULL: /* accept */
		*result = METRIC_ACTION_NOACTION;
		break;
	case 0x4E9666ECCD3FC314ULL: /* quarantine */
		*result = METRIC_ACTION_QUARANTINE;
		break;
	case 0x93B346242F7F69B3ULL: /* discard */
		*result = METRIC_ACTION_DISCARD;
		break;
	default:
		return FALSE;
	}

	return TRUE;
}

const gchar *
rspamd_action_to_str (enum rspamd_action_type action)
{
	switch (action) {
	case METRIC_ACTION_REJECT:
		return "reject";
	case METRIC_ACTION_SOFT_REJECT:
		return "soft reject";
	case METRIC_ACTION_REWRITE_SUBJECT:
		return "rewrite subject";
	case METRIC_ACTION_ADD_HEADER:
		return "add header";
	case METRIC_ACTION_GREYLIST:
		return "greylist";
	case METRIC_ACTION_NOACTION:
		return "no action";
	case METRIC_ACTION_MAX:
		return "invalid max action";
	case METRIC_ACTION_CUSTOM:
		return "custom";
	case METRIC_ACTION_DISCARD:
		return "discard";
	case METRIC_ACTION_QUARANTINE:
		return "quarantine";
	}

	return "unknown action";
}

const gchar *
rspamd_action_to_str_alt (enum rspamd_action_type action)
{
	switch (action) {
	case METRIC_ACTION_REJECT:
		return "reject";
	case METRIC_ACTION_SOFT_REJECT:
		return "soft_reject";
	case METRIC_ACTION_REWRITE_SUBJECT:
		return "rewrite_subject";
	case METRIC_ACTION_ADD_HEADER:
		return "add_header";
	case METRIC_ACTION_GREYLIST:
		return "greylist";
	case METRIC_ACTION_NOACTION:
		return "no action";
	case METRIC_ACTION_MAX:
		return "invalid max action";
	case METRIC_ACTION_CUSTOM:
		return "custom";
	case METRIC_ACTION_DISCARD:
		return "discard";
	case METRIC_ACTION_QUARANTINE:
		return "quarantine";
	}

	return "unknown action";
}

static int
rspamd_actions_cmp (const struct rspamd_action *a1, const struct rspamd_action *a2)
{
	if (!isnan (a1->threshold) && !isnan (a2->threshold)) {
		if (a1->threshold < a2->threshold) {
			return -1;
		}
		else if (a1->threshold > a2->threshold) {
			return 1;
		}

		return 0;
	}

	if (isnan (a1->threshold) && isnan (a2->threshold)) {
		return 0;
	}
	else if (isnan (a1->threshold)) {
		return 1;
	}
	else {
		return -1;
	}
}

void
rspamd_actions_sort (struct rspamd_config *cfg)
{
	HASH_SORT (cfg->actions, rspamd_actions_cmp);
}

static void
rspamd_config_settings_elt_dtor (struct rspamd_config_settings_elt *e)
{
	if (e->symbols_enabled) {
		ucl_object_unref (e->symbols_enabled);
	}
	if (e->symbols_disabled) {
		ucl_object_unref (e->symbols_disabled);
	}
}

guint32
rspamd_config_name_to_id (const gchar *name, gsize namelen)
{
	guint64 h;

	h = rspamd_cryptobox_fast_hash_specific (RSPAMD_CRYPTOBOX_XXHASH64,
			name, namelen, 0x0);
	/* Take the lower part of hash as LE number */
	return ((guint32)GUINT64_TO_LE (h));
}

struct rspamd_config_settings_elt *
rspamd_config_find_settings_id_ref (struct rspamd_config *cfg,
									guint32 id)
{
	struct rspamd_config_settings_elt *cur;

	DL_FOREACH (cfg->setting_ids, cur) {
		if (cur->id == id) {
			REF_RETAIN (cur);
			return cur;
		}
	}

	return NULL;
}

struct rspamd_config_settings_elt *rspamd_config_find_settings_name_ref (
		struct rspamd_config *cfg,
		const gchar *name, gsize namelen)
{
	guint32 id;

	id = rspamd_config_name_to_id (name, namelen);

	return rspamd_config_find_settings_id_ref (cfg, id);
}

void
rspamd_config_register_settings_id (struct rspamd_config *cfg,
									const gchar *name,
									ucl_object_t *symbols_enabled,
									ucl_object_t *symbols_disabled,
									enum rspamd_config_settings_policy policy)
{
	struct rspamd_config_settings_elt *elt;
	guint32 id;

	id = rspamd_config_name_to_id (name, strlen (name));
	elt = rspamd_config_find_settings_id_ref (cfg, id);

	if (elt) {
		/* Need to replace */
		struct rspamd_config_settings_elt *nelt;

		DL_DELETE (cfg->setting_ids, elt);

		nelt = rspamd_mempool_alloc0 (cfg->cfg_pool, sizeof (*nelt));

		nelt->id = id;
		nelt->name = rspamd_mempool_strdup (cfg->cfg_pool, name);

		if (symbols_enabled) {
			nelt->symbols_enabled = ucl_object_ref (symbols_enabled);
		}

		if (symbols_disabled) {
			nelt->symbols_disabled = ucl_object_ref (symbols_disabled);
		}

		nelt->policy = policy;

		REF_INIT_RETAIN (nelt, rspamd_config_settings_elt_dtor);
		msg_warn_config ("replace settings id %ud (%s)", id, name);
		rspamd_symcache_process_settings_elt (cfg->cache, elt);
		DL_APPEND (cfg->setting_ids, nelt);

		/*
		 * Need to unref old element twice as there are two reference holders:
		 * 1. Config structure as we call REF_INIT_RETAIN
		 * 2. rspamd_config_find_settings_id_ref also increases refcount
		 */
		REF_RELEASE (elt);
		REF_RELEASE (elt);
	}
	else {
		elt = rspamd_mempool_alloc0 (cfg->cfg_pool, sizeof (*elt));

		elt->id = id;
		elt->name = rspamd_mempool_strdup (cfg->cfg_pool, name);

		if (symbols_enabled) {
			elt->symbols_enabled = ucl_object_ref (symbols_enabled);
		}

		if (symbols_disabled) {
			elt->symbols_disabled = ucl_object_ref (symbols_disabled);
		}

		elt->policy = policy;

		msg_info_config ("register new settings id %ud (%s)", id, name);
		REF_INIT_RETAIN (elt, rspamd_config_settings_elt_dtor);
		rspamd_symcache_process_settings_elt (cfg->cache, elt);
		DL_APPEND (cfg->setting_ids, elt);
	}
}

int
rspamd_config_ev_backend_get (struct rspamd_config *cfg)
{
#define AUTO_BACKEND (ev_supported_backends () & ~EVBACKEND_IOURING)
	if (cfg == NULL || cfg->events_backend == NULL) {
		return AUTO_BACKEND;
	}

	if (strcmp (cfg->events_backend, "auto") == 0) {
		return AUTO_BACKEND;
	}
	else if (strcmp (cfg->events_backend, "epoll") == 0) {
		if (ev_supported_backends () & EVBACKEND_EPOLL) {
			return EVBACKEND_EPOLL;
		}
		else {
			msg_warn_config ("unsupported events_backend: %s; defaulting to auto",
					cfg->events_backend);
			return AUTO_BACKEND;
		}
	}
	else if (strcmp (cfg->events_backend, "iouring") == 0) {
		if (ev_supported_backends () & EVBACKEND_IOURING) {
			return EVBACKEND_IOURING;
		}
		else {
			msg_warn_config ("unsupported events_backend: %s; defaulting to auto",
					cfg->events_backend);
			return AUTO_BACKEND;
		}
	}
	else if (strcmp (cfg->events_backend, "kqueue") == 0) {
		if (ev_supported_backends () & EVBACKEND_KQUEUE) {
			return EVBACKEND_KQUEUE;
		}
		else {
			msg_warn_config ("unsupported events_backend: %s; defaulting to auto",
					cfg->events_backend);
			return AUTO_BACKEND;
		}
	}
	else if (strcmp (cfg->events_backend, "poll") == 0) {
		return EVBACKEND_POLL;
	}
	else if (strcmp (cfg->events_backend, "select") == 0) {
		return EVBACKEND_SELECT;
	}
	else {
		msg_warn_config ("unknown events_backend: %s; defaulting to auto",
				cfg->events_backend);
	}

	return AUTO_BACKEND;
}

const gchar *
rspamd_config_ev_backend_to_string (int ev_backend, gboolean *effective)
{
#define SET_EFFECTIVE(b) do { if ((effective) != NULL) *(effective) = b; } while(0)

	if ((ev_backend & EVBACKEND_ALL) == EVBACKEND_ALL) {
		SET_EFFECTIVE (TRUE);
		return "auto";
	}

	if (ev_backend & EVBACKEND_IOURING) {
		SET_EFFECTIVE (TRUE);
		return "epoll+io_uring";
	}
	if (ev_backend & EVBACKEND_LINUXAIO) {
		SET_EFFECTIVE (TRUE);
		return "epoll+aio";
	}if (ev_backend & EVBACKEND_IOURING) {
		SET_EFFECTIVE (TRUE);
		return "epoll+io_uring";
	}
	if (ev_backend & EVBACKEND_LINUXAIO) {
		SET_EFFECTIVE (TRUE);
		return "epoll+aio";
	}
	if (ev_backend & EVBACKEND_EPOLL) {
		SET_EFFECTIVE (TRUE);
		return "epoll";
	}
	if (ev_backend & EVBACKEND_KQUEUE) {
		SET_EFFECTIVE (TRUE);
		return "kqueue";
	}
	if (ev_backend & EVBACKEND_POLL) {
		SET_EFFECTIVE (FALSE);
		return "poll";
	}
	if (ev_backend & EVBACKEND_SELECT) {
		SET_EFFECTIVE (FALSE);
		return "select";
	}

	SET_EFFECTIVE (FALSE);
	return "unknown";
#undef SET_EFFECTIVE
}

struct rspamd_external_libs_ctx *
rspamd_init_libs (void)
{
	struct rlimit rlim;
	struct rspamd_external_libs_ctx *ctx;
	struct ottery_config *ottery_cfg;

	ctx = g_malloc0 (sizeof (*ctx));
	ctx->crypto_ctx = rspamd_cryptobox_init ();
	ottery_cfg = g_malloc0 (ottery_get_sizeof_config ());
	ottery_config_init (ottery_cfg);
	ctx->ottery_cfg = ottery_cfg;

	rspamd_openssl_maybe_init ();

	/* Check if we have rdrand */
	if ((ctx->crypto_ctx->cpu_config & CPUID_RDRAND) == 0) {
		ottery_config_disable_entropy_sources (ottery_cfg,
				OTTERY_ENTROPY_SRC_RDRAND);
#if OPENSSL_VERSION_NUMBER >= 0x1000104fL && !defined(LIBRESSL_VERSION_NUMBER)
		RAND_set_rand_engine (NULL);
#endif
	}

	/* Configure utf8 library */
	guint utf8_flags = 0;

	if ((ctx->crypto_ctx->cpu_config & CPUID_SSE41)) {
		utf8_flags |= RSPAMD_FAST_UTF8_FLAG_SSE41;
	}
	if ((ctx->crypto_ctx->cpu_config & CPUID_AVX2)) {
		utf8_flags |= RSPAMD_FAST_UTF8_FLAG_AVX2;
	}

	rspamd_fast_utf8_library_init (utf8_flags);

	g_assert (ottery_init (ottery_cfg) == 0);

#ifdef HAVE_LOCALE_H
	if (getenv ("LANG") == NULL) {
		setlocale (LC_ALL, "C");
		setlocale (LC_CTYPE, "C");
		setlocale (LC_MESSAGES, "C");
		setlocale (LC_TIME, "C");
	}
	else {
		/* Just set the default locale */
		setlocale (LC_ALL, "");
		/* But for some issues we still want C locale */
		setlocale (LC_NUMERIC, "C");
	}
#endif

	ctx->ssl_ctx = rspamd_init_ssl_ctx ();
	ctx->ssl_ctx_noverify = rspamd_init_ssl_ctx_noverify ();
	rspamd_random_seed_fast ();

	/* Set stack size for pcre */
	getrlimit (RLIMIT_STACK, &rlim);
	rlim.rlim_cur = 100 * 1024 * 1024;
	rlim.rlim_max = rlim.rlim_cur;
	setrlimit (RLIMIT_STACK, &rlim);

	ctx->local_addrs = rspamd_inet_library_init ();
	REF_INIT_RETAIN (ctx, rspamd_deinit_libs);

	return ctx;
}

static struct zstd_dictionary *
rspamd_open_zstd_dictionary (const char *path)
{
	struct zstd_dictionary *dict;

	dict = g_malloc0 (sizeof (*dict));
	dict->dict = rspamd_file_xmap (path, PROT_READ, &dict->size, TRUE);

	if (dict->dict == NULL) {
		g_free (dict);

		return NULL;
	}

	dict->id = -1;

	if (dict->id == 0) {
		g_free (dict);

		return NULL;
	}

	return dict;
}

static void
rspamd_free_zstd_dictionary (struct zstd_dictionary *dict)
{
	if (dict) {
		munmap (dict->dict, dict->size);
		g_free (dict);
	}
}

#ifdef HAVE_OPENBLAS_SET_NUM_THREADS
extern void openblas_set_num_threads(int num_threads);
#endif
#ifdef HAVE_BLI_THREAD_SET_NUM_THREADS
extern void bli_thread_set_num_threads(int num_threads);
#endif

gboolean
rspamd_config_libs (struct rspamd_external_libs_ctx *ctx,
					struct rspamd_config *cfg)
{
	size_t r;
	gboolean ret = TRUE;

	g_assert (cfg != NULL);

	if (ctx != NULL) {
		if (cfg->local_addrs) {
			rspamd_config_radix_from_ucl (cfg, cfg->local_addrs,
					"Local addresses",
					(struct rspamd_radix_map_helper **) ctx->local_addrs,
					NULL,
					NULL, "local addresses");
		}

		rspamd_free_zstd_dictionary (ctx->in_dict);
		rspamd_free_zstd_dictionary (ctx->out_dict);

		if (ctx->out_zstream) {
			ZSTD_freeCStream (ctx->out_zstream);
			ctx->out_zstream = NULL;
		}

		if (ctx->in_zstream) {
			ZSTD_freeDStream (ctx->in_zstream);
			ctx->in_zstream = NULL;
		}

		if (cfg->zstd_input_dictionary) {
			ctx->in_dict = rspamd_open_zstd_dictionary (
					cfg->zstd_input_dictionary);

			if (ctx->in_dict == NULL) {
				msg_err_config ("cannot open zstd dictionary in %s",
						cfg->zstd_input_dictionary);
			}
		}
		if (cfg->zstd_output_dictionary) {
			ctx->out_dict = rspamd_open_zstd_dictionary (
					cfg->zstd_output_dictionary);

			if (ctx->out_dict == NULL) {
				msg_err_config ("cannot open zstd dictionary in %s",
						cfg->zstd_output_dictionary);
			}
		}

		if (cfg->fips_mode) {
#ifdef HAVE_FIPS_MODE
			int mode = FIPS_mode ();
			unsigned long err = (unsigned long)-1;

			/* Toggle FIPS mode */
			if (mode == 0) {
#if defined(OPENSSL_VERSION_MAJOR) && (OPENSSL_VERSION_MAJOR >= 3)
				if (EVP_set_default_properties (NULL, "fips=yes") != 1) {
#else
				if (FIPS_mode_set (1) != 1) {
#endif
					err = ERR_get_error ();
				}
			}
			else {
				msg_info_config ("OpenSSL FIPS mode is already enabled");
			}

			if (err != (unsigned long)-1) {
#if defined(OPENSSL_VERSION_MAJOR) && (OPENSSL_VERSION_MAJOR >= 3)
				msg_err_config ("EVP_set_default_properties failed: %s",
#else
				msg_err_config ("FIPS_mode_set failed: %s",
#endif
						ERR_error_string (err, NULL));
				ret = FALSE;
			}
			else {
				msg_info_config ("OpenSSL FIPS mode is enabled");
			}
#else
			msg_warn_config ("SSL FIPS mode is enabled but not supported by OpenSSL library!");
#endif
		}

		rspamd_ssl_ctx_config (cfg, ctx->ssl_ctx);
		rspamd_ssl_ctx_config (cfg, ctx->ssl_ctx_noverify);

		/* Init decompression */
		ctx->in_zstream = ZSTD_createDStream ();
		r = ZSTD_initDStream (ctx->in_zstream);

		if (ZSTD_isError (r)) {
			msg_err ("cannot init decompression stream: %s",
					ZSTD_getErrorName (r));
			ZSTD_freeDStream (ctx->in_zstream);
			ctx->in_zstream = NULL;
		}

		/* Init compression */
		ctx->out_zstream = ZSTD_createCStream ();
		r = ZSTD_initCStream (ctx->out_zstream, 1);

		if (ZSTD_isError (r)) {
			msg_err ("cannot init compression stream: %s",
					ZSTD_getErrorName (r));
			ZSTD_freeCStream (ctx->out_zstream);
			ctx->out_zstream = NULL;
		}
#ifdef HAVE_OPENBLAS_SET_NUM_THREADS
		openblas_set_num_threads (cfg->max_blas_threads);
#endif
#ifdef HAVE_BLI_THREAD_SET_NUM_THREADS
		bli_thread_set_num_threads (cfg->max_blas_threads);
#endif

	}

	return ret;
}

gboolean
rspamd_libs_reset_decompression (struct rspamd_external_libs_ctx *ctx)
{
	gsize r;

	if (ctx->in_zstream == NULL) {
		return FALSE;
	}
	else {
		r = ZSTD_resetDStream (ctx->in_zstream);

		if (ZSTD_isError (r)) {
			msg_err ("cannot init decompression stream: %s",
					ZSTD_getErrorName (r));
			ZSTD_freeDStream (ctx->in_zstream);
			ctx->in_zstream = NULL;

			return FALSE;
		}
	}

	return TRUE;
}

gboolean
rspamd_libs_reset_compression (struct rspamd_external_libs_ctx *ctx)
{
	gsize r;

	if (ctx->out_zstream == NULL) {
		return FALSE;
	}
	else {
		/* Dictionary will be reused automatically if specified */
		r = ZSTD_resetCStream (ctx->out_zstream, 0);

		if (ZSTD_isError (r)) {
			msg_err ("cannot init compression stream: %s",
					ZSTD_getErrorName (r));
			ZSTD_freeCStream (ctx->out_zstream);
			ctx->out_zstream = NULL;

			return FALSE;
		}
	}

	return TRUE;
}

void
rspamd_deinit_libs (struct rspamd_external_libs_ctx *ctx)
{
	if (ctx != NULL) {
		g_free (ctx->ottery_cfg);

#ifdef HAVE_OPENSSL
		EVP_cleanup ();
		ERR_free_strings ();
		rspamd_ssl_ctx_free (ctx->ssl_ctx);
		rspamd_ssl_ctx_free (ctx->ssl_ctx_noverify);
#endif
		rspamd_inet_library_destroy ();
		rspamd_free_zstd_dictionary (ctx->in_dict);
		rspamd_free_zstd_dictionary (ctx->out_dict);

		if (ctx->out_zstream) {
			ZSTD_freeCStream (ctx->out_zstream);
		}

		if (ctx->in_zstream) {
			ZSTD_freeDStream (ctx->in_zstream);
		}

		rspamd_cryptobox_deinit (ctx->crypto_ctx);

		g_free (ctx);
	}
}

gboolean
rspamd_ip_is_local_cfg (struct rspamd_config *cfg,
								 const rspamd_inet_addr_t *addr)
{
	struct rspamd_radix_map_helper *local_addrs = NULL;

	if (cfg && cfg->libs_ctx) {
		local_addrs = *(struct rspamd_radix_map_helper**)cfg->libs_ctx->local_addrs;
	}

	if (rspamd_inet_address_is_local (addr)) {
		return TRUE;
	}

	if (local_addrs) {
		if (rspamd_match_radix_map_addr (local_addrs, addr) != NULL) {
			return TRUE;
		}
	}

	return FALSE;
}
