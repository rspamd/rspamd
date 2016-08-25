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
#include "uthash_strcase.h"
#include "filter.h"
#include "lua/lua_common.h"
#include "map.h"
#include "map_private.h"
#include "dynamic_cfg.h"
#include "utlist.h"
#include "stat_api.h"
#include "unix-std.h"
#include "libutil/multipattern.h"
#include <math.h>

#define DEFAULT_SCORE 10.0

#define DEFAULT_RLIMIT_NOFILE 2048
#define DEFAULT_RLIMIT_MAXCORE 0
#define DEFAULT_MAP_TIMEOUT 10
#define DEFAULT_MIN_WORD 4
#define DEFAULT_MAX_WORD 40
#define DEFAULT_WORDS_DECAY 200
#define DEFAULT_MAX_MESSAGE (50 * 1024 * 1024)

struct rspamd_ucl_map_cbdata {
	struct rspamd_config *cfg;
	GString *buf;
};
static gchar * rspamd_ucl_read_cb (gchar * chunk,
	gint len,
	struct map_cb_data *data,
	gboolean final);
static void rspamd_ucl_fin_cb (struct map_cb_data *data);

gboolean
rspamd_parse_bind_line (struct rspamd_config *cfg,
	struct rspamd_worker_conf *cf,
	const gchar *str)
{
	struct rspamd_worker_bind_conf *cnf;
	gchar *err;
	gboolean ret = TRUE;

	if (str == NULL) {
		return FALSE;
	}

	cnf =
		rspamd_mempool_alloc0 (cfg->cfg_pool,
			sizeof (struct rspamd_worker_bind_conf));

	cnf->cnt = 1024;

	if (g_ascii_strncasecmp (str, "systemd:", sizeof ("systemd:") - 1) == 0) {
		/* The actual socket will be passed by systemd environment */
		cnf->is_systemd = TRUE;
		cnf->cnt = strtoul (str + sizeof ("systemd:") - 1, &err, 10);
		cnf->addrs = NULL;

		if (err == NULL || *err == '\0') {
			cnf->name = rspamd_mempool_strdup (cfg->cfg_pool, str);
			LL_PREPEND (cf->bind_conf, cnf);
		}
		else {
			msg_err_config ("cannot parse bind line: %s", str);
			ret = FALSE;
		}
	}
	else {
		if (!rspamd_parse_host_port_priority (str, &cnf->addrs,
				NULL, &cnf->name, DEFAULT_BIND_PORT, cfg->cfg_pool)) {
			msg_err_config ("cannot parse bind line: %s", str);
			ret = FALSE;
		}
		else {
			cnf->cnt = cnf->addrs->len;
			LL_PREPEND (cf->bind_conf, cnf);
		}
	}

	return ret;
}

struct rspamd_config *
rspamd_config_new (void)
{
	struct rspamd_config *cfg;

	cfg = g_slice_alloc0 (sizeof (*cfg));
	cfg->cfg_pool = rspamd_mempool_new (rspamd_mempool_suggest_size (), "cfg");
	cfg->dns_timeout = 1000;
	cfg->dns_retransmits = 5;
	/* After 20 errors do throttling for 10 seconds */
	cfg->dns_throttling_errors = 20;
	cfg->dns_throttling_time = 10000;
	/* 16 sockets per DNS server */
	cfg->dns_io_per_server = 16;

	/* 20 Kb */
	cfg->max_diff = 20480;

	cfg->metrics = g_hash_table_new (rspamd_str_hash, rspamd_str_equal);
	if (cfg->c_modules == NULL) {
		cfg->c_modules = g_hash_table_new (rspamd_str_hash, rspamd_str_equal);
	}
	cfg->composite_symbols =
		g_hash_table_new (rspamd_str_hash, rspamd_str_equal);
	cfg->classifiers_symbols = g_hash_table_new (rspamd_str_hash,
			rspamd_str_equal);
	cfg->cfg_params = g_hash_table_new (rspamd_str_hash, rspamd_str_equal);
	cfg->metrics_symbols = g_hash_table_new (rspamd_str_hash, rspamd_str_equal);
	cfg->debug_modules = g_hash_table_new (rspamd_str_hash, rspamd_str_equal);
	cfg->explicit_modules = g_hash_table_new (rspamd_str_hash, rspamd_str_equal);
	cfg->wrk_parsers = g_hash_table_new (g_int_hash, g_int_equal);
	cfg->trusted_keys = g_hash_table_new (rspamd_str_hash,
				rspamd_str_equal);

	cfg->map_timeout = DEFAULT_MAP_TIMEOUT;

	cfg->log_level = G_LOG_LEVEL_WARNING;
	cfg->log_extended = TRUE;

	cfg->dns_max_requests = 64;
	cfg->history_rows = 200;

	/* Default log line */
	cfg->log_format_str = "id: <$mid>,$if_qid{ qid: <$>,}$if_ip{ ip: $,}"
			"$if_user{ user: $,}$if_smtp_from{ from: <$>,} (default: $is_spam "
			"($action): [$scores] [$symbols]), len: $len, time: $time_real real,"
			" $time_virtual virtual, dns req: $dns_req";
	/* Allow non-mime input by default */
	cfg->allow_raw_input = TRUE;
	/* Default maximum words processed */
	cfg->words_decay = DEFAULT_WORDS_DECAY;
	cfg->min_word_len = DEFAULT_MIN_WORD;
	cfg->max_word_len = DEFAULT_MAX_WORD;

	cfg->lua_state = rspamd_lua_init ();
	cfg->cache = rspamd_symbols_cache_new (cfg);
	cfg->ups_ctx = rspamd_upstreams_library_init ();
	cfg->re_cache = rspamd_re_cache_new ();
	cfg->doc_strings = ucl_object_typed_new (UCL_OBJECT);
	/*
	 * Unless exim is fixed
	 */
	cfg->enable_shutdown_workaround = TRUE;

	cfg->ssl_ciphers = "HIGH:!aNULL:!kRSA:!PSK:!SRP:!MD5:!RC4";
	cfg->max_message = DEFAULT_MAX_MESSAGE;

	REF_INIT_RETAIN (cfg, rspamd_config_free);

	return cfg;
}

void
rspamd_config_free (struct rspamd_config *cfg)
{
	struct rspamd_dynamic_module *dyn_mod;
	struct rspamd_dynamic_worker *dyn_wrk;
	struct rspamd_config_post_load_script *sc, *sctmp;
	GList *cur;

	rspamd_map_remove_all (cfg);
	ucl_object_unref (cfg->rcl_obj);
	ucl_object_unref (cfg->config_comments);
	ucl_object_unref (cfg->doc_strings);
	g_hash_table_remove_all (cfg->metrics);
	g_hash_table_unref (cfg->metrics);
	g_hash_table_unref (cfg->c_modules);
	g_hash_table_remove_all (cfg->composite_symbols);
	g_hash_table_unref (cfg->composite_symbols);
	g_hash_table_remove_all (cfg->cfg_params);
	g_hash_table_unref (cfg->cfg_params);
	g_hash_table_destroy (cfg->metrics_symbols);
	g_hash_table_unref (cfg->classifiers_symbols);
	g_hash_table_unref (cfg->debug_modules);
	g_hash_table_unref (cfg->explicit_modules);
	g_hash_table_unref (cfg->wrk_parsers);
	g_hash_table_unref (cfg->trusted_keys);

	if (cfg->checksum) {
		g_free (cfg->checksum);
	}

	/* Unload dynamic workers/modules */
	cur = g_list_first (cfg->dynamic_modules);
	while (cur) {
		dyn_mod = cur->data;

		if (dyn_mod->lib) {
			g_module_close (dyn_mod->lib);
		}

		cur = g_list_next (cur);
	}
	cur = g_list_first (cfg->dynamic_workers);
	while (cur) {
		dyn_wrk = cur->data;

		if (dyn_wrk->lib) {
			g_module_close (dyn_wrk->lib);
		}

		cur = g_list_next (cur);
	}

	DL_FOREACH_SAFE (cfg->finish_callbacks, sc, sctmp) {
		luaL_unref (cfg->lua_state, LUA_REGISTRYINDEX, sc->cbref);
		g_slice_free1 (sizeof (*sc), sc);
	}

	DL_FOREACH_SAFE (cfg->on_load, sc, sctmp) {
		luaL_unref (cfg->lua_state, LUA_REGISTRYINDEX, sc->cbref);
		g_slice_free1 (sizeof (*sc), sc);
	}

	g_list_free (cfg->classifiers);
	g_list_free (cfg->metrics_list);
	rspamd_symbols_cache_destroy (cfg->cache);
	REF_RELEASE (cfg->libs_ctx);
	rspamd_re_cache_unref (cfg->re_cache);
	rspamd_upstreams_library_unref (cfg->ups_ctx);
	rspamd_mempool_delete (cfg->cfg_pool);
	lua_close (cfg->lua_state);
	g_slice_free1 (sizeof (*cfg), cfg);
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
		flags |= RSPAMD_LOG_FLAG_CONDITION;
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
		flags |= RSPAMD_LOG_FLAG_SYMBOLS_SCORES;
	}
	else if (rspamd_ftok_cstr_equal (&tok, "symbols_params", TRUE)) {
		type = RSPAMD_LOG_SYMBOLS;
		flags |= RSPAMD_LOG_FLAG_SYMBOLS_PARAMS;
	}
	else if (rspamd_ftok_cstr_equal (&tok, "symbols_scores_params", TRUE)) {
		type = RSPAMD_LOG_SYMBOLS;
		flags |= RSPAMD_LOG_FLAG_SYMBOLS_PARAMS|RSPAMD_LOG_FLAG_SYMBOLS_SCORES;
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
	struct metric *def_metric;
	struct rspamd_config_post_load_script *sc;
	struct rspamd_config **pcfg;
	gboolean ret = TRUE;

#ifdef HAVE_CLOCK_GETTIME
#ifdef HAVE_CLOCK_PROCESS_CPUTIME_ID
	clock_getres (CLOCK_PROCESS_CPUTIME_ID, &ts);
# elif defined(HAVE_CLOCK_VIRTUAL)
	clock_getres (CLOCK_VIRTUAL,			&ts);
# else
	clock_getres (CLOCK_REALTIME,			&ts);
# endif

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

	rspamd_regexp_library_init ();
	rspamd_multipattern_library_init (cfg->hs_cache_dir,
			cfg->libs_ctx->crypto_ctx);

#ifdef WITH_HYPERSCAN
	if (!cfg->disable_hyperscan) {
		if (!(cfg->libs_ctx->crypto_ctx->cpu_config & CPUID_SSSE3)) {
			msg_warn_config ("CPU doesn't have SSSE3 instructions set "
					"required for hyperscan, disable it");
			cfg->disable_hyperscan = TRUE;
		}
	}
#endif

	if ((def_metric =
		g_hash_table_lookup (cfg->metrics, DEFAULT_METRIC)) == NULL) {
		def_metric = rspamd_config_new_metric (cfg, NULL, DEFAULT_METRIC);
		def_metric->actions[METRIC_ACTION_REJECT].score = DEFAULT_SCORE;
	}

	if (opts & RSPAMD_CONFIG_INIT_URL) {
		if (cfg->tld_file == NULL) {
			/* Try to guess tld file */
			GString *fpath = g_string_new (NULL);

			rspamd_printf_gstring (fpath, "%s%c%s", RSPAMD_PLUGINSDIR,
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

		rspamd_url_init (cfg->tld_file);
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
		rspamd_symbols_cache_init (cfg->cache);

		/* Init re cache */
		rspamd_re_cache_init (cfg->re_cache, cfg);
	}

	if (opts & RSPAMD_CONFIG_INIT_LIBS) {
		/* Config other libraries */
		rspamd_config_libs (cfg->libs_ctx, cfg);
	}

	/* Execute post load scripts */
	LL_FOREACH (cfg->on_load, sc) {
		lua_rawgeti (cfg->lua_state, LUA_REGISTRYINDEX, sc->cbref);
		pcfg = lua_newuserdata (cfg->lua_state, sizeof (*pcfg));
		*pcfg = cfg;
		rspamd_lua_setclass (cfg->lua_state, "rspamd{config}", -1);

		if (lua_pcall (cfg->lua_state, 1, 0, 0) != 0) {
			msg_err_config ("error executing post load code: %s",
					lua_tostring (cfg->lua_state, -1));
			lua_pop (cfg->lua_state, 1);

			return FALSE;
		}
	}

	/* Validate cache */
	if (opts & RSPAMD_CONFIG_INIT_VALIDATE) {
		return rspamd_symbols_cache_validate (cfg->cache, cfg, FALSE) && ret;
	}

	return ret;
}

#if 0
void
parse_err (const gchar *fmt, ...)
{
	va_list aq;
	gchar logbuf[BUFSIZ], readbuf[32];
	gint r;

	va_start (aq, fmt);
	rspamd_strlcpy (readbuf, yytext, sizeof (readbuf));

	r = snprintf (logbuf,
			sizeof (logbuf),
			"config file parse error! line: %d, text: %s, reason: ",
			yylineno,
			readbuf);
	r += vsnprintf (logbuf + r, sizeof (logbuf) - r, fmt, aq);

	va_end (aq);
	g_critical ("%s", logbuf);
}

void
parse_warn (const gchar *fmt, ...)
{
	va_list aq;
	gchar logbuf[BUFSIZ], readbuf[32];
	gint r;

	va_start (aq, fmt);
	rspamd_strlcpy (readbuf, yytext, sizeof (readbuf));

	r = snprintf (logbuf,
			sizeof (logbuf),
			"config file parse warning! line: %d, text: %s, reason: ",
			yylineno,
			readbuf);
	r += vsnprintf (logbuf + r, sizeof (logbuf) - r, fmt, aq);

	va_end (aq);
	g_warning ("%s", logbuf);
}
#endif

void
rspamd_config_unescape_quotes (gchar *line)
{
	gchar *c = line, *t;

	while (*c) {
		if (*c == '\\' && *(c + 1) == '"') {
			t = c;
			while (*t) {
				*t = *(t + 1);
				t++;
			}
		}
		c++;
	}
}

GList *
rspamd_config_parse_comma_list (rspamd_mempool_t * pool, const gchar *line)
{
	GList *res = NULL;
	const gchar *c, *p;
	gchar *str;

	c = line;
	p = c;

	while (*p) {
		if (*p == ',' && *c != *p) {
			str = rspamd_mempool_alloc (pool, p - c + 1);
			rspamd_strlcpy (str, c, p - c + 1);
			res = g_list_prepend (res, str);
			/* Skip spaces */
			while (g_ascii_isspace (*(++p))) ;
			c = p;
			continue;
		}
		p++;
	}
	if (res != NULL) {
		rspamd_mempool_add_destructor (pool,
			(rspamd_mempool_destruct_t) g_list_free,
			res);
	}

	return res;
}

struct rspamd_classifier_config *
rspamd_config_new_classifier (struct rspamd_config *cfg,
	struct rspamd_classifier_config *c)
{
	if (c == NULL) {
		c =
			rspamd_mempool_alloc0 (cfg->cfg_pool,
				sizeof (struct rspamd_classifier_config));
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

struct metric *
rspamd_config_new_metric (struct rspamd_config *cfg, struct metric *c,
		const gchar *name)
{
	int i;

	if (c == NULL) {
		c = rspamd_mempool_alloc0 (cfg->cfg_pool, sizeof (struct metric));
		c->grow_factor = 1.0;
		c->symbols = g_hash_table_new (rspamd_str_hash, rspamd_str_equal);
		c->groups = g_hash_table_new (rspamd_strcase_hash, rspamd_strcase_equal);

		for (i = METRIC_ACTION_REJECT; i < METRIC_ACTION_MAX; i++) {
			c->actions[i].score = NAN;
			c->actions[i].action = i;
			c->actions[i].priority = 0;
		}

		c->subject = SPAM_SUBJECT;
		c->name = rspamd_mempool_strdup (cfg->cfg_pool, name);
		rspamd_mempool_add_destructor (cfg->cfg_pool,
			(rspamd_mempool_destruct_t) g_hash_table_unref,
			c->symbols);
		rspamd_mempool_add_destructor (cfg->cfg_pool,
			(rspamd_mempool_destruct_t) g_hash_table_unref,
			c->groups);

		g_hash_table_insert (cfg->metrics, (void *)c->name, c);
		cfg->metrics_list = g_list_prepend (cfg->metrics_list, c);

		if (strcmp (c->name, DEFAULT_METRIC) == 0) {
			cfg->default_metric = c;
		}
	}

	return c;
}

struct rspamd_symbols_group *
rspamd_config_new_group (struct rspamd_config *cfg, struct metric *metric,
		const gchar *name)
{
	struct rspamd_symbols_group *gr;

	gr = rspamd_mempool_alloc0 (cfg->cfg_pool, sizeof (*gr));
	gr->symbols = g_hash_table_new (rspamd_strcase_hash,
			rspamd_strcase_equal);
	rspamd_mempool_add_destructor (cfg->cfg_pool,
			(rspamd_mempool_destruct_t)g_hash_table_unref, gr->symbols);
	gr->name = rspamd_mempool_strdup (cfg->cfg_pool, name);

	g_hash_table_insert (metric->groups, gr->name, gr);

	return gr;
}

struct rspamd_worker_conf *
rspamd_config_new_worker (struct rspamd_config *cfg,
	struct rspamd_worker_conf *c)
{
	if (c == NULL) {
		c =
			rspamd_mempool_alloc0 (cfg->cfg_pool,
				sizeof (struct rspamd_worker_conf));
		c->params = g_hash_table_new (rspamd_str_hash, rspamd_str_equal);
		c->active_workers = g_queue_new ();
		rspamd_mempool_add_destructor (cfg->cfg_pool,
			(rspamd_mempool_destruct_t)g_hash_table_destroy,
			c->params);
		rspamd_mempool_add_destructor (cfg->cfg_pool,
			(rspamd_mempool_destruct_t)g_queue_free,
			c->active_workers);
#ifdef HAVE_SC_NPROCESSORS_ONLN
		c->count = sysconf (_SC_NPROCESSORS_ONLN);
#else
		c->count = DEFAULT_WORKERS_NUM;
#endif
		c->rlimit_nofile = 0;
		c->rlimit_maxcore = 0;
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
			   (void **)pcbdata);
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
#define RSPAMD_RULESDIR_MACRO "RULESDIR"
#define RSPAMD_WWWDIR_MACRO "WWWDIR"
#define RSPAMD_PREFIX_MACRO "PREFIX"
#define RSPAMD_VERSION_MACRO "VERSION"
#define RSPAMD_VERSION_MAJOR_MACRO "VERSION_MAJOR"
#define RSPAMD_VERSION_MINOR_MACRO "VERSION_MINOR"
#define RSPAMD_VERSION_PATCH_MACRO "VERSION_PATCH"
#define RSPAMD_BRANCH_VERSION_MACRO "BRANCH_VERSION"

void
rspamd_ucl_add_conf_variables (struct ucl_parser *parser, GHashTable *vars)
{
	GHashTableIter it;
	gpointer k, v;

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
	ucl_parser_register_variable (parser, RSPAMD_VERSION_PATCH_MACRO,
			RSPAMD_VERSION_PATCH);
	ucl_parser_register_variable (parser, RSPAMD_BRANCH_VERSION_MACRO,
			RSPAMD_VERSION_BRANCH);

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
	rspamd_symbols_cache_add_symbol (cfg->cache, key, 0, NULL, NULL,
			SYMBOL_TYPE_CLASSIFIER, -1);
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
	gboolean has_other = FALSE, res = FALSE, cur_class;
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
		if (rspamd_strncasestr (st->symbol, "spam", -1) != NULL) {
			st->is_spam = TRUE;
		}
		else if (rspamd_strncasestr (st->symbol, "ham", -1) != NULL) {
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
rspamd_ucl_fin_cb (struct map_cb_data *data)
{
	struct rspamd_ucl_map_cbdata *cbdata = data->cur_data, *prev =
		data->prev_data;
	ucl_object_t *obj;
	struct ucl_parser *parser;
	guint32 checksum;
	ucl_object_iter_t it = NULL;
	const ucl_object_t *cur;
	struct rspamd_config *cfg = data->map->cfg;

	if (prev != NULL) {
		if (prev->buf != NULL) {
			g_string_free (prev->buf, TRUE);
		}
		g_free (prev);
	}

	if (cbdata == NULL) {
		msg_err_config ("map fin error: new data is NULL");
		return;
	}

	checksum = rspamd_cryptobox_fast_hash (cbdata->buf->str, cbdata->buf->len, 0);
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
}

gboolean
rspamd_check_module (struct rspamd_config *cfg, module_t *mod)
{
	gboolean ret = TRUE;

	if (mod != NULL) {
		if (mod->module_version != RSPAMD_CUR_MODULE_VERSION) {
			msg_err_config ("module %s has incorrect version %xd (%xd expected)",
					mod->name, mod->module_version, RSPAMD_CUR_MODULE_VERSION);
			ret = FALSE;
		}
		if (ret && mod->rspamd_version != RSPAMD_VERSION_NUM) {
			msg_err_config ("module %s has incorrect rspamd version %xd (%xd expected)",
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
			msg_err_config ("worker %s has incorrect rspamd version %xd (%xd expected)",
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
rspamd_init_filters (struct rspamd_config *cfg, bool reconfig)
{
	GList *cur;
	module_t *mod, **pmod;
	struct rspamd_dynamic_module *dyn_mod;
	struct module_ctx *mod_ctx;

	/* Init all compiled modules */
	if (!reconfig) {
		for (pmod = cfg->compiled_modules; pmod != NULL && *pmod != NULL; pmod ++) {
			mod = *pmod;

			if (rspamd_check_module (cfg, mod)) {
				mod_ctx = g_slice_alloc0 (sizeof (struct module_ctx));

				if (mod->module_init_func (cfg, &mod_ctx) == 0) {
					g_hash_table_insert (cfg->c_modules,
							(gpointer) mod->name,
							mod_ctx);
					mod_ctx->mod = mod;
				}
			}
		}

		cur = g_list_first (cfg->dynamic_modules);

		while (cur) {
			dyn_mod = cur->data;

			if (dyn_mod->lib) {
				mod = &dyn_mod->mod;

				if (rspamd_check_module (cfg, mod)) {
					mod_ctx = g_slice_alloc0 (sizeof (struct module_ctx));

					if (mod->module_init_func (cfg, &mod_ctx) == 0) {
						g_hash_table_insert (cfg->c_modules,
								(gpointer) mod->name,
								mod_ctx);
						mod_ctx->mod = mod;
					}
				}
			}

			cur = g_list_next (cur);
		}
	}

	/* Now check what's enabled */
	cur = g_list_first (cfg->filters);

	while (cur) {
		/* Perform modules configuring */
		mod_ctx = NULL;
		mod_ctx = g_hash_table_lookup (cfg->c_modules, cur->data);

		if (mod_ctx) {
			mod = mod_ctx->mod;
			mod_ctx->enabled = TRUE;

			if (reconfig) {
				(void)mod->module_reconfig_func (cfg);
				msg_info_config ("reconfig of %s", mod->name);
			}
			else {
				(void)mod->module_config_func (cfg);
			}
		}

		if (mod_ctx == NULL) {
			msg_warn_config ("requested unknown module %s", cur->data);
		}

		cur = g_list_next (cur);
	}

	return rspamd_init_lua_filters (cfg);
}

static void
rspamd_config_new_metric_symbol (struct rspamd_config *cfg,
		struct metric *metric, const gchar *symbol,
		gdouble score, const gchar *description, const gchar *group,
		guint flags, guint priority)
{
	struct rspamd_symbols_group *sym_group;
	struct rspamd_symbol_def *sym_def;
	GList *metric_list;
	gdouble *score_ptr;

	sym_def =
		rspamd_mempool_alloc0 (cfg->cfg_pool, sizeof (struct rspamd_symbol_def));
	score_ptr = rspamd_mempool_alloc (cfg->cfg_pool, sizeof (gdouble));

	*score_ptr = score;
	sym_def->score = score;
	sym_def->weight_ptr = score_ptr;
	sym_def->name = rspamd_mempool_strdup (cfg->cfg_pool, symbol);
	sym_def->priority = priority;
	sym_def->flags = flags;

	if (description) {
		sym_def->description = rspamd_mempool_strdup (cfg->cfg_pool, description);
	}

	msg_debug_config ("registered symbol %s with weight %.2f in metric %s and group %s",
			sym_def->name, score, metric->name, group);

	g_hash_table_insert (metric->symbols, sym_def->name, sym_def);

	if ((metric_list =
			g_hash_table_lookup (cfg->metrics_symbols, sym_def->name)) == NULL) {
		metric_list = g_list_prepend (NULL, metric);
		rspamd_mempool_add_destructor (cfg->cfg_pool,
				(rspamd_mempool_destruct_t)g_list_free,
				metric_list);
		g_hash_table_insert (cfg->metrics_symbols, sym_def->name, metric_list);
	}
	else {
		/* Slow but keep start element of list in safe */
		if (!g_list_find (metric_list, metric)) {
			metric_list = g_list_append (metric_list, metric);
		}
	}

	/* Search for symbol group */
	if (group == NULL) {
		group = "ungrouped";
	}

	sym_group = g_hash_table_lookup (metric->groups, group);
	if (sym_group == NULL) {
		/* Create new group */
		sym_group = rspamd_config_new_group (cfg, metric, group);
	}

	sym_def->gr = sym_group;
	g_hash_table_insert (sym_group->symbols, sym_def->name, sym_def);
}


gboolean
rspamd_config_add_metric_symbol (struct rspamd_config *cfg,
		const gchar *metric_name, const gchar *symbol,
		gdouble score, const gchar *description, const gchar *group,
		guint flags, guint priority)
{
	struct rspamd_symbol_def *sym_def;
	struct metric *metric;

	g_assert (cfg != NULL);
	g_assert (symbol != NULL);

	if (metric_name == NULL) {
		metric_name = DEFAULT_METRIC;
	}

	metric = g_hash_table_lookup (cfg->metrics, metric_name);

	if (metric == NULL) {
		msg_err_config ("metric %s has not been found", metric_name);
		return FALSE;
	}

	sym_def = g_hash_table_lookup (metric->symbols, symbol);

	if (sym_def != NULL) {
		if (sym_def->priority > priority) {
			msg_info_config ("symbol %s has been already registered with "
					"priority %ud, do not override (new priority: %ud)",
					symbol,
					sym_def->priority,
					priority);
			/* But we can still add description */
			if (!sym_def->description && description) {
				sym_def->description = rspamd_mempool_strdup (cfg->cfg_pool,
						description);
			}

			return FALSE;
		}
		else {
			msg_info_config ("symbol %s has been already registered with "
					"priority %ud, override it with new priority: %ud, "
					"old score: %.2f, new score: %.2f",
					symbol,
					sym_def->priority,
					priority,
					sym_def->score,
					score);

			*sym_def->weight_ptr = score;
			sym_def->score = score;
			sym_def->flags = flags;

			if (description) {
				sym_def->description = rspamd_mempool_strdup (cfg->cfg_pool,
						description);
			}

			sym_def->priority = priority;

			return TRUE;
		}
	}

	rspamd_config_new_metric_symbol (cfg, metric, symbol, score, description,
			group, flags, priority);

	return TRUE;
}

gboolean
rspamd_config_is_module_enabled (struct rspamd_config *cfg,
		const gchar *module_name)
{
	gboolean is_c = FALSE;
	struct metric *metric;
	const ucl_object_t *conf, *enabled;
	GList *cur;
	struct rspamd_symbols_group *gr;

	metric = cfg->default_metric;

	if (g_hash_table_lookup (cfg->c_modules, module_name)) {
		is_c = TRUE;
	}

	if (g_hash_table_lookup (cfg->explicit_modules, module_name) != NULL) {
		/* Always load module */
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

			return FALSE;
		}
	}

	conf = ucl_object_lookup (cfg->rcl_obj, module_name);

	if (conf == NULL) {
		msg_info_config ("%s module %s is enabled but has not been configured",
				is_c ? "internal" : "lua", module_name);

		if (!is_c) {
			msg_info_config ("%s disabling unconfigured lua module", module_name);
			return FALSE;
		}
	}
	else {
		enabled = ucl_object_lookup (conf, "enabled");

		if (enabled && ucl_object_type (enabled) == UCL_BOOLEAN) {
			if (!ucl_object_toboolean (enabled)) {
				msg_info_config ("%s module %s is disabled in the configuration",
						is_c ? "internal" : "lua", module_name);
				return FALSE;
			}
		}
	}

	if (metric) {
		/* Now we check symbols group */
		gr = g_hash_table_lookup (metric->groups, module_name);

		if (gr) {
			if (gr->disabled) {
				msg_info_config ("%s module %s is disabled in the configuration as "
						"its group has been disabled",
						is_c ? "internal" : "lua", module_name);
				return FALSE;
			}
		}
	}

	return TRUE;
}

gboolean
rspamd_config_set_action_score (struct rspamd_config *cfg,
		const gchar *metric_name,
		const gchar *action_name,
		gdouble score,
		guint priority)
{
	struct metric_action *act;
	struct metric *metric;
	gint act_num;

	g_assert (cfg != NULL);
	g_assert (action_name != NULL);

	if (metric_name == NULL) {
		metric_name = DEFAULT_METRIC;
	}

	metric = g_hash_table_lookup (cfg->metrics, metric_name);

	if (metric == NULL) {
		msg_err_config ("metric %s has not been found", metric_name);
		return FALSE;
	}

	if (!rspamd_action_from_str (action_name, &act_num)) {
		msg_err_config ("invalid action name", action_name);
		return FALSE;
	}

	g_assert (act_num >= METRIC_ACTION_REJECT && act_num < METRIC_ACTION_MAX);

	act = &metric->actions[act_num];

	if (isnan (act->score)) {
		act->score = score;
		act->priority = priority;
	}
	else {
		if (act->priority > priority) {
			msg_info_config ("action %s has been already registered with "
					"priority %ud, do not override (new priority: %ud)",
					action_name,
					act->priority,
					priority);
			return FALSE;
		}
		else {
			msg_info_config ("action %s has been already registered with "
					"priority %ud, override it with new priority: %ud, "
					"old score: %.2f, new score: %.2f",
					action_name,
					act->priority,
					priority,
					act->score,
					score);

			act->score = score;
			act->priority = priority;
		}
	}

	return TRUE;
}


gboolean
rspamd_config_radix_from_ucl (struct rspamd_config *cfg,
		const ucl_object_t *obj,
		const gchar *description,
		radix_compressed_t **target,
		GError **err)
{
	ucl_type_t type;
	ucl_object_iter_t it = NULL;
	const ucl_object_t *cur, *cur_elt;
	const gchar *str;

	LL_FOREACH (obj, cur_elt) {
		type = ucl_object_type (cur_elt);

		switch (type) {
		case UCL_STRING:
			/* Either map or a list of IPs */
			str = ucl_object_tostring (cur_elt);

			if (rspamd_map_is_map (str)) {
				if (rspamd_map_add_from_ucl (cfg, cur_elt,
						description, rspamd_radix_read, rspamd_radix_fin,
						(void **)target) == NULL) {
					g_set_error (err, g_quark_from_static_string ("rspamd-config"),
							EINVAL, "bad map definition %s for %s", str,
							ucl_object_key (obj));
					return FALSE;
				}
			}
			else {
				/* Just a list */
				if (!radix_add_generic_iplist (str, target, TRUE)) {
					g_set_error (err, g_quark_from_static_string ("rspamd-config"),
							EINVAL, "bad map definition %s for %s", str,
							ucl_object_key (obj));
					return FALSE;
				}
			}
			break;
		case UCL_OBJECT:
			/* Should be a map description */
			if (rspamd_map_add_from_ucl (cfg, cur_elt,
					description, rspamd_radix_read, rspamd_radix_fin,
					(void **)target) == NULL) {
				g_set_error (err, g_quark_from_static_string ("rspamd-config"),
						EINVAL, "bad map object for %s", ucl_object_key (obj));
				return FALSE;
			}
			break;
		case UCL_ARRAY:
			/* List of IP addresses */
			while ((cur = ucl_iterate_object (cur_elt, &it, true)) != NULL) {
				str = ucl_object_tostring (cur);

				if (str == NULL || !radix_add_generic_iplist (str, target, TRUE)) {
					g_set_error (err, g_quark_from_static_string ("rspamd-config"),
							EINVAL, "bad map element %s for %s", str,
							ucl_object_key (obj));

					if (*target) {
						radix_destroy_compressed (*target);
					}

					return FALSE;
				}
			}
			break;
		default:
			g_set_error (err, g_quark_from_static_string ("rspamd-config"),
					EINVAL, "bad map type %s for %s",
					ucl_object_type_to_string (type),
					ucl_object_key (obj));
			return FALSE;
		}
	}

	return TRUE;
}
