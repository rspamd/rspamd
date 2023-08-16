/*
 * Copyright 2023 Vsevolod Stakhov
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
#include "config.h"

#include "lua/lua_common.h"
#include "lua/lua_thread_pool.h"

#include "cfg_file.h"
#include "rspamd.h"
#include "cfg_file_private.h"

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
#include "zstd.h"
#else
#define ZSTD_STATIC_LINKING_ONLY
#include "contrib/zstd/zstd.h"
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

#include <string>
#include <string_view>
#include <vector>
#include "fmt/core.h"
#include "cxx/util.hxx"
#include "frozen/unordered_map.h"
#include "frozen/string.h"
#include "contrib/ankerl/unordered_dense.h"

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
#define DEFAULT_MAX_HTML_SIZE DEFAULT_MAX_MESSAGE / 5 /* 10 Mb */
/* Timeout for task processing */
#define DEFAULT_TASK_TIMEOUT 8.0
#define DEFAULT_LUA_GC_STEP 200
#define DEFAULT_LUA_GC_PAUSE 200
#define DEFAULT_GC_MAXITERS 0

struct rspamd_ucl_map_cbdata {
	struct rspamd_config *cfg;
	std::string buf;

	explicit rspamd_ucl_map_cbdata(struct rspamd_config *cfg)
		: cfg(cfg)
	{
	}
};
static gchar *rspamd_ucl_read_cb(gchar *chunk,
								 gint len,
								 struct map_cb_data *data,
								 gboolean final);
static void rspamd_ucl_fin_cb(struct map_cb_data *data, void **target);
static void rspamd_ucl_dtor_cb(struct map_cb_data *data);

guint rspamd_config_log_id = (guint) -1;
RSPAMD_CONSTRUCTOR(rspamd_config_log_init)
{
	rspamd_config_log_id = rspamd_logger_add_debug_module("config");
}

struct rspamd_actions_list {
	using action_ptr = std::shared_ptr<rspamd_action>;
	std::vector<action_ptr> actions;
	ankerl::unordered_dense::map<std::string_view, action_ptr> actions_by_name;

	explicit rspamd_actions_list()
	{
		actions.reserve(METRIC_ACTION_MAX + 2);
		actions_by_name.reserve(METRIC_ACTION_MAX + 2);
	}

	void add_action(action_ptr action)
	{
		actions.push_back(action);
		actions_by_name[action->name] = action;
		sort();
	}

	void sort()
	{
		std::sort(actions.begin(), actions.end(), [](const action_ptr &a1, const action_ptr &a2) -> bool {
			if (!isnan(a1->threshold) && !isnan(a2->threshold)) {
				if (a1->threshold < a2->threshold) {
					return false;
				}
				else if (a1->threshold > a2->threshold) {
					return true;
				}

				return false;
			}

			if (isnan(a1->threshold) && isnan(a2->threshold)) {
				return false;
			}
			else if (isnan(a1->threshold)) {
				return true;
			}

			return false;
		});
	}

	void clear()
	{
		actions.clear();
		actions_by_name.clear();
	}
};

#define RSPAMD_CFG_ACTIONS(cfg) (reinterpret_cast<rspamd_actions_list *>((cfg)->actions))

gboolean
rspamd_parse_bind_line(struct rspamd_config *cfg,
					   struct rspamd_worker_conf *cf,
					   const gchar *str)
{
	struct rspamd_worker_bind_conf *cnf;
	const gchar *fdname;
	gboolean ret = TRUE;

	if (str == nullptr) {
		return FALSE;
	}

	cnf = rspamd_mempool_alloc0_type(cfg->cfg_pool, struct rspamd_worker_bind_conf);

	cnf->cnt = 1024;
	cnf->bind_line = rspamd_mempool_strdup(cfg->cfg_pool, str);

	auto bind_line = std::string_view{cnf->bind_line};

	if (bind_line.starts_with("systemd:")) {
		/* The actual socket will be passed by systemd environment */
		fdname = str + sizeof("systemd:") - 1;
		cnf->is_systemd = TRUE;
		cnf->addrs = g_ptr_array_new_full(1, nullptr);
		rspamd_mempool_add_destructor(cfg->cfg_pool,
									  rspamd_ptr_array_free_hard, cnf->addrs);

		if (fdname[0]) {
			g_ptr_array_add(cnf->addrs, rspamd_mempool_strdup(cfg->cfg_pool, fdname));
			cnf->cnt = cnf->addrs->len;
			cnf->name = rspamd_mempool_strdup(cfg->cfg_pool, str);
			LL_PREPEND(cf->bind_conf, cnf);
		}
		else {
			msg_err_config("cannot parse bind line: %s", str);
			ret = FALSE;
		}
	}
	else {
		if (rspamd_parse_host_port_priority(str, &cnf->addrs,
											nullptr, &cnf->name, DEFAULT_BIND_PORT, TRUE, cfg->cfg_pool) == RSPAMD_PARSE_ADDR_FAIL) {
			msg_err_config("cannot parse bind line: %s", str);
			ret = FALSE;
		}
		else {
			cnf->cnt = cnf->addrs->len;
			LL_PREPEND(cf->bind_conf, cnf);
		}
	}

	return ret;
}

struct rspamd_config *
rspamd_config_new(enum rspamd_config_init_flags flags)
{
	struct rspamd_config *cfg;
	rspamd_mempool_t *pool;

	pool = rspamd_mempool_new(8 * 1024 * 1024, "cfg", 0);
	cfg = rspamd_mempool_alloc0_type(pool, struct rspamd_config);
	/* Allocate larger pool for cfg */
	cfg->cfg_pool = pool;
	cfg->dns_timeout = 1.0;
	cfg->dns_retransmits = 5;
	/* 16 sockets per DNS server */
	cfg->dns_io_per_server = 16;
	cfg->unknown_weight = NAN;

	cfg->actions = (void *) new rspamd_actions_list();

	/* Add all internal actions to keep compatibility */
	for (int i = METRIC_ACTION_REJECT; i < METRIC_ACTION_MAX; i++) {

		auto &&action = std::make_shared<rspamd_action>();
		action->threshold = NAN;
		action->name = rspamd_mempool_strdup(cfg->cfg_pool,
											 rspamd_action_to_str(static_cast<rspamd_action_type>(i)));
		action->action_type = static_cast<rspamd_action_type>(i);

		if (i == METRIC_ACTION_SOFT_REJECT) {
			action->flags |= RSPAMD_ACTION_NO_THRESHOLD | RSPAMD_ACTION_HAM;
		}
		else if (i == METRIC_ACTION_GREYLIST) {
			action->flags |= RSPAMD_ACTION_THRESHOLD_ONLY | RSPAMD_ACTION_HAM;
		}
		else if (i == METRIC_ACTION_NOACTION) {
			action->flags |= RSPAMD_ACTION_HAM;
		}

		RSPAMD_CFG_ACTIONS(cfg)->add_action(std::move(action));
	}

	/* Disable timeout */
	cfg->task_timeout = DEFAULT_TASK_TIMEOUT;


	rspamd_config_init_metric(cfg);
	cfg->composites_manager = rspamd_composites_manager_create(cfg);
	cfg->classifiers_symbols = g_hash_table_new(rspamd_str_hash,
												rspamd_str_equal);
	cfg->cfg_params = g_hash_table_new(rspamd_str_hash, rspamd_str_equal);
	cfg->debug_modules = g_hash_table_new(rspamd_str_hash, rspamd_str_equal);
	cfg->explicit_modules = g_hash_table_new(rspamd_str_hash, rspamd_str_equal);
	cfg->trusted_keys = g_hash_table_new(rspamd_str_hash,
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
	cfg->log_format_str = rspamd_mempool_strdup(cfg->cfg_pool,
												"id: <$mid>,$if_qid{ qid: <$>,}$if_ip{ ip: $,}"
												"$if_user{ user: $,}$if_smtp_from{ from: <$>,} (default: $is_spam "
												"($action): [$scores] [$symbols_scores_params]), len: $len, time: $time_real, "
												"dns req: $dns_req, digest: <$digest>"
												"$if_smtp_rcpts{ rcpts: <$>, }$if_mime_rcpt{ mime_rcpt: <$>, }");
	/* Allow non-mime input by default */
	cfg->allow_raw_input = TRUE;
	/* Default maximum words processed */
	cfg->words_decay = DEFAULT_WORDS_DECAY;
	cfg->min_word_len = DEFAULT_MIN_WORD;
	cfg->max_word_len = DEFAULT_MAX_WORD;
	cfg->max_html_len = DEFAULT_MAX_HTML_SIZE;

	/* GC limits */
	cfg->lua_gc_pause = DEFAULT_LUA_GC_PAUSE;
	cfg->lua_gc_step = DEFAULT_LUA_GC_STEP;
	cfg->full_gc_iters = DEFAULT_GC_MAXITERS;

	/* Default hyperscan cache */
	cfg->hs_cache_dir = rspamd_mempool_strdup(cfg->cfg_pool, RSPAMD_DBDIR "/");

	if (!(flags & RSPAMD_CONFIG_INIT_SKIP_LUA)) {
		cfg->lua_state = (void *) rspamd_lua_init(flags & RSPAMD_CONFIG_INIT_WIPE_LUA_MEM);
		cfg->own_lua_state = TRUE;
		cfg->lua_thread_pool = (void *) lua_thread_pool_new(RSPAMD_LUA_CFG_STATE(cfg));
	}

	cfg->cache = rspamd_symcache_new(cfg);
	cfg->ups_ctx = rspamd_upstreams_library_init();
	cfg->re_cache = rspamd_re_cache_new();
	cfg->doc_strings = ucl_object_typed_new(UCL_OBJECT);
	/*
	 * Unless exim is fixed
	 */
	cfg->enable_shutdown_workaround = TRUE;

	cfg->ssl_ciphers = rspamd_mempool_strdup(cfg->cfg_pool, "HIGH:!anullptr:!kRSA:!PSK:!SRP:!MD5:!RC4");
	cfg->max_message = DEFAULT_MAX_MESSAGE;
	cfg->max_pic_size = DEFAULT_MAX_PIC;
	cfg->images_cache_size = 256;
	cfg->monitored_ctx = rspamd_monitored_ctx_init();
	cfg->neighbours = ucl_object_typed_new(UCL_OBJECT);
	cfg->redis_pool = rspamd_redis_pool_init();
	cfg->default_max_shots = DEFAULT_MAX_SHOTS;
	cfg->max_sessions_cache = DEFAULT_MAX_SESSIONS;
	cfg->maps_cache_dir = rspamd_mempool_strdup(cfg->cfg_pool, RSPAMD_DBDIR);
	cfg->c_modules = g_ptr_array_new();
	cfg->heartbeat_interval = 10.0;

	cfg->enable_css_parser = true;

	REF_INIT_RETAIN(cfg, rspamd_config_free);

	return cfg;
}

void rspamd_config_free(struct rspamd_config *cfg)
{
	struct rspamd_config_cfg_lua_script *sc, *sctmp;
	struct rspamd_config_settings_elt *set, *stmp;
	struct rspamd_worker_log_pipe *lp, *ltmp;

	rspamd_lua_run_config_unload(RSPAMD_LUA_CFG_STATE(cfg), cfg);

	/* Scripts part */
	DL_FOREACH_SAFE(cfg->on_term_scripts, sc, sctmp)
	{
		luaL_unref(RSPAMD_LUA_CFG_STATE(cfg), LUA_REGISTRYINDEX, sc->cbref);
	}

	DL_FOREACH_SAFE(cfg->on_load_scripts, sc, sctmp)
	{
		luaL_unref(RSPAMD_LUA_CFG_STATE(cfg), LUA_REGISTRYINDEX, sc->cbref);
	}

	DL_FOREACH_SAFE(cfg->post_init_scripts, sc, sctmp)
	{
		luaL_unref(RSPAMD_LUA_CFG_STATE(cfg), LUA_REGISTRYINDEX, sc->cbref);
	}

	DL_FOREACH_SAFE(cfg->config_unload_scripts, sc, sctmp)
	{
		luaL_unref(RSPAMD_LUA_CFG_STATE(cfg), LUA_REGISTRYINDEX, sc->cbref);
	}

	DL_FOREACH_SAFE(cfg->setting_ids, set, stmp)
	{
		REF_RELEASE(set);
	}

	rspamd_map_remove_all(cfg);
	rspamd_mempool_destructors_enforce(cfg->cfg_pool);

	g_list_free(cfg->classifiers);
	g_list_free(cfg->workers);
	rspamd_symcache_destroy(cfg->cache);
	ucl_object_unref(cfg->cfg_ucl_obj);
	ucl_object_unref(cfg->config_comments);
	ucl_object_unref(cfg->doc_strings);
	ucl_object_unref(cfg->neighbours);
	g_hash_table_remove_all(cfg->cfg_params);
	g_hash_table_unref(cfg->cfg_params);
	g_hash_table_unref(cfg->classifiers_symbols);
	g_hash_table_unref(cfg->debug_modules);
	g_hash_table_unref(cfg->explicit_modules);
	g_hash_table_unref(cfg->trusted_keys);

	rspamd_re_cache_unref(cfg->re_cache);
	g_ptr_array_free(cfg->c_modules, TRUE);

	if (cfg->monitored_ctx) {
		rspamd_monitored_ctx_destroy(cfg->monitored_ctx);
	}

	if (RSPAMD_LUA_CFG_STATE(cfg) && cfg->own_lua_state) {
		lua_thread_pool_free((struct lua_thread_pool *) cfg->lua_thread_pool);
		rspamd_lua_close(RSPAMD_LUA_CFG_STATE(cfg));
	}

	if (cfg->redis_pool) {
		rspamd_redis_pool_destroy(cfg->redis_pool);
	}

	rspamd_upstreams_library_unref(cfg->ups_ctx);
	delete RSPAMD_CFG_ACTIONS(cfg);

	rspamd_mempool_destructors_enforce(cfg->cfg_pool);

	if (cfg->checksum) {
		g_free(cfg->checksum);
	}

	REF_RELEASE(cfg->libs_ctx);

	DL_FOREACH_SAFE(cfg->log_pipes, lp, ltmp)
	{
		close(lp->fd);
		g_free(lp);
	}

	rspamd_mempool_delete(cfg->cfg_pool);
}

const ucl_object_t *
rspamd_config_get_module_opt(struct rspamd_config *cfg,
							 const gchar *module_name,
							 const gchar *opt_name)
{
	const ucl_object_t *res = nullptr, *sec;

	sec = ucl_obj_get_key(cfg->cfg_ucl_obj, module_name);
	if (sec != nullptr) {
		res = ucl_obj_get_key(sec, opt_name);
	}

	return res;
}

gint rspamd_config_parse_flag(const gchar *str, guint len)
{
	gint c;

	if (!str || !*str) {
		return -1;
	}

	if (len == 0) {
		len = strlen(str);
	}

	switch (len) {
	case 1:
		c = g_ascii_tolower(*str);
		if (c == 'y' || c == '1') {
			return 1;
		}
		else if (c == 'n' || c == '0') {
			return 0;
		}
		break;
	case 2:
		if (g_ascii_strncasecmp(str, "no", len) == 0) {
			return 0;
		}
		else if (g_ascii_strncasecmp(str, "on", len) == 0) {
			return 1;
		}
		break;
	case 3:
		if (g_ascii_strncasecmp(str, "yes", len) == 0) {
			return 1;
		}
		else if (g_ascii_strncasecmp(str, "off", len) == 0) {
			return 0;
		}
		break;
	case 4:
		if (g_ascii_strncasecmp(str, "true", len) == 0) {
			return 1;
		}
		break;
	case 5:
		if (g_ascii_strncasecmp(str, "false", len) == 0) {
			return 0;
		}
		break;
	}

	return -1;
}

// A mapping between names and log format types + flags
constexpr const auto config_vars = frozen::make_unordered_map<frozen::string, std::pair<rspamd_log_format_type, int>>({
	{"mid", {RSPAMD_LOG_MID, 0}},
	{"qid", {RSPAMD_LOG_QID, 0}},
	{"user", {RSPAMD_LOG_USER, 0}},
	{"ip", {RSPAMD_LOG_IP, 0}},
	{"len", {RSPAMD_LOG_LEN, 0}},
	{"dns_req", {RSPAMD_LOG_DNS_REQ, 0}},
	{"smtp_from", {RSPAMD_LOG_SMTP_FROM, 0}},
	{"mime_from", {RSPAMD_LOG_MIME_FROM, 0}},
	{"smtp_rcpt", {RSPAMD_LOG_SMTP_RCPT, 0}},
	{"mime_rcpt", {RSPAMD_LOG_MIME_RCPT, 0}},
	{"smtp_rcpts", {RSPAMD_LOG_SMTP_RCPTS, 0}},
	{"mime_rcpts", {RSPAMD_LOG_MIME_RCPTS, 0}},
	{"time_real", {RSPAMD_LOG_TIME_REAL, 0}},
	{"time_virtual", {RSPAMD_LOG_TIME_VIRTUAL, 0}},
	{"lua", {RSPAMD_LOG_LUA, 0}},
	{"digest", {RSPAMD_LOG_DIGEST, 0}},
	{"checksum", {RSPAMD_LOG_DIGEST, 0}},
	{"filename", {RSPAMD_LOG_FILENAME, 0}},
	{"forced_action", {RSPAMD_LOG_FORCED_ACTION, 0}},
	{"settings_id", {RSPAMD_LOG_SETTINGS_ID, 0}},
	{"mempool_size", {RSPAMD_LOG_MEMPOOL_SIZE, 0}},
	{"mempool_waste", {RSPAMD_LOG_MEMPOOL_WASTE, 0}},
	{"action", {RSPAMD_LOG_ACTION, 0}},
	{"scores", {RSPAMD_LOG_SCORES, 0}},
	{"symbols", {RSPAMD_LOG_SYMBOLS, 0}},
	{"symbols_scores", {RSPAMD_LOG_SYMBOLS, RSPAMD_LOG_FMT_FLAG_SYMBOLS_SCORES}},
	{"symbols_params", {RSPAMD_LOG_SYMBOLS, RSPAMD_LOG_FMT_FLAG_SYMBOLS_PARAMS}},
	{"symbols_scores_params", {RSPAMD_LOG_SYMBOLS, RSPAMD_LOG_FMT_FLAG_SYMBOLS_PARAMS | RSPAMD_LOG_FMT_FLAG_SYMBOLS_SCORES}},
	{"groups", {RSPAMD_LOG_GROUPS, 0}},
	{"public_groups", {RSPAMD_LOG_PUBLIC_GROUPS, 0}},
});

static gboolean
rspamd_config_process_var(struct rspamd_config *cfg, const rspamd_ftok_t *var,
						  const rspamd_ftok_t *content)
{
	g_assert(var != nullptr);

	auto flags = 0;
	auto lc_var = std::string{var->begin, var->len};
	std::transform(lc_var.begin(), lc_var.end(), lc_var.begin(), g_ascii_tolower);
	auto tok = std::string_view{lc_var};

	if (var->len > 3 && tok.starts_with("if_")) {
		flags |= RSPAMD_LOG_FMT_FLAG_CONDITION;
		tok = tok.substr(3);
	}

	auto maybe_fmt_var = rspamd::find_map(config_vars, tok);

	if (maybe_fmt_var) {
		auto &fmt_var = maybe_fmt_var.value().get();
		auto *log_format = rspamd_mempool_alloc0_type(cfg->cfg_pool, rspamd_log_format);

		log_format->type = fmt_var.first;
		log_format->flags = fmt_var.second | flags;

		if (log_format->type != RSPAMD_LOG_LUA) {
			if (content && content->len > 0) {
				log_format->data = rspamd_mempool_alloc0(cfg->cfg_pool,
														 sizeof(rspamd_ftok_t));
				memcpy(log_format->data, content, sizeof(*content));
				log_format->len = sizeof(*content);
			}
		}
		else {
			/* Load lua code and ensure that we have function ref returned */
			if (!content || content->len == 0) {
				msg_err_config("lua variable needs content: %T", &tok);
				return FALSE;
			}

			if (luaL_loadbuffer(RSPAMD_LUA_CFG_STATE(cfg), content->begin, content->len,
								"lua log variable") != 0) {
				msg_err_config("error loading lua code: '%T': %s", content,
							   lua_tostring(RSPAMD_LUA_CFG_STATE(cfg), -1));
				return FALSE;
			}
			if (lua_pcall(RSPAMD_LUA_CFG_STATE(cfg), 0, 1, 0) != 0) {
				msg_err_config("error executing lua code: '%T': %s", content,
							   lua_tostring(RSPAMD_LUA_CFG_STATE(cfg), -1));
				lua_pop(RSPAMD_LUA_CFG_STATE(cfg), 1);

				return FALSE;
			}

			if (lua_type(RSPAMD_LUA_CFG_STATE(cfg), -1) != LUA_TFUNCTION) {
				msg_err_config("lua variable should return function: %T", content);
				lua_pop(RSPAMD_LUA_CFG_STATE(cfg), 1);
				return FALSE;
			}

			auto id = luaL_ref(RSPAMD_LUA_CFG_STATE(cfg), LUA_REGISTRYINDEX);
			log_format->data = GINT_TO_POINTER(id);
			log_format->len = 0;
		}

		DL_APPEND(cfg->log_format, log_format);
	}
	else {
		std::string known_formats;

		for (const auto &v: config_vars) {
			known_formats += std::string_view{v.first.data(), v.first.size()};
			known_formats += ", ";
		}

		if (known_formats.size() > 2) {
			// Remove last comma
			known_formats.resize(known_formats.size() - 2);
		}
		msg_err_config("unknown log variable: %T, known vars are: \"%s\"", var, known_formats.c_str());
		return FALSE;
	}

	return TRUE;
}

static gboolean
rspamd_config_parse_log_format(struct rspamd_config *cfg)
{
	const gchar *p, *c, *end, *s;
	gchar *d;
	struct rspamd_log_format *lf = nullptr;
	rspamd_ftok_t var, var_content;
	enum {
		parse_str,
		parse_dollar,
		parse_var_name,
		parse_var_content,
	} state = parse_str;
	gint braces = 0;

	g_assert(cfg != nullptr);
	c = cfg->log_format_str;

	if (c == nullptr) {
		return FALSE;
	}

	p = c;
	end = p + strlen(p);

	while (p < end) {
		switch (state) {
		case parse_str:
			if (*p == '$') {
				state = parse_dollar;
			}
			else {
				p++;
			}
			break;
		case parse_dollar:
			if (p > c) {
				/* We have string element that we need to store */
				lf = rspamd_mempool_alloc0_type(cfg->cfg_pool, struct rspamd_log_format);
				lf->type = RSPAMD_LOG_STRING;
				lf->data = rspamd_mempool_alloc(cfg->cfg_pool, p - c + 1);
				/* Filter \r\n from the destination */
				s = c;
				d = (char *) lf->data;

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

				lf->len = d - (char *) lf->data;
				DL_APPEND(cfg->log_format, lf);
				lf = nullptr;
			}
			p++;
			c = p;
			state = parse_var_name;
			break;
		case parse_var_name:
			if (*p == '{') {
				var.begin = c;
				var.len = p - c;
				p++;
				c = p;
				state = parse_var_content;
				braces = 1;
			}
			else if (*p != '_' && *p != '-' && !g_ascii_isalnum(*p)) {
				/* Variable with no content */
				var.begin = c;
				var.len = p - c;
				c = p;

				if (!rspamd_config_process_var(cfg, &var, nullptr)) {
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
				p++;
				c = p;

				if (!rspamd_config_process_var(cfg, &var, &var_content)) {
					return FALSE;
				}

				state = parse_str;
			}
			else if (*p == '{') {
				braces++;
				p++;
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
			lf = rspamd_mempool_alloc0_type(cfg->cfg_pool, struct rspamd_log_format);
			lf->type = RSPAMD_LOG_STRING;
			lf->data = rspamd_mempool_alloc(cfg->cfg_pool, p - c + 1);
			/* Filter \r\n from the destination */
			s = c;
			d = (char *) lf->data;

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

			lf->len = d - (char *) lf->data;
			DL_APPEND(cfg->log_format, lf);
			lf = nullptr;
		}
		break;

	case parse_var_name:
		var.begin = c;
		var.len = p - c;

		if (!rspamd_config_process_var(cfg, &var, nullptr)) {
			return FALSE;
		}
		break;
	case parse_dollar:
	case parse_var_content:
		msg_err_config("cannot parse log format %s: incomplete string",
					   cfg->log_format_str);
		return FALSE;
		break;
	}

	return TRUE;
}

static void
rspamd_urls_config_dtor(gpointer _unused)
{
	rspamd_url_deinit();
}

static void
rspamd_adjust_clocks_resolution(struct rspamd_config *cfg)
{
#ifdef HAVE_CLOCK_GETTIME
	struct timespec ts;
#endif

#ifdef HAVE_CLOCK_GETTIME
#ifdef HAVE_CLOCK_PROCESS_CPUTIME_ID
	clock_getres(CLOCK_PROCESS_CPUTIME_ID, &ts);
#elif defined(HAVE_CLOCK_VIRTUAL)
	clock_getres(CLOCK_VIRTUAL, &ts);
#else
	clock_getres(CLOCK_REALTIME, &ts);
#endif
	cfg->clock_res = log10(1000000. / ts.tv_nsec);
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
}

/*
 * Perform post load actions
 */
gboolean
rspamd_config_post_load(struct rspamd_config *cfg,
						enum rspamd_post_load_options opts)
{

	auto ret = TRUE;

	rspamd_adjust_clocks_resolution(cfg);
	rspamd_logger_configure_modules(cfg->debug_modules);

	if (cfg->one_shot_mode) {
		msg_info_config("enabling one shot mode (was %d max shots)",
						cfg->default_max_shots);
		cfg->default_max_shots = 1;
	}

#if defined(WITH_HYPERSCAN) && !defined(__aarch64__) && !defined(__powerpc64__)
	if (!cfg->disable_hyperscan) {
		if (!(cfg->libs_ctx->crypto_ctx->cpu_config & CPUID_SSSE3)) {
			msg_warn_config("CPU doesn't have SSSE3 instructions set "
							"required for hyperscan, disable it");
			cfg->disable_hyperscan = TRUE;
		}
	}
#endif

	rspamd_regexp_library_init(cfg);
	rspamd_multipattern_library_init(cfg->hs_cache_dir);

	if (opts & RSPAMD_CONFIG_INIT_URL) {
		if (cfg->tld_file == nullptr) {
			/* Try to guess tld file */
			auto fpath = fmt::format("{0}{1}{2}", RSPAMD_SHAREDIR,
									 G_DIR_SEPARATOR, "effective_tld_names.dat");

			if (access(fpath.c_str(), R_OK) != -1) {
				msg_debug_config("url_tld option is not specified but %s is available,"
								 " therefore this file is assumed as TLD file for URL"
								 " extraction",
								 fpath.c_str());
				cfg->tld_file = rspamd_mempool_strdup(cfg->cfg_pool, fpath.c_str());
			}
			else {
				if (opts & RSPAMD_CONFIG_INIT_VALIDATE) {
					msg_err_config("no url_tld option has been specified");
					ret = FALSE;
				}
			}
		}
		else {
			if (access(cfg->tld_file, R_OK) == -1) {
				if (opts & RSPAMD_CONFIG_INIT_VALIDATE) {
					ret = FALSE;
					msg_err_config("cannot access tld file %s: %s", cfg->tld_file,
								   strerror(errno));
				}
				else {
					msg_debug_config("cannot access tld file %s: %s", cfg->tld_file,
									 strerror(errno));
					cfg->tld_file = nullptr;
				}
			}
		}

		if (opts & RSPAMD_CONFIG_INIT_NO_TLD) {
			rspamd_url_init(nullptr);
		}
		else {
			rspamd_url_init(cfg->tld_file);
		}

		rspamd_mempool_add_destructor(cfg->cfg_pool, rspamd_urls_config_dtor,
									  nullptr);
	}

	init_dynamic_config(cfg);
	/* Insert classifiers symbols */
	rspamd_config_insert_classify_symbols(cfg);

	/* Parse format string that we have */
	if (!rspamd_config_parse_log_format(cfg)) {
		msg_err_config("cannot parse log format, task logging will not be available");
		if (opts & RSPAMD_CONFIG_INIT_VALIDATE) {
			ret = FALSE;
		}
	}

	if (opts & RSPAMD_CONFIG_INIT_SYMCACHE) {
		/* Init config cache */
		ret &= rspamd_symcache_init(cfg->cache);

		/* Init re cache */
		rspamd_re_cache_init(cfg->re_cache, cfg);

		/* Try load Hypersan */
		auto hs_ret = rspamd_re_cache_load_hyperscan(cfg->re_cache,
													 cfg->hs_cache_dir ? cfg->hs_cache_dir : RSPAMD_DBDIR "/",
													 true);

		if (hs_ret == RSPAMD_HYPERSCAN_LOAD_ERROR) {
			ret = FALSE;
		}
	}

	if (opts & RSPAMD_CONFIG_INIT_LIBS) {
		/* Config other libraries */
		ret &= rspamd_config_libs(cfg->libs_ctx, cfg);
	}

	/* Validate cache */
	if (opts & RSPAMD_CONFIG_INIT_VALIDATE) {
		/* Check for actions sanity */
		auto seen_controller = FALSE;

		auto *cur = cfg->workers;
		while (cur) {
			auto *wcf = (struct rspamd_worker_conf *) cur->data;

			if (wcf->type == g_quark_from_static_string("controller")) {
				seen_controller = TRUE;
				break;
			}

			cur = g_list_next(cur);
		}

		if (!seen_controller) {
			msg_warn_config("controller worker is unconfigured: learning,"
							" periodic scripts, maps watching and many other"
							" Rspamd features will be broken");
		}

		ret &= rspamd_symcache_validate(cfg->cache, cfg, FALSE);
	}

	if (opts & RSPAMD_CONFIG_INIT_POST_LOAD_LUA) {
		rspamd_lua_run_config_post_init(RSPAMD_LUA_CFG_STATE(cfg), cfg);
	}

	if (opts & RSPAMD_CONFIG_INIT_PRELOAD_MAPS) {
		rspamd_map_preload(cfg);
	}

	return ret;
}

struct rspamd_classifier_config *
rspamd_config_new_classifier(struct rspamd_config *cfg,
							 struct rspamd_classifier_config *c)
{
	if (c == nullptr) {
		c =
			rspamd_mempool_alloc0_type(cfg->cfg_pool,
									   struct rspamd_classifier_config);
		c->min_prob_strength = 0.05;
		c->min_token_hits = 2;
	}

	if (c->labels == nullptr) {
		c->labels = g_hash_table_new_full(rspamd_str_hash,
										  rspamd_str_equal,
										  nullptr,
										  (GDestroyNotify) g_list_free);
		rspamd_mempool_add_destructor(cfg->cfg_pool,
									  (rspamd_mempool_destruct_t) g_hash_table_destroy,
									  c->labels);
	}

	return c;
}

struct rspamd_statfile_config *
rspamd_config_new_statfile(struct rspamd_config *cfg,
						   struct rspamd_statfile_config *c)
{
	if (c == nullptr) {
		c =
			rspamd_mempool_alloc0_type(cfg->cfg_pool, struct rspamd_statfile_config);
	}

	return c;
}

void rspamd_config_init_metric(struct rspamd_config *cfg)
{
	cfg->grow_factor = 1.0;
	cfg->symbols = g_hash_table_new(rspamd_str_hash, rspamd_str_equal);
	cfg->groups = g_hash_table_new(rspamd_strcase_hash, rspamd_strcase_equal);

	cfg->subject = SPAM_SUBJECT;
	rspamd_mempool_add_destructor(cfg->cfg_pool,
								  (rspamd_mempool_destruct_t) g_hash_table_unref,
								  cfg->symbols);
	rspamd_mempool_add_destructor(cfg->cfg_pool,
								  (rspamd_mempool_destruct_t) g_hash_table_unref,
								  cfg->groups);
}

struct rspamd_symbols_group *
rspamd_config_new_group(struct rspamd_config *cfg, const gchar *name)
{
	struct rspamd_symbols_group *gr;

	gr = rspamd_mempool_alloc0_type(cfg->cfg_pool, struct rspamd_symbols_group);
	gr->symbols = g_hash_table_new(rspamd_strcase_hash,
								   rspamd_strcase_equal);
	rspamd_mempool_add_destructor(cfg->cfg_pool,
								  (rspamd_mempool_destruct_t) g_hash_table_unref, gr->symbols);
	gr->name = rspamd_mempool_strdup(cfg->cfg_pool, name);

	if (strcmp(gr->name, "ungrouped") == 0) {
		gr->flags |= RSPAMD_SYMBOL_GROUP_UNGROUPED;
	}

	g_hash_table_insert(cfg->groups, gr->name, gr);

	return gr;
}

static void
rspamd_worker_conf_dtor(struct rspamd_worker_conf *wcf)
{
	if (wcf) {
		struct rspamd_worker_bind_conf *cnf, *tmp;

		LL_FOREACH_SAFE(wcf->bind_conf, cnf, tmp)
		{
			g_ptr_array_free(cnf->addrs, TRUE);
		}

		ucl_object_unref(wcf->options);
		g_queue_free(wcf->active_workers);
		g_hash_table_unref(wcf->params);
		g_free(wcf);
	}
}

static void
rspamd_worker_conf_cfg_fin(gpointer d)
{
	auto *wcf = (struct rspamd_worker_conf *) d;

	REF_RELEASE(wcf);
}

struct rspamd_worker_conf *
rspamd_config_new_worker(struct rspamd_config *cfg,
						 struct rspamd_worker_conf *c)
{
	if (c == nullptr) {
		c = g_new0(struct rspamd_worker_conf, 1);
		c->params = g_hash_table_new(rspamd_str_hash, rspamd_str_equal);
		c->active_workers = g_queue_new();
#ifdef HAVE_SC_NPROCESSORS_ONLN
		auto nproc = sysconf(_SC_NPROCESSORS_ONLN);
		c->count = MIN(DEFAULT_MAX_WORKERS, MAX(1, nproc - 2));
#else
		c->count = DEFAULT_MAX_WORKERS;
#endif
		c->rlimit_nofile = 0;
		c->rlimit_maxcore = 0;
		c->enabled = TRUE;

		REF_INIT_RETAIN(c, rspamd_worker_conf_dtor);
		rspamd_mempool_add_destructor(cfg->cfg_pool,
									  rspamd_worker_conf_cfg_fin, c);
	}

	return c;
}


static bool
rspamd_include_map_handler(const guchar *data, gsize len,
						   const ucl_object_t *args, void *ud)
{
	auto *cfg = (struct rspamd_config *) ud;

	auto ftok = rspamd_ftok_t{.len = len + 1, .begin = (char *) data};
	auto *map_line = rspamd_mempool_ftokdup(cfg->cfg_pool, &ftok);

	auto *cbdata = new rspamd_ucl_map_cbdata{cfg};
	auto **pcbdata = new rspamd_ucl_map_cbdata *(cbdata);

	return rspamd_map_add(cfg,
						  map_line,
						  "ucl include",
						  rspamd_ucl_read_cb,
						  rspamd_ucl_fin_cb,
						  rspamd_ucl_dtor_cb,
						  (void **) pcbdata,
						  nullptr, RSPAMD_MAP_DEFAULT) != nullptr;
}

/*
 * Variables:
 * $CONFDIR - configuration directory
 * $LOCAL_CONFDIR - local configuration directory
 * $RUNDIR - local states directory
 * $DBDIR - databases dir
 * $LOGDIR - logs dir
 * $PLUGINSDIR - plugins dir
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

void rspamd_ucl_add_conf_variables(struct ucl_parser *parser, GHashTable *vars)
{
	GHashTableIter it;
	gpointer k, v;

	ucl_parser_register_variable(parser,
								 RSPAMD_CONFDIR_MACRO,
								 RSPAMD_CONFDIR);
	ucl_parser_register_variable(parser,
								 RSPAMD_LOCAL_CONFDIR_MACRO,
								 RSPAMD_LOCAL_CONFDIR);
	ucl_parser_register_variable(parser, RSPAMD_RUNDIR_MACRO,
								 RSPAMD_RUNDIR);
	ucl_parser_register_variable(parser, RSPAMD_DBDIR_MACRO,
								 RSPAMD_DBDIR);
	ucl_parser_register_variable(parser, RSPAMD_LOGDIR_MACRO,
								 RSPAMD_LOGDIR);
	ucl_parser_register_variable(parser,
								 RSPAMD_PLUGINSDIR_MACRO,
								 RSPAMD_PLUGINSDIR);
	ucl_parser_register_variable(parser,
								 RSPAMD_SHAREDIR_MACRO,
								 RSPAMD_SHAREDIR);
	ucl_parser_register_variable(parser,
								 RSPAMD_RULESDIR_MACRO,
								 RSPAMD_RULESDIR);
	ucl_parser_register_variable(parser, RSPAMD_WWWDIR_MACRO,
								 RSPAMD_WWWDIR);
	ucl_parser_register_variable(parser, RSPAMD_PREFIX_MACRO,
								 RSPAMD_PREFIX);
	ucl_parser_register_variable(parser, RSPAMD_VERSION_MACRO, RVERSION);
	ucl_parser_register_variable(parser, RSPAMD_VERSION_MAJOR_MACRO,
								 RSPAMD_VERSION_MAJOR);
	ucl_parser_register_variable(parser, RSPAMD_VERSION_MINOR_MACRO,
								 RSPAMD_VERSION_MINOR);
	ucl_parser_register_variable(parser, RSPAMD_BRANCH_VERSION_MACRO,
								 RSPAMD_VERSION_BRANCH);

	auto hostlen = sysconf(_SC_HOST_NAME_MAX);

	if (hostlen <= 0) {
		hostlen = 256;
	}
	else {
		hostlen++;
	}

	auto hostbuf = std::string{};
	hostbuf.resize(hostlen);

	if (gethostname(hostbuf.data(), hostlen) != 0) {
		hostbuf = "unknown";
	}

	/* UCL copies variables, so it is safe to pass an ephemeral buffer here */
	ucl_parser_register_variable(parser, RSPAMD_HOSTNAME_MACRO,
								 hostbuf.c_str());

	if (vars != nullptr) {
		g_hash_table_iter_init(&it, vars);

		while (g_hash_table_iter_next(&it, &k, &v)) {
			ucl_parser_register_variable(parser, (const char *) k, (const char *) v);
		}
	}
}

void rspamd_ucl_add_conf_macros(struct ucl_parser *parser,
								struct rspamd_config *cfg)
{
	ucl_parser_register_macro(parser,
							  "include_map",
							  rspamd_include_map_handler,
							  cfg);
}

static void
symbols_classifiers_callback(gpointer key, gpointer value, gpointer ud)
{
	auto *cfg = (struct rspamd_config *) ud;

	/* Actually, statistics should act like any ordinary symbol */
	rspamd_symcache_add_symbol(cfg->cache, (const char *) key, 0, nullptr, nullptr,
							   SYMBOL_TYPE_CLASSIFIER | SYMBOL_TYPE_NOSTAT, -1);
}

void rspamd_config_insert_classify_symbols(struct rspamd_config *cfg)
{
	g_hash_table_foreach(cfg->classifiers_symbols,
						 symbols_classifiers_callback,
						 cfg);
}

struct rspamd_classifier_config *
rspamd_config_find_classifier(struct rspamd_config *cfg, const gchar *name)
{
	if (name == nullptr) {
		return nullptr;
	}

	auto *cur = cfg->classifiers;
	while (cur) {
		auto *cf = (struct rspamd_classifier_config *) cur->data;

		if (g_ascii_strcasecmp(cf->name, name) == 0) {
			return cf;
		}

		cur = g_list_next(cur);
	}

	return nullptr;
}

gboolean
rspamd_config_check_statfiles(struct rspamd_classifier_config *cf)
{
	gboolean has_other = FALSE, res = FALSE, cur_class = FALSE;

	/* First check classes directly */
	auto *cur = cf->statfiles;
	while (cur) {
		auto *st = (struct rspamd_statfile_config *) cur->data;
		if (!has_other) {
			cur_class = st->is_spam;
			has_other = TRUE;
		}
		else {
			if (cur_class != st->is_spam) {
				return TRUE;
			}
		}

		cur = g_list_next(cur);
	}

	if (!has_other) {
		/* We have only one statfile */
		return FALSE;
	}
	/* We have not detected any statfile that has different class, so turn on heuristic based on symbol's name */
	has_other = FALSE;
	cur = cf->statfiles;
	while (cur) {
		auto *st = (struct rspamd_statfile_config *) cur->data;
		if (rspamd_substring_search_caseless(st->symbol,
											 strlen(st->symbol), "spam", 4) != -1) {
			st->is_spam = TRUE;
		}
		else if (rspamd_substring_search_caseless(st->symbol,
												  strlen(st->symbol), "ham", 3) != -1) {
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

		cur = g_list_next(cur);
	}

	return res;
}

static gchar *
rspamd_ucl_read_cb(gchar *chunk,
				   gint len,
				   struct map_cb_data *data,
				   gboolean final)
{
	auto *cbdata = (struct rspamd_ucl_map_cbdata *) data->cur_data;
	auto *prev = (struct rspamd_ucl_map_cbdata *) data->prev_data;

	if (cbdata == nullptr) {
		cbdata = new rspamd_ucl_map_cbdata{prev->cfg};
		data->cur_data = cbdata;
	}
	cbdata->buf.append(chunk, len);

	/* Say not to copy any part of this buffer */
	return nullptr;
}

static void
rspamd_ucl_fin_cb(struct map_cb_data *data, void **target)
{
	auto *cbdata = (struct rspamd_ucl_map_cbdata *) data->cur_data;
	auto *prev = (struct rspamd_ucl_map_cbdata *) data->prev_data;
	auto *cfg = data->map->cfg;

	if (cbdata == nullptr) {
		msg_err_config("map fin error: new data is nullptr");
		return;
	}

	/* New data available */
	auto *parser = ucl_parser_new(0);
	if (!ucl_parser_add_chunk(parser, (unsigned char *) cbdata->buf.data(),
							  cbdata->buf.size())) {
		msg_err_config("cannot parse map %s: %s",
					   data->map->name,
					   ucl_parser_get_error(parser));
		ucl_parser_free(parser);
	}
	else {
		auto *obj = ucl_parser_get_object(parser);
		ucl_object_iter_t it = nullptr;

		for (auto *cur = ucl_object_iterate(obj, &it, true); cur != nullptr; cur = ucl_object_iterate(obj, &it, true)) {
			ucl_object_replace_key(cbdata->cfg->cfg_ucl_obj, (ucl_object_t *) cur,
								   cur->key, cur->keylen, false);
		}

		ucl_parser_free(parser);
		ucl_object_unref(obj);
	}

	if (target) {
		*target = data->cur_data;
	}

	delete prev;
}

static void
rspamd_ucl_dtor_cb(struct map_cb_data *data)
{
	auto *cbdata = (struct rspamd_ucl_map_cbdata *) data->cur_data;

	delete cbdata;
}

gboolean
rspamd_check_module(struct rspamd_config *cfg, module_t *mod)
{
	gboolean ret = TRUE;

	if (mod != nullptr) {
		if (mod->module_version != RSPAMD_CUR_MODULE_VERSION) {
			msg_err_config("module %s has incorrect version %xd (%xd expected)",
						   mod->name, (gint) mod->module_version, RSPAMD_CUR_MODULE_VERSION);
			ret = FALSE;
		}
		if (ret && mod->rspamd_version != RSPAMD_VERSION_NUM) {
			msg_err_config("module %s has incorrect rspamd version %xL (%xL expected)",
						   mod->name, mod->rspamd_version, RSPAMD_VERSION_NUM);
			ret = FALSE;
		}
		if (ret && strcmp(mod->rspamd_features, RSPAMD_FEATURES) != 0) {
			msg_err_config("module %s has incorrect rspamd features '%s' ('%s' expected)",
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
rspamd_check_worker(struct rspamd_config *cfg, worker_t *wrk)
{
	gboolean ret = TRUE;

	if (wrk != nullptr) {
		if (wrk->worker_version != RSPAMD_CUR_WORKER_VERSION) {
			msg_err_config("worker %s has incorrect version %xd (%xd expected)",
						   wrk->name, wrk->worker_version, RSPAMD_CUR_WORKER_VERSION);
			ret = FALSE;
		}
		if (ret && wrk->rspamd_version != RSPAMD_VERSION_NUM) {
			msg_err_config("worker %s has incorrect rspamd version %xL (%xL expected)",
						   wrk->name, wrk->rspamd_version, RSPAMD_VERSION_NUM);
			ret = FALSE;
		}
		if (ret && strcmp(wrk->rspamd_features, RSPAMD_FEATURES) != 0) {
			msg_err_config("worker %s has incorrect rspamd features '%s' ('%s' expected)",
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
rspamd_init_filters(struct rspamd_config *cfg, bool reconfig, bool strict)
{
	GList *cur;
	module_t *mod, **pmod;
	guint i = 0;
	struct module_ctx *mod_ctx, *cur_ctx;
	gboolean ret = TRUE;

	/* Init all compiled modules */

	for (pmod = cfg->compiled_modules; pmod != nullptr && *pmod != nullptr; pmod++) {
		mod = *pmod;
		if (rspamd_check_module(cfg, mod)) {
			if (mod->module_init_func(cfg, &mod_ctx) == 0) {
				g_assert(mod_ctx != nullptr);
				g_ptr_array_add(cfg->c_modules, mod_ctx);
				mod_ctx->mod = mod;
				mod->ctx_offset = i++;
			}
		}
	}

	/* Now check what's enabled */
	cur = g_list_first(cfg->filters);

	while (cur) {
		/* Perform modules configuring */
		mod_ctx = nullptr;
		PTR_ARRAY_FOREACH(cfg->c_modules, i, cur_ctx)
		{
			if (g_ascii_strcasecmp(cur_ctx->mod->name,
								   (const gchar *) cur->data) == 0) {
				mod_ctx = cur_ctx;
				break;
			}
		}

		if (mod_ctx) {
			mod = mod_ctx->mod;
			mod_ctx->enabled = rspamd_config_is_module_enabled(cfg, mod->name);

			if (reconfig) {
				if (!mod->module_reconfig_func(cfg)) {
					msg_err_config("reconfig of %s failed!", mod->name);
				}
				else {
					msg_info_config("reconfig of %s", mod->name);
				}
			}
			else {
				if (!mod->module_config_func(cfg, strict)) {
					msg_err_config("config of %s failed", mod->name);
					ret = FALSE;

					if (strict) {
						return FALSE;
					}
				}
			}
		}

		if (mod_ctx == nullptr) {
			msg_warn_config("requested unknown module %s", cur->data);
		}

		cur = g_list_next(cur);
	}

	ret = rspamd_init_lua_filters(cfg, 0, strict) && ret;

	return ret;
}

static void
rspamd_config_new_symbol(struct rspamd_config *cfg, const gchar *symbol,
						 gdouble score, const gchar *description, const gchar *group,
						 guint flags, guint priority, gint nshots)
{
	struct rspamd_symbols_group *sym_group;
	struct rspamd_symbol *sym_def;
	double *score_ptr;

	sym_def =
		rspamd_mempool_alloc0_type(cfg->cfg_pool, struct rspamd_symbol);
	score_ptr = rspamd_mempool_alloc_type(cfg->cfg_pool, double);

	if (isnan(score)) {
		/* In fact, it could be defined later */
		msg_debug_config("score is not defined for symbol %s, set it to zero",
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
	sym_def->name = rspamd_mempool_strdup(cfg->cfg_pool, symbol);
	sym_def->flags = flags;
	sym_def->nshots = nshots != 0 ? nshots : cfg->default_max_shots;
	sym_def->groups = g_ptr_array_sized_new(1);
	rspamd_mempool_add_destructor(cfg->cfg_pool, rspamd_ptr_array_free_hard,
								  sym_def->groups);

	if (description) {
		sym_def->description = rspamd_mempool_strdup(cfg->cfg_pool, description);
	}

	msg_debug_config("registered symbol %s with weight %.2f in and group %s",
					 sym_def->name, score, group);

	g_hash_table_insert(cfg->symbols, sym_def->name, sym_def);

	/* Search for symbol group */
	if (group == nullptr) {
		group = "ungrouped";
		sym_def->flags |= RSPAMD_SYMBOL_FLAG_UNGROUPED;
	}
	else {
		if (strcmp(group, "ungrouped") == 0) {
			sym_def->flags |= RSPAMD_SYMBOL_FLAG_UNGROUPED;
		}
	}

	sym_group = reinterpret_cast<rspamd_symbols_group *>(g_hash_table_lookup(cfg->groups, group));
	if (sym_group == nullptr) {
		/* Create new group */
		sym_group = rspamd_config_new_group(cfg, group);
	}

	sym_def->gr = sym_group;
	g_hash_table_insert(sym_group->symbols, sym_def->name, sym_def);

	if (!(sym_def->flags & RSPAMD_SYMBOL_FLAG_UNGROUPED)) {
		g_ptr_array_add(sym_def->groups, sym_group);
	}
}


gboolean
rspamd_config_add_symbol(struct rspamd_config *cfg,
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

	g_assert(cfg != nullptr);
	g_assert(symbol != nullptr);

	sym_def = reinterpret_cast<rspamd_symbol *>(g_hash_table_lookup(cfg->symbols, symbol));

	if (sym_def != nullptr) {
		if (group != nullptr) {
			gboolean has_group = FALSE;

			PTR_ARRAY_FOREACH(sym_def->groups, i, sym_group)
			{
				if (g_ascii_strcasecmp(sym_group->name, group) == 0) {
					/* Group is already here */
					has_group = TRUE;
					break;
				}
			}

			if (!has_group) {
				/* Non-empty group has a priority over non-grouped one */
				sym_group = reinterpret_cast<rspamd_symbols_group *>(g_hash_table_lookup(cfg->groups, group));

				if (sym_group == nullptr) {
					/* Create new group */
					sym_group = rspamd_config_new_group(cfg, group);
				}

				if ((!sym_def->gr) || (sym_def->flags & RSPAMD_SYMBOL_FLAG_UNGROUPED)) {
					sym_def->gr = sym_group;
					sym_def->flags &= ~RSPAMD_SYMBOL_FLAG_UNGROUPED;
				}

				g_hash_table_insert(sym_group->symbols, sym_def->name, sym_def);
				sym_def->flags &= ~(RSPAMD_SYMBOL_FLAG_UNGROUPED);
				g_ptr_array_add(sym_def->groups, sym_group);
			}
		}

		if (sym_def->priority > priority &&
			(isnan(score) || !(sym_def->flags & RSPAMD_SYMBOL_FLAG_UNSCORED))) {
			msg_debug_config("symbol %s has been already registered with "
							 "priority %ud, do not override (new priority: %ud)",
							 symbol,
							 sym_def->priority,
							 priority);
			/* But we can still add description */
			if (!sym_def->description && description) {
				sym_def->description = rspamd_mempool_strdup(cfg->cfg_pool,
															 description);
			}

			/* Or nshots in case of non-default setting */
			if (nshots != 0 && sym_def->nshots == cfg->default_max_shots) {
				sym_def->nshots = nshots;
			}

			return FALSE;
		}
		else {

			if (!isnan(score)) {
				msg_debug_config("symbol %s has been already registered with "
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
				sym_def->description = rspamd_mempool_strdup(cfg->cfg_pool,
															 description);
			}


			/* We also check group information in this case */
			if (group != nullptr && sym_def->gr != nullptr &&
				strcmp(group, sym_def->gr->name) != 0) {

				sym_group = reinterpret_cast<rspamd_symbols_group *>(g_hash_table_lookup(cfg->groups, group));

				if (sym_group == nullptr) {
					/* Create new group */
					sym_group = rspamd_config_new_group(cfg, group);
				}

				if (!(sym_group->flags & RSPAMD_SYMBOL_GROUP_UNGROUPED)) {
					msg_debug_config("move symbol %s from group %s to %s",
									 sym_def->name, sym_def->gr->name, group);
					g_hash_table_remove(sym_def->gr->symbols, sym_def->name);
					sym_def->gr = sym_group;
					g_hash_table_insert(sym_group->symbols, sym_def->name, sym_def);
				}
			}

			return TRUE;
		}
	}

	/* This is called merely when we have an undefined symbol */
	rspamd_config_new_symbol(cfg, symbol, score, description,
							 group, flags, priority, nshots);

	return TRUE;
}

gboolean
rspamd_config_add_symbol_group(struct rspamd_config *cfg,
							   const gchar *symbol,
							   const gchar *group)
{
	struct rspamd_symbol *sym_def;
	struct rspamd_symbols_group *sym_group;
	guint i;

	g_assert(cfg != nullptr);
	g_assert(symbol != nullptr);
	g_assert(group != nullptr);

	sym_def = reinterpret_cast<rspamd_symbol *>(g_hash_table_lookup(cfg->symbols, symbol));

	if (sym_def != nullptr) {
		gboolean has_group = FALSE;

		PTR_ARRAY_FOREACH(sym_def->groups, i, sym_group)
		{
			if (g_ascii_strcasecmp(sym_group->name, group) == 0) {
				/* Group is already here */
				has_group = TRUE;
				break;
			}
		}

		if (!has_group) {
			/* Non-empty group has a priority over non-grouped one */
			sym_group = reinterpret_cast<rspamd_symbols_group *>(g_hash_table_lookup(cfg->groups, group));

			if (sym_group == nullptr) {
				/* Create new group */
				sym_group = rspamd_config_new_group(cfg, group);
			}

			if (!sym_def->gr) {
				sym_def->gr = sym_group;
			}

			g_hash_table_insert(sym_group->symbols, sym_def->name, sym_def);
			sym_def->flags &= ~(RSPAMD_SYMBOL_FLAG_UNGROUPED);
			g_ptr_array_add(sym_def->groups, sym_group);

			return TRUE;
		}
	}

	return FALSE;
}

gboolean
rspamd_config_is_enabled_from_ucl(rspamd_mempool_t *pool,
								  const ucl_object_t *obj)
{

	const ucl_object_t *enabled;

	enabled = ucl_object_lookup(obj, "enabled");

	if (enabled) {
		if (ucl_object_type(enabled) == UCL_BOOLEAN) {
			return ucl_object_toboolean(enabled);
		}
		else if (ucl_object_type(enabled) == UCL_STRING) {
			gint ret = rspamd_config_parse_flag(ucl_object_tostring(enabled), 0);

			if (ret == 0) {
				return FALSE;
			}
			else if (ret == -1) {

				msg_info_pool_check("wrong value for the `enabled` key");
				return FALSE;
			}
			/* Default return is TRUE here */
		}
	}


	const ucl_object_t *disabled;

	disabled = ucl_object_lookup(obj, "disabled");

	if (disabled) {
		if (ucl_object_type(disabled) == UCL_BOOLEAN) {
			return !ucl_object_toboolean(disabled);
		}
		else if (ucl_object_type(disabled) == UCL_STRING) {
			gint ret = rspamd_config_parse_flag(ucl_object_tostring(disabled), 0);

			if (ret == 0) {
				return TRUE;
			}
			else if (ret == -1) {

				msg_info_pool_check("wrong value for the `disabled` key");
				return FALSE;
			}

			return FALSE;
		}
	}

	return TRUE;
}

gboolean
rspamd_config_is_module_enabled(struct rspamd_config *cfg,
								const gchar *module_name)
{
	gboolean is_c = FALSE, enabled;
	const ucl_object_t *conf;
	GList *cur;
	struct rspamd_symbols_group *gr;
	lua_State *L = RSPAMD_LUA_CFG_STATE(cfg);
	struct module_ctx *cur_ctx;
	guint i;

	PTR_ARRAY_FOREACH(cfg->c_modules, i, cur_ctx)
	{
		if (g_ascii_strcasecmp(cur_ctx->mod->name, module_name) == 0) {
			is_c = TRUE;
			break;
		}
	}

	if (g_hash_table_lookup(cfg->explicit_modules, module_name) != nullptr) {
		/* Always load module */
		rspamd_plugins_table_push_elt(L, "enabled", module_name);

		return TRUE;
	}

	if (is_c) {
		gboolean found = FALSE;

		cur = g_list_first(cfg->filters);

		while (cur) {
			if (strcmp((char *) cur->data, module_name) == 0) {
				found = TRUE;
				break;
			}

			cur = g_list_next(cur);
		}

		if (!found) {
			msg_info_config("internal module %s is disable in `filters` line",
							module_name);
			rspamd_plugins_table_push_elt(L,
										  "disabled_explicitly", module_name);

			return FALSE;
		}
	}

	conf = ucl_object_lookup(cfg->cfg_ucl_obj, module_name);

	if (conf == nullptr) {
		rspamd_plugins_table_push_elt(L, "disabled_unconfigured", module_name);

		msg_info_config("%s module %s is enabled but has not been configured",
						is_c ? "internal" : "lua", module_name);

		if (!is_c) {
			msg_info_config("%s disabling unconfigured lua module", module_name);
			return FALSE;
		}
	}
	else {
		enabled = rspamd_config_is_enabled_from_ucl(cfg->cfg_pool, conf);

		if (!enabled) {
			rspamd_plugins_table_push_elt(L,
										  "disabled_explicitly", module_name);

			msg_info_config(
				"%s module %s is disabled in the configuration",
				is_c ? "internal" : "lua", module_name);
			return FALSE;
		}
	}

	/* Now we check symbols group */
	gr = reinterpret_cast<rspamd_symbols_group *>(g_hash_table_lookup(cfg->groups, module_name));

	if (gr) {
		if (gr->flags & RSPAMD_SYMBOL_GROUP_DISABLED) {
			rspamd_plugins_table_push_elt(L,
										  "disabled_explicitly", module_name);
			msg_info_config("%s module %s is disabled in the configuration as "
							"its group has been disabled",
							is_c ? "internal" : "lua", module_name);

			return FALSE;
		}
	}

	rspamd_plugins_table_push_elt(L, "enabled", module_name);

	return TRUE;
}

static gboolean
rspamd_config_action_from_ucl(struct rspamd_config *cfg,
							  struct rspamd_action *act,
							  const ucl_object_t *obj,
							  guint priority)
{
	const ucl_object_t *elt;
	gdouble threshold = NAN;
	int flags = 0, obj_type;

	obj_type = ucl_object_type(obj);

	if (obj_type == UCL_OBJECT) {
		obj_type = ucl_object_type(obj);

		elt = ucl_object_lookup_any(obj, "score", "threshold", nullptr);

		if (elt) {
			threshold = ucl_object_todouble(elt);
		}

		elt = ucl_object_lookup(obj, "flags");

		if (elt && ucl_object_type(elt) == UCL_ARRAY) {
			const ucl_object_t *cur;
			ucl_object_iter_t it = nullptr;

			while ((cur = ucl_object_iterate(elt, &it, true)) != nullptr) {
				if (ucl_object_type(cur) == UCL_STRING) {
					const gchar *fl_str = ucl_object_tostring(cur);

					if (g_ascii_strcasecmp(fl_str, "no_threshold") == 0) {
						flags |= RSPAMD_ACTION_NO_THRESHOLD;
					}
					else if (g_ascii_strcasecmp(fl_str, "threshold_only") == 0) {
						flags |= RSPAMD_ACTION_THRESHOLD_ONLY;
					}
					else if (g_ascii_strcasecmp(fl_str, "ham") == 0) {
						flags |= RSPAMD_ACTION_HAM;
					}
					else {
						msg_warn_config("unknown action flag: %s", fl_str);
					}
				}
			}
		}

		elt = ucl_object_lookup(obj, "milter");

		if (elt) {
			const gchar *milter_action = ucl_object_tostring(elt);

			if (strcmp(milter_action, "discard") == 0) {
				flags |= RSPAMD_ACTION_MILTER;
				act->action_type = METRIC_ACTION_DISCARD;
			}
			else if (strcmp(milter_action, "quarantine") == 0) {
				flags |= RSPAMD_ACTION_MILTER;
				act->action_type = METRIC_ACTION_QUARANTINE;
			}
			else {
				msg_warn_config("unknown milter action: %s", milter_action);
			}
		}
	}
	else if (obj_type == UCL_FLOAT || obj_type == UCL_INT) {
		threshold = ucl_object_todouble(obj);
	}

	/* TODO: add lua references support */

	if (isnan(threshold) && !(flags & RSPAMD_ACTION_NO_THRESHOLD)) {
		msg_err_config("action %s has no threshold being set and it is not"
					   " a no threshold action",
					   act->name);

		return FALSE;
	}

	act->threshold = threshold;
	act->flags = flags;

	enum rspamd_action_type std_act;

	if (!(flags & RSPAMD_ACTION_MILTER)) {
		if (rspamd_action_from_str(act->name, &std_act)) {
			act->action_type = std_act;
		}
		else {
			act->action_type = METRIC_ACTION_CUSTOM;
		}
	}

	return TRUE;
}

gboolean
rspamd_config_set_action_score(struct rspamd_config *cfg,
							   const gchar *action_name,
							   const ucl_object_t *obj)
{
	enum rspamd_action_type std_act;
	const ucl_object_t *elt;
	guint priority = ucl_object_get_priority(obj), obj_type;

	g_assert(cfg != nullptr);
	g_assert(action_name != nullptr);

	obj_type = ucl_object_type(obj);

	if (obj_type == UCL_OBJECT) {
		elt = ucl_object_lookup(obj, "priority");

		if (elt) {
			priority = ucl_object_toint(elt);
		}
	}

	/* Here are dragons:
	 * We have `canonical` name for actions, such as `soft reject` and
	 * configuration names for actions (used to be more convenient), such
	 * as `soft_reject`. Unfortunately, we must have heuristic for this
	 * variance of names.
	 */

	if (rspamd_action_from_str(action_name, &std_act)) {
		action_name = rspamd_action_to_str(std_act);
	}

	auto actions = RSPAMD_CFG_ACTIONS(cfg);
	auto existing_act_it = actions->actions_by_name.find(action_name);

	if (existing_act_it != actions->actions_by_name.end()) {
		auto *act = existing_act_it->second.get();
		/* Existing element */
		if (act->priority <= priority) {
			/* We can replace data */
			msg_info_config("action %s has been already registered with "
							"priority %ud, override it with new priority: %ud, "
							"old score: %.2f",
							action_name,
							act->priority,
							priority,
							act->threshold);
			if (rspamd_config_action_from_ucl(cfg, act, obj, priority)) {
				actions->sort();
			}
			else {
				return FALSE;
			}
		}
		else {
			msg_info_config("action %s has been already registered with "
							"priority %ud, do not override (new priority: %ud)",
							action_name,
							act->priority,
							priority);
		}
	}
	else {
		/* Add new element */
		auto act = std::make_shared<rspamd_action>();
		act->name = rspamd_mempool_strdup(cfg->cfg_pool, action_name);

		if (rspamd_config_action_from_ucl(cfg, act.get(), obj, priority)) {
			actions->add_action(std::move(act));
		}
		else {
			return FALSE;
		}
	}

	return TRUE;
}

gboolean
rspamd_config_maybe_disable_action(struct rspamd_config *cfg,
								   const gchar *action_name,
								   guint priority)
{
	auto actions = RSPAMD_CFG_ACTIONS(cfg);
	auto maybe_act = rspamd::find_map(actions->actions_by_name, action_name);

	if (maybe_act) {
		auto *act = maybe_act.value().get().get();
		if (priority >= act->priority) {
			msg_info_config("disable action %s; old priority: %ud, new priority: %ud",
							action_name,
							act->priority,
							priority);

			act->threshold = NAN;
			act->priority = priority;
			act->flags |= RSPAMD_ACTION_NO_THRESHOLD;

			return TRUE;
		}
		else {
			msg_info_config("action %s has been already registered with "
							"priority %ud, cannot disable it with new priority: %ud",
							action_name,
							act->priority,
							priority);
		}
	}

	return FALSE;
}

struct rspamd_action *
rspamd_config_get_action(struct rspamd_config *cfg, const gchar *name)
{
	auto actions = RSPAMD_CFG_ACTIONS(cfg);
	auto maybe_act = rspamd::find_map(actions->actions_by_name, name);

	if (maybe_act) {
		return maybe_act.value().get().get();
	}

	return nullptr;
}

struct rspamd_action *
rspamd_config_get_action_by_type(struct rspamd_config *cfg,
								 enum rspamd_action_type type)
{
	for (const auto &act: RSPAMD_CFG_ACTIONS(cfg)->actions) {
		if (act->action_type == type) {
			return act.get();
		}
	}

	return nullptr;
}

void rspamd_config_actions_foreach(struct rspamd_config *cfg,
								   void (*func)(struct rspamd_action *act, void *d),
								   void *data)
{
	for (const auto &act: RSPAMD_CFG_ACTIONS(cfg)->actions) {
		func(act.get(), data);
	}
}

void rspamd_config_actions_foreach_enumerate(struct rspamd_config *cfg,
											 void (*func)(int idx, struct rspamd_action *act, void *d),
											 void *data)
{
	for (const auto &[idx, act]: rspamd::enumerate(RSPAMD_CFG_ACTIONS(cfg)->actions)) {
		func(idx, act.get(), data);
	}
}

gsize rspamd_config_actions_size(struct rspamd_config *cfg)
{
	return RSPAMD_CFG_ACTIONS(cfg)->actions.size();
}

gboolean
rspamd_config_radix_from_ucl(struct rspamd_config *cfg, const ucl_object_t *obj, const gchar *description,
							 struct rspamd_radix_map_helper **target, GError **err,
							 struct rspamd_worker *worker, const gchar *map_name)
{
	ucl_type_t type;
	ucl_object_iter_t it = nullptr;
	const ucl_object_t *cur, *cur_elt;
	const gchar *str;

	/* Cleanup */
	*target = nullptr;

	LL_FOREACH(obj, cur_elt)
	{
		type = ucl_object_type(cur_elt);

		switch (type) {
		case UCL_STRING:
			/* Either map or a list of IPs */
			str = ucl_object_tostring(cur_elt);

			if (rspamd_map_is_map(str)) {
				if (rspamd_map_add_from_ucl(cfg, cur_elt,
											description,
											rspamd_radix_read,
											rspamd_radix_fin,
											rspamd_radix_dtor,
											(void **) target,
											worker, RSPAMD_MAP_DEFAULT) == nullptr) {
					g_set_error(err,
								g_quark_from_static_string("rspamd-config"),
								EINVAL, "bad map definition %s for %s", str,
								ucl_object_key(obj));
					return FALSE;
				}

				return TRUE;
			}
			else {
				/* Just a list */
				if (!*target) {
					*target = rspamd_map_helper_new_radix(
						rspamd_map_add_fake(cfg, description, map_name));
				}

				rspamd_map_helper_insert_radix_resolve(*target, str, "");
			}
			break;
		case UCL_OBJECT:
			/* Should be a map description */
			if (rspamd_map_add_from_ucl(cfg, cur_elt,
										description,
										rspamd_radix_read,
										rspamd_radix_fin,
										rspamd_radix_dtor,
										(void **) target,
										worker, RSPAMD_MAP_DEFAULT) == nullptr) {
				g_set_error(err,
							g_quark_from_static_string("rspamd-config"),
							EINVAL, "bad map object for %s", ucl_object_key(obj));
				return FALSE;
			}

			return TRUE;
			break;
		case UCL_ARRAY:
			/* List of IP addresses */
			it = ucl_object_iterate_new(cur_elt);

			while ((cur = ucl_object_iterate_safe(it, true)) != nullptr) {


				if (ucl_object_type(cur) == UCL_STRING) {
					str = ucl_object_tostring(cur);
					if (!*target) {
						*target = rspamd_map_helper_new_radix(
							rspamd_map_add_fake(cfg, description, map_name));
					}

					rspamd_map_helper_insert_radix_resolve(*target, str, "");
				}
				else {
					g_set_error(err,
								g_quark_from_static_string("rspamd-config"),
								EINVAL, "bad element inside array object for %s: expected string, got: %s",
								ucl_object_key(obj), ucl_object_type_to_string(ucl_object_type(cur)));
					ucl_object_iterate_free(it);
					return FALSE;
				}
			}

			ucl_object_iterate_free(it);
			break;
		default:
			g_set_error(err, g_quark_from_static_string("rspamd-config"),
						EINVAL, "bad map type %s for %s",
						ucl_object_type_to_string(type),
						ucl_object_key(obj));
			return FALSE;
		}
	}

	/* Destroy on cfg cleanup */
	rspamd_mempool_add_destructor(cfg->cfg_pool,
								  (rspamd_mempool_destruct_t) rspamd_map_helper_destroy_radix,
								  *target);

	return TRUE;
}

constexpr const auto action_types = frozen::make_unordered_map<frozen::string, enum rspamd_action_type>({
	{"reject", METRIC_ACTION_REJECT},
	{"greylist", METRIC_ACTION_GREYLIST},
	{"add header", METRIC_ACTION_ADD_HEADER},
	{"add_header", METRIC_ACTION_ADD_HEADER},
	{"rewrite subject", METRIC_ACTION_REWRITE_SUBJECT},
	{"rewrite_subject", METRIC_ACTION_REWRITE_SUBJECT},
	{"soft reject", METRIC_ACTION_SOFT_REJECT},
	{"soft_reject", METRIC_ACTION_SOFT_REJECT},
	{"no action", METRIC_ACTION_NOACTION},
	{"no_action", METRIC_ACTION_NOACTION},
	{"accept", METRIC_ACTION_NOACTION},
	{"quarantine", METRIC_ACTION_QUARANTINE},
	{"discard", METRIC_ACTION_DISCARD},

});

gboolean
rspamd_action_from_str(const gchar *data, enum rspamd_action_type *result)
{
	auto maybe_action = rspamd::find_map(action_types, std::string_view{data});

	if (maybe_action) {
		*result = maybe_action.value().get();
		return true;
	}
	else {
		return false;
	}
}

const gchar *
rspamd_action_to_str(enum rspamd_action_type action)
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
rspamd_action_to_str_alt(enum rspamd_action_type action)
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

static void
rspamd_config_settings_elt_dtor(struct rspamd_config_settings_elt *e)
{
	if (e->symbols_enabled) {
		ucl_object_unref(e->symbols_enabled);
	}
	if (e->symbols_disabled) {
		ucl_object_unref(e->symbols_disabled);
	}
}

guint32
rspamd_config_name_to_id(const gchar *name, gsize namelen)
{
	guint64 h;

	h = rspamd_cryptobox_fast_hash_specific(RSPAMD_CRYPTOBOX_XXHASH64,
											name, namelen, 0x0);
	/* Take the lower part of hash as LE number */
	return ((guint32) GUINT64_TO_LE(h));
}

struct rspamd_config_settings_elt *
rspamd_config_find_settings_id_ref(struct rspamd_config *cfg,
								   guint32 id)
{
	struct rspamd_config_settings_elt *cur;

	DL_FOREACH(cfg->setting_ids, cur)
	{
		if (cur->id == id) {
			REF_RETAIN(cur);
			return cur;
		}
	}

	return nullptr;
}

struct rspamd_config_settings_elt *rspamd_config_find_settings_name_ref(
	struct rspamd_config *cfg,
	const gchar *name, gsize namelen)
{
	guint32 id;

	id = rspamd_config_name_to_id(name, namelen);

	return rspamd_config_find_settings_id_ref(cfg, id);
}

void rspamd_config_register_settings_id(struct rspamd_config *cfg,
										const gchar *name,
										ucl_object_t *symbols_enabled,
										ucl_object_t *symbols_disabled,
										enum rspamd_config_settings_policy policy)
{
	struct rspamd_config_settings_elt *elt;
	guint32 id;

	id = rspamd_config_name_to_id(name, strlen(name));
	elt = rspamd_config_find_settings_id_ref(cfg, id);

	if (elt) {
		/* Need to replace */
		struct rspamd_config_settings_elt *nelt;

		DL_DELETE(cfg->setting_ids, elt);

		nelt = rspamd_mempool_alloc0_type(cfg->cfg_pool, struct rspamd_config_settings_elt);

		nelt->id = id;
		nelt->name = rspamd_mempool_strdup(cfg->cfg_pool, name);

		if (symbols_enabled) {
			nelt->symbols_enabled = ucl_object_ref(symbols_enabled);
		}

		if (symbols_disabled) {
			nelt->symbols_disabled = ucl_object_ref(symbols_disabled);
		}

		nelt->policy = policy;

		REF_INIT_RETAIN(nelt, rspamd_config_settings_elt_dtor);
		msg_warn_config("replace settings id %ud (%s)", id, name);
		rspamd_symcache_process_settings_elt(cfg->cache, elt);
		DL_APPEND(cfg->setting_ids, nelt);

		/*
		 * Need to unref old element twice as there are two reference holders:
		 * 1. Config structure as we call REF_INIT_RETAIN
		 * 2. rspamd_config_find_settings_id_ref also increases refcount
		 */
		REF_RELEASE(elt);
		REF_RELEASE(elt);
	}
	else {
		elt = rspamd_mempool_alloc0_type(cfg->cfg_pool, struct rspamd_config_settings_elt);

		elt->id = id;
		elt->name = rspamd_mempool_strdup(cfg->cfg_pool, name);

		if (symbols_enabled) {
			elt->symbols_enabled = ucl_object_ref(symbols_enabled);
		}

		if (symbols_disabled) {
			elt->symbols_disabled = ucl_object_ref(symbols_disabled);
		}

		elt->policy = policy;

		msg_info_config("register new settings id %ud (%s)", id, name);
		REF_INIT_RETAIN(elt, rspamd_config_settings_elt_dtor);
		rspamd_symcache_process_settings_elt(cfg->cache, elt);
		DL_APPEND(cfg->setting_ids, elt);
	}
}

int rspamd_config_ev_backend_get(struct rspamd_config *cfg)
{
#define AUTO_BACKEND (ev_supported_backends() & ~EVBACKEND_IOURING)
	if (cfg == nullptr || cfg->events_backend == nullptr) {
		return AUTO_BACKEND;
	}

	if (strcmp(cfg->events_backend, "auto") == 0) {
		return AUTO_BACKEND;
	}
	else if (strcmp(cfg->events_backend, "epoll") == 0) {
		if (ev_supported_backends() & EVBACKEND_EPOLL) {
			return EVBACKEND_EPOLL;
		}
		else {
			msg_warn_config("unsupported events_backend: %s; defaulting to auto",
							cfg->events_backend);
			return AUTO_BACKEND;
		}
	}
	else if (strcmp(cfg->events_backend, "iouring") == 0) {
		if (ev_supported_backends() & EVBACKEND_IOURING) {
			return EVBACKEND_IOURING;
		}
		else {
			msg_warn_config("unsupported events_backend: %s; defaulting to auto",
							cfg->events_backend);
			return AUTO_BACKEND;
		}
	}
	else if (strcmp(cfg->events_backend, "kqueue") == 0) {
		if (ev_supported_backends() & EVBACKEND_KQUEUE) {
			return EVBACKEND_KQUEUE;
		}
		else {
			msg_warn_config("unsupported events_backend: %s; defaulting to auto",
							cfg->events_backend);
			return AUTO_BACKEND;
		}
	}
	else if (strcmp(cfg->events_backend, "poll") == 0) {
		return EVBACKEND_POLL;
	}
	else if (strcmp(cfg->events_backend, "select") == 0) {
		return EVBACKEND_SELECT;
	}
	else {
		msg_warn_config("unknown events_backend: %s; defaulting to auto",
						cfg->events_backend);
	}

	return AUTO_BACKEND;
}

const gchar *
rspamd_config_ev_backend_to_string(int ev_backend, gboolean *effective)
{
#define SET_EFFECTIVE(b)                              \
	do {                                              \
		if ((effective) != nullptr) *(effective) = b; \
	} while (0)

	if ((ev_backend & EVBACKEND_ALL) == EVBACKEND_ALL) {
		SET_EFFECTIVE(TRUE);
		return "auto";
	}

	if (ev_backend & EVBACKEND_IOURING) {
		SET_EFFECTIVE(TRUE);
		return "epoll+io_uring";
	}
	if (ev_backend & EVBACKEND_LINUXAIO) {
		SET_EFFECTIVE(TRUE);
		return "epoll+aio";
	}
	if (ev_backend & EVBACKEND_IOURING) {
		SET_EFFECTIVE(TRUE);
		return "epoll+io_uring";
	}
	if (ev_backend & EVBACKEND_LINUXAIO) {
		SET_EFFECTIVE(TRUE);
		return "epoll+aio";
	}
	if (ev_backend & EVBACKEND_EPOLL) {
		SET_EFFECTIVE(TRUE);
		return "epoll";
	}
	if (ev_backend & EVBACKEND_KQUEUE) {
		SET_EFFECTIVE(TRUE);
		return "kqueue";
	}
	if (ev_backend & EVBACKEND_POLL) {
		SET_EFFECTIVE(FALSE);
		return "poll";
	}
	if (ev_backend & EVBACKEND_SELECT) {
		SET_EFFECTIVE(FALSE);
		return "select";
	}

	SET_EFFECTIVE(FALSE);
	return "unknown";
#undef SET_EFFECTIVE
}

struct rspamd_external_libs_ctx *
rspamd_init_libs(void)
{
	struct rlimit rlim;
	struct ottery_config *ottery_cfg;

	auto *ctx = g_new0(struct rspamd_external_libs_ctx, 1);
	ctx->crypto_ctx = rspamd_cryptobox_init();
	ottery_cfg = (struct ottery_config *) g_malloc0(ottery_get_sizeof_config());
	ottery_config_init(ottery_cfg);
	ctx->ottery_cfg = ottery_cfg;

	rspamd_openssl_maybe_init();

	/* Check if we have rdrand */
	if ((ctx->crypto_ctx->cpu_config & CPUID_RDRAND) == 0) {
		ottery_config_disable_entropy_sources(ottery_cfg,
											  OTTERY_ENTROPY_SRC_RDRAND);
	}

	g_assert(ottery_init(ottery_cfg) == 0);
#if OPENSSL_VERSION_NUMBER >= 0x1000104fL && OPENSSL_VERSION_NUMBER < 0x30000000L && !defined(LIBRESSL_VERSION_NUMBER)
	RAND_set_rand_engine(nullptr);
#endif

	/* Configure utf8 library */
	guint utf8_flags = 0;

	if ((ctx->crypto_ctx->cpu_config & CPUID_SSE41)) {
		utf8_flags |= RSPAMD_FAST_UTF8_FLAG_SSE41;
	}
	if ((ctx->crypto_ctx->cpu_config & CPUID_AVX2)) {
		utf8_flags |= RSPAMD_FAST_UTF8_FLAG_AVX2;
	}

	rspamd_fast_utf8_library_init(utf8_flags);

#ifdef HAVE_LOCALE_H
	if (getenv("LANG") == nullptr) {
		setlocale(LC_ALL, "C");
		setlocale(LC_CTYPE, "C");
		setlocale(LC_MESSAGES, "C");
		setlocale(LC_TIME, "C");
	}
	else {
		/* Just set the default locale */
		setlocale(LC_ALL, "");
		/* But for some issues we still want C locale */
		setlocale(LC_NUMERIC, "C");
	}
#endif

	ctx->ssl_ctx = rspamd_init_ssl_ctx();
	ctx->ssl_ctx_noverify = rspamd_init_ssl_ctx_noverify();
	rspamd_random_seed_fast();

	/* Set stack size for pcre */
	getrlimit(RLIMIT_STACK, &rlim);
	rlim.rlim_cur = 100 * 1024 * 1024;
	rlim.rlim_max = rlim.rlim_cur;
	setrlimit(RLIMIT_STACK, &rlim);

	ctx->local_addrs = rspamd_inet_library_init();
	REF_INIT_RETAIN(ctx, rspamd_deinit_libs);

	return ctx;
}

static struct zstd_dictionary *
rspamd_open_zstd_dictionary(const char *path)
{
	struct zstd_dictionary *dict;

	dict = g_new0(zstd_dictionary, 1);
	dict->dict = rspamd_file_xmap(path, PROT_READ, &dict->size, TRUE);

	if (dict->dict == nullptr) {
		g_free(dict);

		return nullptr;
	}

	dict->id = -1;

	if (dict->id == 0) {
		g_free(dict);

		return nullptr;
	}

	return dict;
}

static void
rspamd_free_zstd_dictionary(struct zstd_dictionary *dict)
{
	if (dict) {
		munmap(dict->dict, dict->size);
		g_free(dict);
	}
}

#ifdef HAVE_OPENBLAS_SET_NUM_THREADS
extern "C" void openblas_set_num_threads(int num_threads);
#endif
#ifdef HAVE_BLI_THREAD_SET_NUM_THREADS
extern "C" void bli_thread_set_num_threads(int num_threads);
#endif

gboolean
rspamd_config_libs(struct rspamd_external_libs_ctx *ctx,
				   struct rspamd_config *cfg)
{
	size_t r;
	gboolean ret = TRUE;

	g_assert(cfg != nullptr);

	if (ctx != nullptr) {
		if (cfg->local_addrs) {
			ret = rspamd_config_radix_from_ucl(cfg, cfg->local_addrs,
											   "Local addresses",
											   (struct rspamd_radix_map_helper **) ctx->local_addrs,
											   nullptr,
											   nullptr, "local addresses");
		}

		rspamd_free_zstd_dictionary(ctx->in_dict);
		rspamd_free_zstd_dictionary(ctx->out_dict);

		if (ctx->out_zstream) {
			ZSTD_freeCStream((ZSTD_CCtx *) ctx->out_zstream);
			ctx->out_zstream = nullptr;
		}

		if (ctx->in_zstream) {
			ZSTD_freeDStream((ZSTD_DCtx *) ctx->in_zstream);
			ctx->in_zstream = nullptr;
		}

		if (cfg->zstd_input_dictionary) {
			ctx->in_dict = rspamd_open_zstd_dictionary(
				cfg->zstd_input_dictionary);

			if (ctx->in_dict == nullptr) {
				msg_err_config("cannot open zstd dictionary in %s",
							   cfg->zstd_input_dictionary);
			}
		}
		if (cfg->zstd_output_dictionary) {
			ctx->out_dict = rspamd_open_zstd_dictionary(
				cfg->zstd_output_dictionary);

			if (ctx->out_dict == nullptr) {
				msg_err_config("cannot open zstd dictionary in %s",
							   cfg->zstd_output_dictionary);
			}
		}

		if (cfg->fips_mode) {
#ifdef HAVE_FIPS_MODE
			int mode = FIPS_mode();
			unsigned long err = (unsigned long) -1;

			/* Toggle FIPS mode */
			if (mode == 0) {
#if defined(OPENSSL_VERSION_MAJOR) && (OPENSSL_VERSION_MAJOR >= 3)
				if (EVP_set_default_properties(nullptr, "fips=yes") != 1) {
#else
				if (FIPS_mode_set(1) != 1) {
#endif
					err = ERR_get_error();
				}
			}
			else {
				msg_info_config("OpenSSL FIPS mode is already enabled");
			}

			if (err != (unsigned long) -1) {
#if defined(OPENSSL_VERSION_MAJOR) && (OPENSSL_VERSION_MAJOR >= 3)
				msg_err_config("EVP_set_default_properties failed: %s",
#else
				msg_err_config("FIPS_mode_set failed: %s",
#endif
							   ERR_error_string(err, nullptr));
				ret = FALSE;
			}
			else {
				msg_info_config("OpenSSL FIPS mode is enabled");
			}
#else
			msg_warn_config("SSL FIPS mode is enabled but not supported by OpenSSL library!");
#endif
		}

		rspamd_ssl_ctx_config(cfg, ctx->ssl_ctx);
		rspamd_ssl_ctx_config(cfg, ctx->ssl_ctx_noverify);

		/* Init decompression */
		ctx->in_zstream = ZSTD_createDStream();
		r = ZSTD_initDStream((ZSTD_DCtx *) ctx->in_zstream);

		if (ZSTD_isError(r)) {
			msg_err("cannot init decompression stream: %s",
					ZSTD_getErrorName(r));
			ZSTD_freeDStream((ZSTD_DCtx *) ctx->in_zstream);
			ctx->in_zstream = nullptr;
		}

		/* Init compression */
		ctx->out_zstream = ZSTD_createCStream();
		r = ZSTD_initCStream((ZSTD_CCtx *) ctx->out_zstream, 1);

		if (ZSTD_isError(r)) {
			msg_err("cannot init compression stream: %s",
					ZSTD_getErrorName(r));
			ZSTD_freeCStream((ZSTD_CCtx *) ctx->out_zstream);
			ctx->out_zstream = nullptr;
		}
#ifdef HAVE_OPENBLAS_SET_NUM_THREADS
		openblas_set_num_threads(cfg->max_blas_threads);
#endif
#ifdef HAVE_BLI_THREAD_SET_NUM_THREADS
		bli_thread_set_num_threads(cfg->max_blas_threads);
#endif
	}

	return ret;
}

gboolean
rspamd_libs_reset_decompression(struct rspamd_external_libs_ctx *ctx)
{
	gsize r;

	if (ctx->in_zstream == nullptr) {
		return FALSE;
	}
	else {
		r = ZSTD_DCtx_reset((ZSTD_DCtx *) ctx->in_zstream, ZSTD_reset_session_only);

		if (ZSTD_isError(r)) {
			msg_err("cannot init decompression stream: %s",
					ZSTD_getErrorName(r));
			ZSTD_freeDStream((ZSTD_DCtx *) ctx->in_zstream);
			ctx->in_zstream = nullptr;

			return FALSE;
		}
	}

	return TRUE;
}

gboolean
rspamd_libs_reset_compression(struct rspamd_external_libs_ctx *ctx)
{
	gsize r;

	if (ctx->out_zstream == nullptr) {
		return FALSE;
	}
	else {
		/* Dictionary will be reused automatically if specified */
		r = ZSTD_CCtx_reset((ZSTD_CCtx *) ctx->out_zstream, ZSTD_reset_session_only);
		if (!ZSTD_isError(r)) {
			r = ZSTD_CCtx_setPledgedSrcSize((ZSTD_CCtx *) ctx->out_zstream, ZSTD_CONTENTSIZE_UNKNOWN);
		}

		if (ZSTD_isError(r)) {
			msg_err("cannot init compression stream: %s",
					ZSTD_getErrorName(r));
			ZSTD_freeCStream((ZSTD_CCtx *) ctx->out_zstream);
			ctx->out_zstream = nullptr;

			return FALSE;
		}
	}

	return TRUE;
}

void rspamd_deinit_libs(struct rspamd_external_libs_ctx *ctx)
{
	if (ctx != nullptr) {
		g_free(ctx->ottery_cfg);

#ifdef HAVE_OPENSSL
		EVP_cleanup();
		ERR_free_strings();
		rspamd_ssl_ctx_free(ctx->ssl_ctx);
		rspamd_ssl_ctx_free(ctx->ssl_ctx_noverify);
#endif
		rspamd_inet_library_destroy();
		rspamd_free_zstd_dictionary(ctx->in_dict);
		rspamd_free_zstd_dictionary(ctx->out_dict);

		if (ctx->out_zstream) {
			ZSTD_freeCStream((ZSTD_CCtx *) ctx->out_zstream);
		}

		if (ctx->in_zstream) {
			ZSTD_freeDStream((ZSTD_DCtx *) ctx->in_zstream);
		}

		rspamd_cryptobox_deinit(ctx->crypto_ctx);

		g_free(ctx);
	}
}

gboolean
rspamd_ip_is_local_cfg(struct rspamd_config *cfg,
					   const rspamd_inet_addr_t *addr)
{
	struct rspamd_radix_map_helper *local_addrs = nullptr;

	if (cfg && cfg->libs_ctx) {
		local_addrs = *(struct rspamd_radix_map_helper **) cfg->libs_ctx->local_addrs;
	}

	if (rspamd_inet_address_is_local(addr)) {
		return TRUE;
	}

	if (local_addrs) {
		if (rspamd_match_radix_map_addr(local_addrs, addr) != nullptr) {
			return TRUE;
		}
	}

	return FALSE;
}
