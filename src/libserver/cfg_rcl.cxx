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

#include "lua/lua_common.h"
#include "cfg_rcl.h"
#include "rspamd.h"
#include "cfg_file_private.h"
#include "utlist.h"
#include "cfg_file.h"
#include "expression.h"
#include "src/libserver/composites/composites.h"
#include "libserver/worker_util.h"
#include "unix-std.h"
#include "cryptobox.h"
#include "libutil/multipattern.h"
#include "libmime/email_addr.h"
#include "libmime/lang_detection.h"

#include <string>
#include <filesystem>
#include <algorithm>// for std::transform
#include <memory>
#include "contrib/ankerl/unordered_dense.h"
#include "fmt/core.h"
#include "libutil/cxx/util.hxx"
#include "libutil/cxx/file_util.hxx"
#include "frozen/unordered_set.h"
#include "frozen/string.h"

#ifdef HAVE_SYSLOG_H
#include <syslog.h>
#endif

#include <cmath>

struct rspamd_rcl_default_handler_data {
	struct rspamd_rcl_struct_parser pd;
	std::string key;
	rspamd_rcl_default_handler_t handler;
};

struct rspamd_rcl_sections_map;

struct rspamd_rcl_section {
	struct rspamd_rcl_sections_map *top{};
	std::string name; /**< name of section */
	std::optional<std::string> key_attr;
	std::optional<std::string> default_key;
	rspamd_rcl_handler_t handler{}; /**< handler of section attributes */
	enum ucl_type type;             /**< type of attribute */
	bool required{};                /**< whether this param is required */
	bool strict_type{};             /**< whether we need strict type */
	mutable bool processed{};       /**< whether this section was processed */
	ankerl::unordered_dense::map<std::string, std::shared_ptr<struct rspamd_rcl_section>> subsections;
	ankerl::unordered_dense::map<std::string, struct rspamd_rcl_default_handler_data> default_parser; /**< generic parsing fields */
	rspamd_rcl_section_fin_t fin{};                                                                   /** called at the end of section parsing */
	gpointer fin_ud{};
	ucl_object_t *doc_ref{}; /**< reference to the section's documentation */

	virtual ~rspamd_rcl_section()
	{
		if (doc_ref) {
			ucl_object_unref(doc_ref);
		}
	}
};

struct rspamd_worker_param_parser {
	rspamd_rcl_default_handler_t handler;   /**< handler function									*/
	struct rspamd_rcl_struct_parser parser; /**< parser attributes									*/
};

struct rspamd_worker_cfg_parser {
	struct pair_hash {
		using is_avalanching = void;
		template<class T1, class T2>
		std::size_t operator()(const std::pair<T1, T2> &pair) const
		{
			return ankerl::unordered_dense::hash<T1>()(pair.first) ^ ankerl::unordered_dense::hash<T2>()(pair.second);
		}
	};
	ankerl::unordered_dense::map<std::pair<std::string, gpointer>,
								 rspamd_worker_param_parser, pair_hash>
		parsers;                                                /**< parsers hash										*/
	gint type;                                                  /**< workers quark										*/
	gboolean (*def_obj_parser)(ucl_object_t *obj, gpointer ud); /**< default object parser								*/
	gpointer def_ud;
};

struct rspamd_rcl_sections_map {
	ankerl::unordered_dense::map<std::string, std::shared_ptr<struct rspamd_rcl_section>> sections;
	std::vector<std::shared_ptr<struct rspamd_rcl_section>> sections_order;
	ankerl::unordered_dense::map<int, struct rspamd_worker_cfg_parser> workers_parser;
	ankerl::unordered_dense::set<std::string> lua_modules_seen;
};

static bool rspamd_rcl_process_section(struct rspamd_config *cfg,
									   const struct rspamd_rcl_section &sec,
									   gpointer ptr, const ucl_object_t *obj, rspamd_mempool_t *pool,
									   GError **err);
static bool
rspamd_rcl_section_parse_defaults(struct rspamd_config *cfg,
								  const struct rspamd_rcl_section &section,
								  rspamd_mempool_t *pool, const ucl_object_t *obj, gpointer ptr,
								  GError **err);

/*
 * Common section handlers
 */
static gboolean
rspamd_rcl_logging_handler(rspamd_mempool_t *pool, const ucl_object_t *obj,
						   const gchar *key, gpointer ud, struct rspamd_rcl_section *section,
						   GError **err)
{
	const ucl_object_t *val;
	const gchar *facility = nullptr, *log_type = nullptr, *log_level = nullptr;
	auto *cfg = (struct rspamd_config *) ud;

	val = ucl_object_lookup(obj, "type");
	if (val != nullptr && ucl_object_tostring_safe(val, &log_type)) {
		if (g_ascii_strcasecmp(log_type, "file") == 0) {
			/* Need to get filename */
			val = ucl_object_lookup(obj, "filename");
			if (val == nullptr || val->type != UCL_STRING) {
				g_set_error(err,
							CFG_RCL_ERROR,
							ENOENT,
							"filename attribute must be specified for file logging type");
				return FALSE;
			}
			cfg->log_type = RSPAMD_LOG_FILE;
			cfg->log_file = rspamd_mempool_strdup(cfg->cfg_pool,
												  ucl_object_tostring(val));
		}
		else if (g_ascii_strcasecmp(log_type, "syslog") == 0) {
			/* Need to get facility */
#ifdef HAVE_SYSLOG_H
			cfg->log_facility = LOG_DAEMON;
			cfg->log_type = RSPAMD_LOG_SYSLOG;
			val = ucl_object_lookup(obj, "facility");
			if (val != nullptr && ucl_object_tostring_safe(val, &facility)) {
				if (g_ascii_strcasecmp(facility, "LOG_AUTH") == 0 ||
					g_ascii_strcasecmp(facility, "auth") == 0) {
					cfg->log_facility = LOG_AUTH;
				}
				else if (g_ascii_strcasecmp(facility, "LOG_CRON") == 0 ||
						 g_ascii_strcasecmp(facility, "cron") == 0) {
					cfg->log_facility = LOG_CRON;
				}
				else if (g_ascii_strcasecmp(facility, "LOG_DAEMON") == 0 ||
						 g_ascii_strcasecmp(facility, "daemon") == 0) {
					cfg->log_facility = LOG_DAEMON;
				}
				else if (g_ascii_strcasecmp(facility, "LOG_MAIL") == 0 ||
						 g_ascii_strcasecmp(facility, "mail") == 0) {
					cfg->log_facility = LOG_MAIL;
				}
				else if (g_ascii_strcasecmp(facility, "LOG_USER") == 0 ||
						 g_ascii_strcasecmp(facility, "user") == 0) {
					cfg->log_facility = LOG_USER;
				}
				else if (g_ascii_strcasecmp(facility, "LOG_LOCAL0") == 0 ||
						 g_ascii_strcasecmp(facility, "local0") == 0) {
					cfg->log_facility = LOG_LOCAL0;
				}
				else if (g_ascii_strcasecmp(facility, "LOG_LOCAL1") == 0 ||
						 g_ascii_strcasecmp(facility, "local1") == 0) {
					cfg->log_facility = LOG_LOCAL1;
				}
				else if (g_ascii_strcasecmp(facility, "LOG_LOCAL2") == 0 ||
						 g_ascii_strcasecmp(facility, "local2") == 0) {
					cfg->log_facility = LOG_LOCAL2;
				}
				else if (g_ascii_strcasecmp(facility, "LOG_LOCAL3") == 0 ||
						 g_ascii_strcasecmp(facility, "local3") == 0) {
					cfg->log_facility = LOG_LOCAL3;
				}
				else if (g_ascii_strcasecmp(facility, "LOG_LOCAL4") == 0 ||
						 g_ascii_strcasecmp(facility, "local4") == 0) {
					cfg->log_facility = LOG_LOCAL4;
				}
				else if (g_ascii_strcasecmp(facility, "LOG_LOCAL5") == 0 ||
						 g_ascii_strcasecmp(facility, "local5") == 0) {
					cfg->log_facility = LOG_LOCAL5;
				}
				else if (g_ascii_strcasecmp(facility, "LOG_LOCAL6") == 0 ||
						 g_ascii_strcasecmp(facility, "local6") == 0) {
					cfg->log_facility = LOG_LOCAL6;
				}
				else if (g_ascii_strcasecmp(facility, "LOG_LOCAL7") == 0 ||
						 g_ascii_strcasecmp(facility, "local7") == 0) {
					cfg->log_facility = LOG_LOCAL7;
				}
				else {
					g_set_error(err,
								CFG_RCL_ERROR,
								EINVAL,
								"invalid log facility: %s",
								facility);
					return FALSE;
				}
			}
#endif
		}
		else if (g_ascii_strcasecmp(log_type,
									"stderr") == 0 ||
				 g_ascii_strcasecmp(log_type, "console") == 0) {
			cfg->log_type = RSPAMD_LOG_CONSOLE;
		}
		else {
			g_set_error(err,
						CFG_RCL_ERROR,
						EINVAL,
						"invalid log type: %s",
						log_type);
			return FALSE;
		}
	}
	else {
		/* No type specified */
		msg_warn_config(
			"logging type is not specified correctly, log output to the console");
	}

	/* Handle log level */
	val = ucl_object_lookup(obj, "level");
	if (val != nullptr && ucl_object_tostring_safe(val, &log_level)) {
		if (g_ascii_strcasecmp(log_level, "error") == 0) {
			cfg->log_level = G_LOG_LEVEL_ERROR | G_LOG_LEVEL_CRITICAL;
		}
		else if (g_ascii_strcasecmp(log_level, "warning") == 0) {
			cfg->log_level = G_LOG_LEVEL_WARNING;
		}
		else if (g_ascii_strcasecmp(log_level, "info") == 0) {
			cfg->log_level = G_LOG_LEVEL_INFO | G_LOG_LEVEL_MESSAGE;
		}
		else if (g_ascii_strcasecmp(log_level, "message") == 0 ||
				 g_ascii_strcasecmp(log_level, "notice") == 0) {
			cfg->log_level = G_LOG_LEVEL_MESSAGE;
		}
		else if (g_ascii_strcasecmp(log_level, "silent") == 0) {
			cfg->log_level = G_LOG_LEVEL_MESSAGE | G_LOG_LEVEL_INFO;
			cfg->log_silent_workers = TRUE;
		}
		else if (g_ascii_strcasecmp(log_level, "debug") == 0) {
			cfg->log_level = G_LOG_LEVEL_DEBUG;
		}
		else {
			g_set_error(err,
						CFG_RCL_ERROR,
						EINVAL,
						"invalid log level: %s",
						log_level);
			return FALSE;
		}
	}

	/* Handle flags */
	val = ucl_object_lookup_any(obj, "color", "log_color", nullptr);
	if (val && ucl_object_toboolean(val)) {
		cfg->log_flags |= RSPAMD_LOG_FLAG_COLOR;
	}

	val = ucl_object_lookup_any(obj, "severity", "log_severity", nullptr);
	if (val && ucl_object_toboolean(val)) {
		cfg->log_flags |= RSPAMD_LOG_FLAG_SEVERITY;
	}

	val = ucl_object_lookup_any(obj, "systemd", "log_systemd", nullptr);
	if (val && ucl_object_toboolean(val)) {
		cfg->log_flags |= RSPAMD_LOG_FLAG_SYSTEMD;
	}

	val = ucl_object_lookup_any(obj, "json", "log_json", nullptr);
	if (val && ucl_object_toboolean(val)) {
		cfg->log_flags |= RSPAMD_LOG_FLAG_JSON;
	}

	val = ucl_object_lookup(obj, "log_re_cache");
	if (val && ucl_object_toboolean(val)) {
		cfg->log_flags |= RSPAMD_LOG_FLAG_RE_CACHE;
	}

	val = ucl_object_lookup_any(obj, "usec", "log_usec", nullptr);
	if (val && ucl_object_toboolean(val)) {
		cfg->log_flags |= RSPAMD_LOG_FLAG_USEC;
	}

	return rspamd_rcl_section_parse_defaults(cfg, *section, cfg->cfg_pool, obj,
											 (void *) cfg, err);
}

static gboolean
rspamd_rcl_options_handler(rspamd_mempool_t *pool, const ucl_object_t *obj,
						   const gchar *key, gpointer ud,
						   struct rspamd_rcl_section *section, GError **err)
{
	const ucl_object_t *dns, *upstream, *neighbours;
	auto *cfg = (struct rspamd_config *) ud;

	auto maybe_subsection = rspamd::find_map(section->subsections, "dns");

	dns = ucl_object_lookup(obj, "dns");
	if (maybe_subsection && dns != nullptr) {
		if (!rspamd_rcl_section_parse_defaults(cfg,
											   *maybe_subsection.value().get(), cfg->cfg_pool, dns,
											   cfg, err)) {
			return FALSE;
		}
	}

	maybe_subsection = rspamd::find_map(section->subsections, "upstream");

	upstream = ucl_object_lookup_any(obj, "upstream", "upstreams", nullptr);
	if (maybe_subsection && upstream != nullptr) {
		if (!rspamd_rcl_section_parse_defaults(cfg,
											   *maybe_subsection.value().get(), cfg->cfg_pool,
											   upstream, cfg, err)) {
			return FALSE;
		}
	}

	maybe_subsection = rspamd::find_map(section->subsections, "neighbours");

	neighbours = ucl_object_lookup(obj, "neighbours");
	if (maybe_subsection && neighbours != nullptr) {
		const ucl_object_t *cur;

		LL_FOREACH(neighbours, cur)
		{
			if (!rspamd_rcl_process_section(cfg, *maybe_subsection.value().get(), cfg, cur,
											pool, err)) {
				return FALSE;
			}
		}
	}

	const auto *gtube_patterns = ucl_object_lookup(obj, "gtube_patterns");
	if (gtube_patterns != nullptr && ucl_object_type(gtube_patterns) == UCL_STRING) {
		auto gtube_st = std::string{ucl_object_tostring(gtube_patterns)};
		std::transform(gtube_st.begin(), gtube_st.end(), gtube_st.begin(), [](const auto c) -> int {
			if (c <= 'Z' && c >= 'A')
				return c - ('Z' - 'z');
			return c;
		});


		if (gtube_st == "all") {
			cfg->gtube_patterns_policy = RSPAMD_GTUBE_ALL;
		}
		else if (gtube_st == "reject") {
			cfg->gtube_patterns_policy = RSPAMD_GTUBE_REJECT;
		}
		else if (gtube_st == "disabled" || gtube_st == "disable") {
			cfg->gtube_patterns_policy = RSPAMD_GTUBE_DISABLED;
		}
		else {
			g_set_error(err,
						CFG_RCL_ERROR,
						EINVAL,
						"invalid GTUBE patterns policy: %s",
						gtube_st.c_str());
			return FALSE;
		}
	}
	else if (auto *enable_test_patterns = ucl_object_lookup(obj, "enable_test_patterns"); enable_test_patterns != nullptr) {
		/* Legacy setting */
		if (!!ucl_object_toboolean(enable_test_patterns)) {
			cfg->gtube_patterns_policy = RSPAMD_GTUBE_ALL;
		}
	}

	if (rspamd_rcl_section_parse_defaults(cfg,
										  *section, cfg->cfg_pool, obj,
										  cfg, err)) {
		/* We need to init this early */
		rspamd_multipattern_library_init(cfg->hs_cache_dir);

		return TRUE;
	}

	return FALSE;
}

struct rspamd_rcl_symbol_data {
	struct rspamd_symbols_group *gr;
	struct rspamd_config *cfg;
};

static gboolean
rspamd_rcl_group_handler(rspamd_mempool_t *pool, const ucl_object_t *obj,
						 const gchar *key, gpointer ud,
						 struct rspamd_rcl_section *section, GError **err)
{
	auto *cfg = static_cast<rspamd_config *>(ud);

	g_assert(key != nullptr);

	auto *gr = static_cast<rspamd_symbols_group *>(g_hash_table_lookup(cfg->groups, key));

	if (gr == nullptr) {
		gr = rspamd_config_new_group(cfg, key);
	}

	if (!rspamd_rcl_section_parse_defaults(cfg, *section, pool, obj,
										   gr, err)) {
		return FALSE;
	}

	if (const auto *elt = ucl_object_lookup(obj, "one_shot"); elt != nullptr) {
		if (ucl_object_type(elt) != UCL_BOOLEAN) {
			g_set_error(err,
						CFG_RCL_ERROR,
						EINVAL,
						"one_shot attribute is not boolean for symbol: '%s'",
						key);

			return FALSE;
		}
		if (ucl_object_toboolean(elt)) {
			gr->flags |= RSPAMD_SYMBOL_GROUP_ONE_SHOT;
		}
	}

	if (const auto *elt = ucl_object_lookup(obj, "disabled"); elt != nullptr) {
		if (ucl_object_type(elt) != UCL_BOOLEAN) {
			g_set_error(err,
						CFG_RCL_ERROR,
						EINVAL,
						"disabled attribute is not boolean for symbol: '%s'",
						key);

			return FALSE;
		}
		if (ucl_object_toboolean(elt)) {
			gr->flags |= RSPAMD_SYMBOL_GROUP_DISABLED;
		}
	}

	if (const auto *elt = ucl_object_lookup(obj, "enabled"); elt != nullptr) {
		if (ucl_object_type(elt) != UCL_BOOLEAN) {
			g_set_error(err,
						CFG_RCL_ERROR,
						EINVAL,
						"enabled attribute is not boolean for symbol: '%s'",
						key);

			return FALSE;
		}
		if (!ucl_object_toboolean(elt)) {
			gr->flags |= RSPAMD_SYMBOL_GROUP_DISABLED;
		}
	}

	if (const auto *elt = ucl_object_lookup(obj, "public"); elt != nullptr) {
		if (ucl_object_type(elt) != UCL_BOOLEAN) {
			g_set_error(err,
						CFG_RCL_ERROR,
						EINVAL,
						"public attribute is not boolean for symbol: '%s'",
						key);

			return FALSE;
		}
		if (ucl_object_toboolean(elt)) {
			gr->flags |= RSPAMD_SYMBOL_GROUP_PUBLIC;
		}
	}

	if (const auto *elt = ucl_object_lookup(obj, "private"); elt != nullptr) {
		if (ucl_object_type(elt) != UCL_BOOLEAN) {
			g_set_error(err,
						CFG_RCL_ERROR,
						EINVAL,
						"private attribute is not boolean for symbol: '%s'",
						key);

			return FALSE;
		}
		if (!ucl_object_toboolean(elt)) {
			gr->flags |= RSPAMD_SYMBOL_GROUP_PUBLIC;
		}
	}


	if (const auto *elt = ucl_object_lookup(obj, "description"); elt != nullptr) {
		gr->description = rspamd_mempool_strdup(cfg->cfg_pool,
												ucl_object_tostring(elt));
	}

	struct rspamd_rcl_symbol_data sd = {
		.gr = gr,
		.cfg = cfg,
	};

	/* Handle symbols */
	if (const auto *val = ucl_object_lookup(obj, "symbols"); val != nullptr && ucl_object_type(val) == UCL_OBJECT) {
		auto subsection = rspamd::find_map(section->subsections, "symbols");

		g_assert(subsection.has_value());
		if (!rspamd_rcl_process_section(cfg, *subsection.value().get(), &sd, val,
										pool, err)) {

			return FALSE;
		}
	}

	return TRUE;
}

static gboolean
rspamd_rcl_symbol_handler(rspamd_mempool_t *pool, const ucl_object_t *obj,
						  const gchar *key, gpointer ud,
						  struct rspamd_rcl_section *section, GError **err)
{
	auto *sd = static_cast<rspamd_rcl_symbol_data *>(ud);
	struct rspamd_config *cfg;
	const ucl_object_t *elt;
	const gchar *description = nullptr;
	gdouble score = NAN;
	guint priority = 1, flags = 0;
	gint nshots = 0;

	g_assert(key != nullptr);
	cfg = sd->cfg;

	if ((elt = ucl_object_lookup(obj, "one_shot")) != nullptr) {
		if (ucl_object_type(elt) != UCL_BOOLEAN) {
			g_set_error(err,
						CFG_RCL_ERROR,
						EINVAL,
						"one_shot attribute is not boolean for symbol: '%s'",
						key);

			return FALSE;
		}
		if (ucl_object_toboolean(elt)) {
			nshots = 1;
		}
	}

	if ((elt = ucl_object_lookup(obj, "any_shot")) != nullptr) {
		if (ucl_object_type(elt) != UCL_BOOLEAN) {
			g_set_error(err,
						CFG_RCL_ERROR,
						EINVAL,
						"any_shot attribute is not boolean for symbol: '%s'",
						key);

			return FALSE;
		}
		if (ucl_object_toboolean(elt)) {
			nshots = -1;
		}
	}

	if ((elt = ucl_object_lookup(obj, "one_param")) != nullptr) {
		if (ucl_object_type(elt) != UCL_BOOLEAN) {
			g_set_error(err,
						CFG_RCL_ERROR,
						EINVAL,
						"one_param attribute is not boolean for symbol: '%s'",
						key);

			return FALSE;
		}

		if (ucl_object_toboolean(elt)) {
			flags |= RSPAMD_SYMBOL_FLAG_ONEPARAM;
		}
	}

	if ((elt = ucl_object_lookup(obj, "ignore")) != nullptr) {
		if (ucl_object_type(elt) != UCL_BOOLEAN) {
			g_set_error(err,
						CFG_RCL_ERROR,
						EINVAL,
						"ignore attribute is not boolean for symbol: '%s'",
						key);

			return FALSE;
		}

		if (ucl_object_toboolean(elt)) {
			flags |= RSPAMD_SYMBOL_FLAG_IGNORE_METRIC;
		}
	}

	if ((elt = ucl_object_lookup(obj, "enabled")) != nullptr) {
		if (ucl_object_type(elt) != UCL_BOOLEAN) {
			g_set_error(err,
						CFG_RCL_ERROR,
						EINVAL,
						"enabled attribute is not boolean for symbol: '%s'",
						key);

			return FALSE;
		}

		if (!ucl_object_toboolean(elt)) {
			flags |= RSPAMD_SYMBOL_FLAG_DISABLED;
		}
	}

	if ((elt = ucl_object_lookup(obj, "nshots")) != nullptr) {
		if (ucl_object_type(elt) != UCL_FLOAT && ucl_object_type(elt) != UCL_INT) {
			g_set_error(err,
						CFG_RCL_ERROR,
						EINVAL,
						"nshots attribute is not numeric for symbol: '%s'",
						key);

			return FALSE;
		}

		nshots = ucl_object_toint(elt);
	}

	elt = ucl_object_lookup_any(obj, "score", "weight", nullptr);
	if (elt) {
		if (ucl_object_type(elt) != UCL_FLOAT && ucl_object_type(elt) != UCL_INT) {
			g_set_error(err,
						CFG_RCL_ERROR,
						EINVAL,
						"score attribute is not numeric for symbol: '%s'",
						key);

			return FALSE;
		}

		score = ucl_object_todouble(elt);
	}

	elt = ucl_object_lookup(obj, "priority");
	if (elt) {
		if (ucl_object_type(elt) != UCL_FLOAT && ucl_object_type(elt) != UCL_INT) {
			g_set_error(err,
						CFG_RCL_ERROR,
						EINVAL,
						"priority attribute is not numeric for symbol: '%s'",
						key);

			return FALSE;
		}

		priority = ucl_object_toint(elt);
	}
	else {
		priority = ucl_object_get_priority(obj) + 1;
	}

	elt = ucl_object_lookup(obj, "description");
	if (elt) {
		description = ucl_object_tostring(elt);
	}

	if (sd->gr) {
		rspamd_config_add_symbol(cfg, key, score,
								 description, sd->gr->name, flags, priority, nshots);
	}
	else {
		rspamd_config_add_symbol(cfg, key, score,
								 description, nullptr, flags, priority, nshots);
	}

	elt = ucl_object_lookup(obj, "groups");

	if (elt) {
		ucl_object_iter_t gr_it;
		const ucl_object_t *cur_gr;

		gr_it = ucl_object_iterate_new(elt);

		while ((cur_gr = ucl_object_iterate_safe(gr_it, true)) != nullptr) {
			rspamd_config_add_symbol_group(cfg, key,
										   ucl_object_tostring(cur_gr));
		}

		ucl_object_iterate_free(gr_it);
	}

	return TRUE;
}

static gboolean
rspamd_rcl_actions_handler(rspamd_mempool_t *pool, const ucl_object_t *obj,
						   const gchar *key, gpointer ud,
						   struct rspamd_rcl_section *section, GError **err)
{
	auto *cfg = static_cast<rspamd_config *>(ud);
	const ucl_object_t *cur;
	ucl_object_iter_t it;

	it = ucl_object_iterate_new(obj);

	while ((cur = ucl_object_iterate_safe(it, true)) != nullptr) {
		gint type = ucl_object_type(cur);

		if (type == UCL_NULL) {
			rspamd_config_maybe_disable_action(cfg, ucl_object_key(cur),
											   ucl_object_get_priority(cur));
		}
		else if (type == UCL_OBJECT || type == UCL_FLOAT || type == UCL_INT) {
			/* Exceptions */
			auto default_elt = false;

			for (const auto &[name, def_elt]: section->default_parser) {
				if (def_elt.key == ucl_object_key(cur)) {
					default_elt = true;
					break;
				}
			}

			if (default_elt) {
				continue;
			}

			/* Something non-default */
			if (!rspamd_config_set_action_score(cfg,
												ucl_object_key(cur),
												cur)) {
				g_set_error(err,
							CFG_RCL_ERROR,
							EINVAL,
							"invalid action definition for: '%s'",
							ucl_object_key(cur));
				ucl_object_iterate_free(it);

				return FALSE;
			}
		}
	}

	ucl_object_iterate_free(it);

	return rspamd_rcl_section_parse_defaults(cfg, *section, pool, obj, cfg, err);
}
constexpr const auto known_worker_attributes = frozen::make_unordered_set<frozen::string>({
	"bind_socket",
	"listen",
	"bind",
	"count",
	"max_files",
	"max_core",
	"enabled",
});
static gboolean
rspamd_rcl_worker_handler(rspamd_mempool_t *pool, const ucl_object_t *obj,
						  const gchar *key, gpointer ud,
						  struct rspamd_rcl_section *section, GError **err)
{
	auto *cfg = static_cast<rspamd_config *>(ud);

	g_assert(key != nullptr);
	const auto *worker_type = key;

	auto qtype = g_quark_try_string(worker_type);
	if (qtype == 0) {
		msg_err_config("unknown worker type: %s", worker_type);
		return FALSE;
	}

	auto *wrk = rspamd_config_new_worker(cfg, nullptr);
	wrk->options = ucl_object_copy(obj);
	wrk->worker = rspamd_get_worker_by_type(cfg, qtype);

	if (wrk->worker == nullptr) {
		g_set_error(err,
					CFG_RCL_ERROR,
					EINVAL,
					"unknown worker type: %s",
					worker_type);
		return FALSE;
	}

	wrk->type = qtype;

	if (wrk->worker->worker_init_func) {
		wrk->ctx = wrk->worker->worker_init_func(cfg);
	}

	const auto *val = ucl_object_lookup_any(obj, "bind_socket", "listen", "bind", nullptr);
	/* This name is more logical */
	if (val != nullptr) {
		auto it = ucl_object_iterate_new(val);
		const ucl_object_t *cur;
		const char *worker_bind = nullptr;

		while ((cur = ucl_object_iterate_safe(it, true)) != nullptr) {
			if (!ucl_object_tostring_safe(cur, &worker_bind)) {
				continue;
			}
			if (!rspamd_parse_bind_line(cfg, wrk, worker_bind)) {
				g_set_error(err,
							CFG_RCL_ERROR,
							EINVAL,
							"cannot parse bind line: %s",
							worker_bind);
				ucl_object_iterate_free(it);
				return FALSE;
			}
		}

		ucl_object_iterate_free(it);
	}

	if (!rspamd_rcl_section_parse_defaults(cfg, *section, cfg->cfg_pool, obj,
										   wrk, err)) {
		return FALSE;
	}

	/* Parse other attributes */
	auto maybe_wparser = rspamd::find_map(section->top->workers_parser, wrk->type);

	if (maybe_wparser && obj->type == UCL_OBJECT) {
		auto &wparser = maybe_wparser.value().get();
		auto it = ucl_object_iterate_new(obj);
		const ucl_object_t *cur;

		while ((cur = ucl_object_iterate_full(it, UCL_ITERATE_EXPLICIT)) != nullptr) {
			auto srch = std::make_pair(ucl_object_key(cur), (gpointer) wrk->ctx);
			auto maybe_specific = rspamd::find_map(wparser.parsers, srch);

			if (maybe_specific) {
				auto &whandler = maybe_specific.value().get();
				const ucl_object_t *cur_obj;

				LL_FOREACH(cur, cur_obj)
				{
					if (!whandler.handler(cfg->cfg_pool,
										  cur_obj,
										  (void *) &whandler.parser,
										  section,
										  err)) {

						ucl_object_iterate_free(it);
						return FALSE;
					}

					if (!(whandler.parser.flags & RSPAMD_CL_FLAG_MULTIPLE)) {
						break;
					}
				}
			}
			else if (!(wrk->worker->flags & RSPAMD_WORKER_NO_STRICT_CONFIG) &&
					 known_worker_attributes.find(std::string_view{ucl_object_key(cur)}) == known_worker_attributes.end()) {
				msg_warn_config("unknown worker attribute: %s; worker type: %s", ucl_object_key(cur), worker_type);
			}
		}

		ucl_object_iterate_free(it);

		if (wparser.def_obj_parser != nullptr) {
			auto *robj = ucl_object_ref(obj);

			if (!wparser.def_obj_parser(robj, wparser.def_ud)) {
				ucl_object_unref(robj);

				return FALSE;
			}

			ucl_object_unref(robj);
		}
	}

	cfg->workers = g_list_prepend(cfg->workers, wrk);

	return TRUE;
}

static gboolean
rspamd_rcl_lua_handler(rspamd_mempool_t *pool, const ucl_object_t *obj,
					   const gchar *key, gpointer ud,
					   struct rspamd_rcl_section *section, GError **err)
{
	namespace fs = std::filesystem;
	auto *cfg = static_cast<rspamd_config *>(ud);
	auto lua_src = fs::path{ucl_object_tostring(obj)};
	auto *L = RSPAMD_LUA_CFG_STATE(cfg);
	std::error_code ec1;

	auto lua_dir = fs::weakly_canonical(lua_src.parent_path(), ec1);
	auto lua_file = lua_src.filename();

	if (!ec1 && !lua_dir.empty() && !lua_file.empty()) {
		auto cur_dir = fs::current_path(ec1);
		if (!ec1 && !cur_dir.empty() && ::chdir(lua_dir.c_str()) != -1) {
			/* Push traceback function */
			lua_pushcfunction(L, &rspamd_lua_traceback);
			auto err_idx = lua_gettop(L);

			/* Load file */
			if (luaL_loadfile(L, lua_file.c_str()) != 0) {
				g_set_error(err,
							CFG_RCL_ERROR,
							EINVAL,
							"cannot load lua file %s: %s",
							lua_src.c_str(),
							lua_tostring(L, -1));
				if (::chdir(cur_dir.c_str()) == -1) {
					msg_err_config("cannot chdir to %s: %s", cur_dir.c_str(),
								   strerror(errno));
				}

				return FALSE;
			}

			/* Now do it */
			if (lua_pcall(L, 0, 0, err_idx) != 0) {
				g_set_error(err,
							CFG_RCL_ERROR,
							EINVAL,
							"cannot init lua file %s: %s",
							lua_src.c_str(),
							lua_tostring(L, -1));
				lua_settop(L, 0);

				if (::chdir(cur_dir.c_str()) == -1) {
					msg_err_config("cannot chdir to %s: %s", cur_dir.c_str(),
								   strerror(errno));
				}

				return FALSE;
			}

			lua_pop(L, 1);
		}
		else {
			g_set_error(err, CFG_RCL_ERROR, ENOENT, "cannot chdir to %s: %s",
						lua_dir.c_str(), strerror(errno));
			if (::chdir(cur_dir.c_str()) == -1) {
				msg_err_config("cannot chdir back to %s: %s", cur_dir.c_str(), strerror(errno));
			}

			return FALSE;
		}
		if (::chdir(cur_dir.c_str()) == -1) {
			msg_err_config("cannot chdir back to %s: %s", cur_dir.c_str(), strerror(errno));
		}
	}
	else {

		g_set_error(err, CFG_RCL_ERROR, ENOENT, "cannot find to %s: %s",
					lua_src.c_str(), strerror(errno));
		return FALSE;
	}

	return TRUE;
}

static int
rspamd_lua_mod_sort_fn(gconstpointer a, gconstpointer b)
{
	auto *m1 = *(const script_module **) a;
	auto *m2 = *(const script_module **) b;

	return strcmp(m1->name, m2->name);
}

gboolean
rspamd_rcl_add_lua_plugins_path(struct rspamd_rcl_sections_map *sections,
								struct rspamd_config *cfg,
								const gchar *path,
								gboolean main_path,
								GError **err)
{
	namespace fs = std::filesystem;
	auto dir = fs::path{path};
	std::error_code ec;

	auto add_single_file = [&](const fs::path &fpath) -> bool {
		auto fname = fpath.filename();
		auto modname = fname.string();

		if (fname.has_extension()) {
			modname = modname.substr(0, modname.size() - fname.extension().native().size());
		}
		auto *cur_mod = rspamd_mempool_alloc_type(cfg->cfg_pool,
												  struct script_module);
		cur_mod->path = rspamd_mempool_strdup(cfg->cfg_pool, fpath.c_str());
		cur_mod->name = rspamd_mempool_strdup(cfg->cfg_pool, modname.c_str());

		if (sections->lua_modules_seen.contains(modname)) {
			msg_info_config("already seen module %s, skip %s",
							cur_mod->name, cur_mod->path);
			return false;
		}

		g_ptr_array_add(cfg->script_modules, cur_mod);
		sections->lua_modules_seen.insert(fname.string());

		return true;
	};

	if (fs::is_regular_file(dir, ec) && dir.has_extension() && dir.extension() == ".lua") {
		add_single_file(dir);
	}
	else if (!fs::is_directory(dir, ec)) {
		if (!fs::exists(dir) && !main_path) {
			msg_debug_config("optional plugins path %s is absent, skip it", path);

			return TRUE;
		}

		g_set_error(err,
					CFG_RCL_ERROR,
					errno,
					"invalid lua path spec %s, %s",
					path,
					ec.message().c_str());
		return FALSE;
	}
	else {
		/* Handle directory */
		for (const auto &p: fs::recursive_directory_iterator(dir, ec)) {
			auto fpath = p.path().string();
			if (p.is_regular_file() && fpath.ends_with(".lua")) {
				add_single_file(p.path());
			}
		}
	}

	g_ptr_array_sort(cfg->script_modules, rspamd_lua_mod_sort_fn);

	return TRUE;
}

static gboolean
rspamd_rcl_modules_handler(rspamd_mempool_t *pool, const ucl_object_t *obj,
						   const gchar *key, gpointer ud,
						   struct rspamd_rcl_section *section, GError **err)
{
	auto *cfg = static_cast<rspamd_config *>(ud);
	const char *data;

	if (obj->type == UCL_OBJECT) {
		const auto *val = ucl_object_lookup(obj, "path");

		if (val) {
			const auto *cur = val;
			LL_FOREACH(val, cur)
			{
				if (ucl_object_tostring_safe(cur, &data)) {
					if (!rspamd_rcl_add_lua_plugins_path(section->top,
														 cfg,
														 data,
														 TRUE,
														 err)) {
						return FALSE;
					}
				}
			}
		}
		else {
			g_set_error(err,
						CFG_RCL_ERROR,
						EINVAL,
						"path attribute is missing");

			return FALSE;
		}

		val = ucl_object_lookup(obj, "fallback_path");

		if (val) {
			const auto *cur = val;
			LL_FOREACH(val, cur)
			{
				if (ucl_object_tostring_safe(cur, &data)) {
					if (!rspamd_rcl_add_lua_plugins_path(section->top,
														 cfg,
														 data,
														 FALSE,
														 err)) {

						return FALSE;
					}
				}
			}
		}

		val = ucl_object_lookup(obj, "try_path");

		if (val) {
			const auto *cur = val;
			LL_FOREACH(val, cur)
			{
				if (ucl_object_tostring_safe(cur, &data)) {
					if (!rspamd_rcl_add_lua_plugins_path(section->top,
														 cfg,
														 data,
														 FALSE,
														 err)) {

						return FALSE;
					}
				}
			}
		}
	}
	else if (ucl_object_tostring_safe(obj, &data)) {
		if (!rspamd_rcl_add_lua_plugins_path(section->top, cfg, data, TRUE, err)) {
			return FALSE;
		}
	}
	else {
		g_set_error(err,
					CFG_RCL_ERROR,
					EINVAL,
					"module parameter has wrong type (must be an object or a string)");
		return FALSE;
	}

	return TRUE;
}

struct statfile_parser_data {
	struct rspamd_config *cfg;
	struct rspamd_classifier_config *ccf;
};

static gboolean
rspamd_rcl_statfile_handler(rspamd_mempool_t *pool, const ucl_object_t *obj,
							const gchar *key, gpointer ud,
							struct rspamd_rcl_section *section, GError **err)
{
	auto *stud = (struct statfile_parser_data *) ud;
	GList *labels;

	g_assert(key != nullptr);

	auto *cfg = stud->cfg;
	auto *ccf = stud->ccf;

	auto *st = rspamd_config_new_statfile(cfg, nullptr);
	st->symbol = rspamd_mempool_strdup(cfg->cfg_pool, key);

	if (rspamd_rcl_section_parse_defaults(cfg, *section, pool, obj, st, err)) {
		ccf->statfiles = rspamd_mempool_glist_prepend(pool, ccf->statfiles, st);

		if (st->label != nullptr) {
			labels = (GList *) g_hash_table_lookup(ccf->labels, st->label);
			if (labels != nullptr) {
				/* Must use append to preserve the head stored in the hash table */
				labels = g_list_append(labels, st);
			}
			else {
				g_hash_table_insert(ccf->labels, st->label,
									g_list_prepend(nullptr, st));
			}
		}

		if (st->symbol != nullptr) {
			g_hash_table_insert(cfg->classifiers_symbols, st->symbol, st);
		}
		else {
			g_set_error(err,
						CFG_RCL_ERROR,
						EINVAL,
						"statfile must have a symbol defined");
			return FALSE;
		}

		st->opts = (ucl_object_t *) obj;
		st->clcf = ccf;

		const auto *val = ucl_object_lookup(obj, "spam");
		if (val == nullptr) {
			msg_info_config(
				"statfile %s has no explicit 'spam' setting, trying to guess by symbol",
				st->symbol);
			if (rspamd_substring_search_caseless(st->symbol,
												 strlen(st->symbol), "spam", 4) != -1) {
				st->is_spam = TRUE;
			}
			else if (rspamd_substring_search_caseless(st->symbol,
													  strlen(st->symbol), "ham", 3) != -1) {
				st->is_spam = FALSE;
			}
			else {
				g_set_error(err,
							CFG_RCL_ERROR,
							EINVAL,
							"cannot guess spam setting from %s",
							st->symbol);
				return FALSE;
			}
			msg_info_config("guessed that statfile with symbol %s is %s",
							st->symbol,
							st->is_spam ? "spam" : "ham");
		}
		return TRUE;
	}

	return FALSE;
}

static gboolean
rspamd_rcl_classifier_handler(rspamd_mempool_t *pool,
							  const ucl_object_t *obj,
							  const gchar *key,
							  gpointer ud,
							  struct rspamd_rcl_section *section,
							  GError **err)
{
	auto *cfg = static_cast<rspamd_config *>(ud);

	g_assert(key != nullptr);
	auto *ccf = rspamd_config_new_classifier(cfg, nullptr);
	auto *tkcf = (rspamd_tokenizer_config *) nullptr;

	ccf->classifier = rspamd_mempool_strdup(cfg->cfg_pool, key);

	if (rspamd_rcl_section_parse_defaults(cfg, *section, cfg->cfg_pool, obj,
										  ccf, err)) {

		auto stat_section = rspamd::find_map(section->subsections, "statfile");

		if (ccf->classifier == nullptr) {
			ccf->classifier = rspamd_mempool_strdup(cfg->cfg_pool, "bayes");
		}

		if (ccf->name == nullptr) {
			ccf->name = ccf->classifier;
		}

		auto it = ucl_object_iterate_new(obj);
		const auto *val = obj;
		auto res = TRUE;

		while ((val = ucl_object_iterate_safe(it, true)) != nullptr && res) {
			const auto *st_key = ucl_object_key(val);

			if (st_key != nullptr) {
				if (g_ascii_strcasecmp(st_key, "statfile") == 0) {
					const auto *cur = val;
					LL_FOREACH(val, cur)
					{
						struct statfile_parser_data stud = {.cfg = cfg, .ccf = ccf};
						res = rspamd_rcl_process_section(cfg, *stat_section.value().get(), &stud,
														 cur, cfg->cfg_pool, err);

						if (!res) {
							ucl_object_iterate_free(it);

							return FALSE;
						}
					}
				}
				else if (g_ascii_strcasecmp(st_key, "tokenizer") == 0) {
					tkcf = rspamd_mempool_alloc0_type(cfg->cfg_pool, rspamd_tokenizer_config);

					if (ucl_object_type(val) == UCL_STRING) {
						tkcf->name = ucl_object_tostring(val);
					}
					else if (ucl_object_type(val) == UCL_OBJECT) {
						const auto *cur = ucl_object_lookup(val, "name");
						if (cur != nullptr) {
							tkcf->name = ucl_object_tostring(cur);
							tkcf->opts = val;
						}
						else {
							cur = ucl_object_lookup(val, "type");
							if (cur != nullptr) {
								tkcf->name = ucl_object_tostring(cur);
								tkcf->opts = val;
							}
						}
					}
				}
			}
		}

		ucl_object_iterate_free(it);
	}
	else {
		msg_err_config("fatal configuration error, cannot parse statfile definition");
	}

	if (tkcf == nullptr) {
		tkcf = rspamd_mempool_alloc0_type(cfg->cfg_pool, rspamd_tokenizer_config);
		tkcf->name = nullptr;
	}

	ccf->tokenizer = tkcf;

	/* Handle lua conditions */
	const auto *val = ucl_object_lookup_any(obj, "learn_condition", nullptr);

	if (val) {
		const auto *cur = val;
		LL_FOREACH(val, cur)
		{
			if (ucl_object_type(cur) == UCL_STRING) {
				const gchar *lua_script;
				gsize slen;
				gint ref_idx;

				lua_script = ucl_object_tolstring(cur, &slen);
				ref_idx = rspamd_lua_function_ref_from_str(RSPAMD_LUA_CFG_STATE(cfg),
														   lua_script, slen, "learn_condition", err);

				if (ref_idx == LUA_NOREF) {
					return FALSE;
				}

				rspamd_lua_add_ref_dtor(RSPAMD_LUA_CFG_STATE(cfg), cfg->cfg_pool, ref_idx);
				ccf->learn_conditions = rspamd_mempool_glist_append(
					cfg->cfg_pool,
					ccf->learn_conditions,
					GINT_TO_POINTER(ref_idx));
			}
		}
	}

	val = ucl_object_lookup_any(obj, "classify_condition", nullptr);

	if (val) {
		const auto *cur = val;
		LL_FOREACH(val, cur)
		{
			if (ucl_object_type(cur) == UCL_STRING) {
				const gchar *lua_script;
				gsize slen;
				gint ref_idx;

				lua_script = ucl_object_tolstring(cur, &slen);
				ref_idx = rspamd_lua_function_ref_from_str(RSPAMD_LUA_CFG_STATE(cfg),
														   lua_script, slen, "classify_condition", err);

				if (ref_idx == LUA_NOREF) {
					return FALSE;
				}

				rspamd_lua_add_ref_dtor(RSPAMD_LUA_CFG_STATE(cfg), cfg->cfg_pool, ref_idx);
				ccf->classify_conditions = rspamd_mempool_glist_append(
					cfg->cfg_pool,
					ccf->classify_conditions,
					GINT_TO_POINTER(ref_idx));
			}
		}
	}

	ccf->opts = (ucl_object_t *) obj;
	cfg->classifiers = g_list_prepend(cfg->classifiers, ccf);

	return TRUE;
}

static gboolean
rspamd_rcl_composite_handler(rspamd_mempool_t *pool,
							 const ucl_object_t *obj,
							 const gchar *key,
							 gpointer ud,
							 struct rspamd_rcl_section *section,
							 GError **err)
{
	auto *cfg = static_cast<rspamd_config *>(ud);
	void *composite;
	const gchar *composite_name;

	g_assert(key != nullptr);

	composite_name = key;

	const auto *val = ucl_object_lookup(obj, "enabled");
	if (val != nullptr && !ucl_object_toboolean(val)) {
		msg_info_config("composite %s is disabled", composite_name);
		return TRUE;
	}

	if ((composite = rspamd_composites_manager_add_from_ucl(cfg->composites_manager,
															composite_name, obj)) != nullptr) {
		rspamd_symcache_add_symbol(cfg->cache, composite_name, 0,
								   nullptr, composite, SYMBOL_TYPE_COMPOSITE, -1);
	}

	return composite != nullptr;
}

static gboolean
rspamd_rcl_composites_handler(rspamd_mempool_t *pool,
							  const ucl_object_t *obj,
							  const gchar *key,
							  gpointer ud,
							  struct rspamd_rcl_section *section,
							  GError **err)
{
	auto success = TRUE;

	auto it = ucl_object_iterate_new(obj);
	const auto *cur = obj;

	while ((cur = ucl_object_iterate_safe(it, true))) {
		success = rspamd_rcl_composite_handler(pool, cur,
											   ucl_object_key(cur), ud, section, err);
		if (!success) {
			break;
		}
	}

	ucl_object_iterate_free(it);

	return success;
}

static gboolean
rspamd_rcl_neighbours_handler(rspamd_mempool_t *pool,
							  const ucl_object_t *obj,
							  const gchar *key,
							  gpointer ud,
							  struct rspamd_rcl_section *section,
							  GError **err)
{
	auto *cfg = static_cast<rspamd_config *>(ud);
	auto has_port = FALSE, has_proto = FALSE;
	const gchar *p;

	if (key == nullptr) {
		g_set_error(err,
					CFG_RCL_ERROR,
					EINVAL,
					"missing name for neighbour");
		return FALSE;
	}

	const auto *hostval = ucl_object_lookup(obj, "host");

	if (hostval == nullptr || ucl_object_type(hostval) != UCL_STRING) {
		g_set_error(err,
					CFG_RCL_ERROR,
					EINVAL,
					"missing host for neighbour: %s", ucl_object_key(obj));
		return FALSE;
	}

	auto *neigh = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(neigh, ucl_object_copy(hostval), "host", 0, false);

	if ((p = strrchr(ucl_object_tostring(hostval), ':')) != nullptr) {
		if (g_ascii_isdigit(p[1])) {
			has_port = TRUE;
		}
	}

	if (strstr(ucl_object_tostring(hostval), "://") != nullptr) {
		has_proto = TRUE;
	}

	/* Now make url */
	auto urlstr = std::string{};
	const auto *pathval = ucl_object_lookup(obj, "path");

	if (!has_proto) {
		urlstr += "http://";
	}

	urlstr += ucl_object_tostring(hostval);

	if (!has_port) {
		urlstr += ":11334";
	}

	if (pathval == nullptr) {
		urlstr += "/";
	}
	else {
		urlstr += ucl_object_tostring(pathval);
	}

	ucl_object_insert_key(neigh,
						  ucl_object_fromlstring(urlstr.data(), urlstr.size()),
						  "url", 0, false);
	ucl_object_insert_key(cfg->neighbours, neigh, key, 0, true);

	return TRUE;
}


struct rspamd_rcl_section *
rspamd_rcl_add_section(struct rspamd_rcl_sections_map **top,
					   struct rspamd_rcl_section *parent_section,
					   const gchar *name, const gchar *key_attr, rspamd_rcl_handler_t handler,
					   enum ucl_type type, gboolean required, gboolean strict_type)
{
	return rspamd_rcl_add_section_doc(top, parent_section, name, key_attr, handler,
									  type, required, strict_type, nullptr, nullptr);
}

struct rspamd_rcl_section *
rspamd_rcl_add_section_doc(struct rspamd_rcl_sections_map **top,
						   struct rspamd_rcl_section *parent_section,
						   const gchar *name, const gchar *key_attr, rspamd_rcl_handler_t handler,
						   enum ucl_type type, gboolean required, gboolean strict_type,
						   ucl_object_t *doc_target,
						   const gchar *doc_string)
{
	if (top == nullptr) {
		g_error("invalid arguments to rspamd_rcl_add_section");
		return nullptr;
	}
	if (*top == nullptr) {
		*top = new rspamd_rcl_sections_map;
	}

	auto fill_section = [&](struct rspamd_rcl_section *section) {
		section->name = name;
		if (key_attr) {
			section->key_attr = std::string{key_attr};
		}
		section->handler = handler;
		section->type = type;
		section->strict_type = strict_type;

		if (doc_target == nullptr) {
			if (parent_section && parent_section->doc_ref) {
				section->doc_ref = ucl_object_ref(rspamd_rcl_add_doc_obj(parent_section->doc_ref,
																		 doc_string,
																		 name,
																		 type,
																		 nullptr,
																		 0,
																		 nullptr,
																		 0));
			}
			else {
				section->doc_ref = nullptr;
			}
		}
		else {
			section->doc_ref = ucl_object_ref(rspamd_rcl_add_doc_obj(doc_target,
																	 doc_string,
																	 name,
																	 type,
																	 nullptr,
																	 0,
																	 nullptr,
																	 0));
		}
		section->top = *top;
	};

	/* Select the appropriate container and insert section inside it */
	if (parent_section) {
		auto it = parent_section->subsections.insert(std::make_pair(std::string{name},
																	std::make_shared<rspamd_rcl_section>()));
		if (!it.second) {
			g_error("invalid arguments to rspamd_rcl_add_section");
			return nullptr;
		}

		fill_section(it.first->second.get());
		return it.first->second.get();
	}
	else {
		auto it = (*top)->sections.insert(std::make_pair(std::string{name},
														 std::make_shared<rspamd_rcl_section>()));
		if (!it.second) {
			g_error("invalid arguments to rspamd_rcl_add_section");
			return nullptr;
		}

		(*top)->sections_order.push_back(it.first->second);
		fill_section(it.first->second.get());
		return it.first->second.get();
	}
}

struct rspamd_rcl_default_handler_data *
rspamd_rcl_add_default_handler(struct rspamd_rcl_section *section,
							   const gchar *name,
							   rspamd_rcl_default_handler_t handler,
							   goffset offset,
							   gint flags,
							   const gchar *doc_string)
{
	auto it = section->default_parser.emplace(std::make_pair(std::string{name}, rspamd_rcl_default_handler_data{}));

	auto &nhandler = it.first->second;
	nhandler.key = name;
	nhandler.handler = handler;
	nhandler.pd.offset = offset;
	nhandler.pd.flags = flags;

	if (section->doc_ref != nullptr) {
		rspamd_rcl_add_doc_obj(section->doc_ref,
							   doc_string,
							   name,
							   UCL_NULL,
							   handler,
							   flags,
							   nullptr,
							   0);
	}

	return &nhandler;
}

struct rspamd_rcl_sections_map *
rspamd_rcl_config_init(struct rspamd_config *cfg, GHashTable *skip_sections)
{
	auto *top = new rspamd_rcl_sections_map;
	/*
	 * Important notice:
	 * the order of parsing is equal to order of this initialization, therefore
	 * it is possible to init some portions of config prior to others
	 */

	/**
	 * Logging section
	 */
	if (!(skip_sections && g_hash_table_lookup(skip_sections, "logging"))) {
		auto *sub = rspamd_rcl_add_section_doc(&top, nullptr,
											   "logging", nullptr,
											   rspamd_rcl_logging_handler,
											   UCL_OBJECT,
											   FALSE,
											   TRUE,
											   cfg->doc_strings,
											   "Configure rspamd logging");
		/* Default handlers */
		rspamd_rcl_add_default_handler(sub,
									   "log_buffer",
									   rspamd_rcl_parse_struct_integer,
									   G_STRUCT_OFFSET(struct rspamd_config, log_buf_size),
									   RSPAMD_CL_FLAG_INT_32,
									   "Size of log buffer in bytes (for file logging)");
		rspamd_rcl_add_default_handler(sub,
									   "log_urls",
									   rspamd_rcl_parse_struct_boolean,
									   G_STRUCT_OFFSET(struct rspamd_config, log_urls),
									   0,
									   "Write each URL found in a message to the log file");
		rspamd_rcl_add_default_handler(sub,
									   "debug_ip",
									   rspamd_rcl_parse_struct_ucl,
									   G_STRUCT_OFFSET(struct rspamd_config, debug_ip_map),
									   0,
									   "Enable debugging log for the specified IP addresses");
		rspamd_rcl_add_default_handler(sub,
									   "debug_modules",
									   rspamd_rcl_parse_struct_string_list,
									   G_STRUCT_OFFSET(struct rspamd_config, debug_modules),
									   RSPAMD_CL_FLAG_STRING_LIST_HASH,
									   "Enable debugging for the specified modules");
		rspamd_rcl_add_default_handler(sub,
									   "log_format",
									   rspamd_rcl_parse_struct_string,
									   G_STRUCT_OFFSET(struct rspamd_config, log_format_str),
									   0,
									   "Specify format string for the task logging output "
									   "(https://rspamd.com/doc/configuration/logging.html "
									   "for details)");
		rspamd_rcl_add_default_handler(sub,
									   "encryption_key",
									   rspamd_rcl_parse_struct_pubkey,
									   G_STRUCT_OFFSET(struct rspamd_config, log_encryption_key),
									   0,
									   "Encrypt sensitive information in logs using this pubkey");
		rspamd_rcl_add_default_handler(sub,
									   "error_elts",
									   rspamd_rcl_parse_struct_integer,
									   G_STRUCT_OFFSET(struct rspamd_config, log_error_elts),
									   RSPAMD_CL_FLAG_UINT,
									   "Size of circular buffer for last errors (10 by default)");
		rspamd_rcl_add_default_handler(sub,
									   "error_maxlen",
									   rspamd_rcl_parse_struct_integer,
									   G_STRUCT_OFFSET(struct rspamd_config, log_error_elt_maxlen),
									   RSPAMD_CL_FLAG_UINT,
									   "Size of each element in error log buffer (1000 by default)");
		rspamd_rcl_add_default_handler(sub,
									   "task_max_elts",
									   rspamd_rcl_parse_struct_integer,
									   G_STRUCT_OFFSET(struct rspamd_config, log_task_max_elts),
									   RSPAMD_CL_FLAG_UINT,
									   "Maximum number of elements in task log entry (7 by default)");

		/* Documentation only options, handled in log_handler to map flags */
		rspamd_rcl_add_doc_by_path(cfg,
								   "logging",
								   "Enable colored output (for console logging)",
								   "log_color",
								   UCL_BOOLEAN,
								   nullptr,
								   0,
								   nullptr,
								   0);
		rspamd_rcl_add_doc_by_path(cfg,
								   "logging",
								   "Enable severity logging output (e.g. [error] or [warning])",
								   "log_severity",
								   UCL_BOOLEAN,
								   nullptr,
								   0,
								   nullptr,
								   0);
		rspamd_rcl_add_doc_by_path(cfg,
								   "logging",
								   "Enable systemd compatible logging",
								   "systemd",
								   UCL_BOOLEAN,
								   nullptr,
								   0,
								   nullptr,
								   0);
		rspamd_rcl_add_doc_by_path(cfg,
								   "logging",
								   "Write statistics of regexp processing to log (useful for hyperscan)",
								   "log_re_cache",
								   UCL_BOOLEAN,
								   nullptr,
								   0,
								   nullptr,
								   0);
		rspamd_rcl_add_doc_by_path(cfg,
								   "logging",
								   "Use microseconds resolution for timestamps",
								   "log_usec",
								   UCL_BOOLEAN,
								   nullptr,
								   0,
								   nullptr,
								   0);
	}
	if (!(skip_sections && g_hash_table_lookup(skip_sections, "options"))) {
		/**
		 * Options section
		 */
		auto *sub = rspamd_rcl_add_section_doc(&top, nullptr,
											   "options", nullptr,
											   rspamd_rcl_options_handler,
											   UCL_OBJECT,
											   FALSE,
											   TRUE,
											   cfg->doc_strings,
											   "Global rspamd options");
		rspamd_rcl_add_default_handler(sub,
									   "cache_file",
									   rspamd_rcl_parse_struct_string,
									   G_STRUCT_OFFSET(struct rspamd_config, cache_filename),
									   RSPAMD_CL_FLAG_STRING_PATH,
									   "Path to the cache file");
		rspamd_rcl_add_default_handler(sub,
									   "cache_reload",
									   rspamd_rcl_parse_struct_time,
									   G_STRUCT_OFFSET(struct rspamd_config, cache_reload_time),
									   RSPAMD_CL_FLAG_TIME_FLOAT,
									   "How often cache reload should be performed");

		/* Old DNS configuration */
		rspamd_rcl_add_default_handler(sub,
									   "dns_nameserver",
									   rspamd_rcl_parse_struct_ucl,
									   G_STRUCT_OFFSET(struct rspamd_config, nameservers),
									   0,
									   "Legacy option for DNS servers used");
		rspamd_rcl_add_default_handler(sub,
									   "dns_timeout",
									   rspamd_rcl_parse_struct_time,
									   G_STRUCT_OFFSET(struct rspamd_config, dns_timeout),
									   RSPAMD_CL_FLAG_TIME_FLOAT,
									   "Legacy option for DNS request timeout");
		rspamd_rcl_add_default_handler(sub,
									   "dns_retransmits",
									   rspamd_rcl_parse_struct_integer,
									   G_STRUCT_OFFSET(struct rspamd_config, dns_retransmits),
									   RSPAMD_CL_FLAG_INT_32,
									   "Legacy option for DNS retransmits count");
		rspamd_rcl_add_default_handler(sub,
									   "dns_sockets",
									   rspamd_rcl_parse_struct_integer,
									   G_STRUCT_OFFSET(struct rspamd_config, dns_io_per_server),
									   RSPAMD_CL_FLAG_INT_32,
									   "Legacy option for DNS sockets per server count");
		rspamd_rcl_add_default_handler(sub,
									   "dns_max_requests",
									   rspamd_rcl_parse_struct_integer,
									   G_STRUCT_OFFSET(struct rspamd_config, dns_max_requests),
									   RSPAMD_CL_FLAG_INT_32,
									   "Maximum DNS requests per task (default: 64)");
		rspamd_rcl_add_default_handler(sub,
									   "control_socket",
									   rspamd_rcl_parse_struct_string,
									   G_STRUCT_OFFSET(struct rspamd_config, control_socket_path),
									   0,
									   "Path to the control socket");
		rspamd_rcl_add_default_handler(sub,
									   "explicit_modules",
									   rspamd_rcl_parse_struct_string_list,
									   G_STRUCT_OFFSET(struct rspamd_config, explicit_modules),
									   RSPAMD_CL_FLAG_STRING_LIST_HASH,
									   "Always load these modules even if they are not configured explicitly");
		rspamd_rcl_add_default_handler(sub,
									   "allow_raw_input",
									   rspamd_rcl_parse_struct_boolean,
									   G_STRUCT_OFFSET(struct rspamd_config, allow_raw_input),
									   0,
									   "Allow non MIME input for rspamd");
		rspamd_rcl_add_default_handler(sub,
									   "one_shot",
									   rspamd_rcl_parse_struct_boolean,
									   G_STRUCT_OFFSET(struct rspamd_config, one_shot_mode),
									   0,
									   "Add all symbols only once per message");
		rspamd_rcl_add_default_handler(sub,
									   "check_attachements",
									   rspamd_rcl_parse_struct_boolean,
									   G_STRUCT_OFFSET(struct rspamd_config, check_text_attachements),
									   0,
									   "Treat text attachments as normal text parts");
		rspamd_rcl_add_default_handler(sub,
									   "tempdir",
									   rspamd_rcl_parse_struct_string,
									   G_STRUCT_OFFSET(struct rspamd_config, temp_dir),
									   RSPAMD_CL_FLAG_STRING_PATH,
									   "Directory for temporary files");
		rspamd_rcl_add_default_handler(sub,
									   "pidfile",
									   rspamd_rcl_parse_struct_string,
									   G_STRUCT_OFFSET(struct rspamd_config, pid_file),
									   RSPAMD_CL_FLAG_STRING_PATH,
									   "Path to the pid file");
		rspamd_rcl_add_default_handler(sub,
									   "filters",
									   rspamd_rcl_parse_struct_string_list,
									   G_STRUCT_OFFSET(struct rspamd_config, filters),
									   0,
									   "List of internal filters enabled");
		rspamd_rcl_add_default_handler(sub,
									   "map_watch_interval",
									   rspamd_rcl_parse_struct_time,
									   G_STRUCT_OFFSET(struct rspamd_config, map_timeout),
									   RSPAMD_CL_FLAG_TIME_FLOAT,
									   "Interval for checking maps");
		rspamd_rcl_add_default_handler(sub,
									   "map_file_watch_multiplier",
									   rspamd_rcl_parse_struct_double,
									   G_STRUCT_OFFSET(struct rspamd_config, map_file_watch_multiplier),
									   0,
									   "Multiplier for map watch interval when map is file");
		rspamd_rcl_add_default_handler(sub,
									   "maps_cache_dir",
									   rspamd_rcl_parse_struct_string,
									   G_STRUCT_OFFSET(struct rspamd_config, maps_cache_dir),
									   0,
									   "Directory to save maps cached data (default: $DBDIR)");
		rspamd_rcl_add_default_handler(sub,
									   "monitoring_watch_interval",
									   rspamd_rcl_parse_struct_time,
									   G_STRUCT_OFFSET(struct rspamd_config, monitored_interval),
									   RSPAMD_CL_FLAG_TIME_FLOAT,
									   "Interval for checking monitored instances");
		rspamd_rcl_add_default_handler(sub,
									   "disable_monitoring",
									   rspamd_rcl_parse_struct_boolean,
									   G_STRUCT_OFFSET(struct rspamd_config, disable_monitored),
									   0,
									   "Disable monitoring completely");
		rspamd_rcl_add_default_handler(sub,
									   "fips_mode",
									   rspamd_rcl_parse_struct_boolean,
									   G_STRUCT_OFFSET(struct rspamd_config, fips_mode),
									   0,
									   "Enable FIPS 140-2 mode in OpenSSL");
		rspamd_rcl_add_default_handler(sub,
									   "dynamic_conf",
									   rspamd_rcl_parse_struct_string,
									   G_STRUCT_OFFSET(struct rspamd_config, dynamic_conf),
									   0,
									   "Path to the dynamic configuration");
		rspamd_rcl_add_default_handler(sub,
									   "rrd",
									   rspamd_rcl_parse_struct_string,
									   G_STRUCT_OFFSET(struct rspamd_config, rrd_file),
									   RSPAMD_CL_FLAG_STRING_PATH,
									   "Path to RRD file");
		rspamd_rcl_add_default_handler(sub,
									   "stats_file",
									   rspamd_rcl_parse_struct_string,
									   G_STRUCT_OFFSET(struct rspamd_config, stats_file),
									   RSPAMD_CL_FLAG_STRING_PATH,
									   "Path to stats file");
		rspamd_rcl_add_default_handler(sub,
									   "history_file",
									   rspamd_rcl_parse_struct_string,
									   G_STRUCT_OFFSET(struct rspamd_config, history_file),
									   RSPAMD_CL_FLAG_STRING_PATH,
									   "Path to history file");
		rspamd_rcl_add_default_handler(sub,
									   "check_all_filters",
									   rspamd_rcl_parse_struct_boolean,
									   G_STRUCT_OFFSET(struct rspamd_config, check_all_filters),
									   0,
									   "Always check all filters");
		rspamd_rcl_add_default_handler(sub,
									   "public_groups_only",
									   rspamd_rcl_parse_struct_boolean,
									   G_STRUCT_OFFSET(struct rspamd_config, public_groups_only),
									   0,
									   "Output merely public groups everywhere");
		rspamd_rcl_add_default_handler(sub,
									   "enable_css_parser",
									   rspamd_rcl_parse_struct_boolean,
									   G_STRUCT_OFFSET(struct rspamd_config, enable_css_parser),
									   0,
									   "Enable CSS parser (experimental)");
		rspamd_rcl_add_default_handler(sub,
									   "enable_experimental",
									   rspamd_rcl_parse_struct_boolean,
									   G_STRUCT_OFFSET(struct rspamd_config, enable_experimental),
									   0,
									   "Enable experimental plugins");
		rspamd_rcl_add_default_handler(sub,
									   "disable_pcre_jit",
									   rspamd_rcl_parse_struct_boolean,
									   G_STRUCT_OFFSET(struct rspamd_config, disable_pcre_jit),
									   0,
									   "Disable PCRE JIT");
		rspamd_rcl_add_default_handler(sub,
									   "min_word_len",
									   rspamd_rcl_parse_struct_integer,
									   G_STRUCT_OFFSET(struct rspamd_config, min_word_len),
									   RSPAMD_CL_FLAG_UINT,
									   "Minimum length of the word to be considered in statistics/fuzzy");
		rspamd_rcl_add_default_handler(sub,
									   "max_word_len",
									   rspamd_rcl_parse_struct_integer,
									   G_STRUCT_OFFSET(struct rspamd_config, max_word_len),
									   RSPAMD_CL_FLAG_UINT,
									   "Maximum length of the word to be considered in statistics/fuzzy");
		rspamd_rcl_add_default_handler(sub,
									   "max_html_len",
									   rspamd_rcl_parse_struct_integer,
									   G_STRUCT_OFFSET(struct rspamd_config, max_word_len),
									   RSPAMD_CL_FLAG_INT_SIZE,
									   "Maximum length of the html part to be parsed");
		rspamd_rcl_add_default_handler(sub,
									   "words_decay",
									   rspamd_rcl_parse_struct_integer,
									   G_STRUCT_OFFSET(struct rspamd_config, words_decay),
									   RSPAMD_CL_FLAG_UINT,
									   "Start skipping words at this amount");
		rspamd_rcl_add_default_handler(sub,
									   "url_tld",
									   rspamd_rcl_parse_struct_string,
									   G_STRUCT_OFFSET(struct rspamd_config, tld_file),
									   RSPAMD_CL_FLAG_STRING_PATH,
									   "Path to the TLD file for urls detector");
		rspamd_rcl_add_default_handler(sub,
									   "tld",
									   rspamd_rcl_parse_struct_string,
									   G_STRUCT_OFFSET(struct rspamd_config, tld_file),
									   RSPAMD_CL_FLAG_STRING_PATH,
									   "Path to the TLD file for urls detector");
		rspamd_rcl_add_default_handler(sub,
									   "hs_cache_dir",
									   rspamd_rcl_parse_struct_string,
									   G_STRUCT_OFFSET(struct rspamd_config, hs_cache_dir),
									   RSPAMD_CL_FLAG_STRING_PATH,
									   "Path directory where rspamd would save hyperscan cache");
		rspamd_rcl_add_default_handler(sub,
									   "history_rows",
									   rspamd_rcl_parse_struct_integer,
									   G_STRUCT_OFFSET(struct rspamd_config, history_rows),
									   RSPAMD_CL_FLAG_UINT,
									   "Number of records in the history file");
		rspamd_rcl_add_default_handler(sub,
									   "disable_hyperscan",
									   rspamd_rcl_parse_struct_boolean,
									   G_STRUCT_OFFSET(struct rspamd_config, disable_hyperscan),
									   0,
									   "Disable hyperscan optimizations for regular expressions");
		rspamd_rcl_add_default_handler(sub,
									   "vectorized_hyperscan",
									   rspamd_rcl_parse_struct_boolean,
									   G_STRUCT_OFFSET(struct rspamd_config, vectorized_hyperscan),
									   0,
									   "Use hyperscan in vectorized mode (obsoleted, do not use)");
		rspamd_rcl_add_default_handler(sub,
									   "cores_dir",
									   rspamd_rcl_parse_struct_string,
									   G_STRUCT_OFFSET(struct rspamd_config, cores_dir),
									   RSPAMD_CL_FLAG_STRING_PATH,
									   "Path to the directory where rspamd core files are intended to be dumped");
		rspamd_rcl_add_default_handler(sub,
									   "max_cores_size",
									   rspamd_rcl_parse_struct_integer,
									   G_STRUCT_OFFSET(struct rspamd_config, max_cores_size),
									   RSPAMD_CL_FLAG_INT_SIZE,
									   "Limit of joint size of all files in `cores_dir`");
		rspamd_rcl_add_default_handler(sub,
									   "max_cores_count",
									   rspamd_rcl_parse_struct_integer,
									   G_STRUCT_OFFSET(struct rspamd_config, max_cores_count),
									   RSPAMD_CL_FLAG_INT_SIZE,
									   "Limit of files count in `cores_dir`");
		rspamd_rcl_add_default_handler(sub,
									   "local_addrs",
									   rspamd_rcl_parse_struct_ucl,
									   G_STRUCT_OFFSET(struct rspamd_config, local_addrs),
									   0,
									   "Use the specified addresses as local ones");
		rspamd_rcl_add_default_handler(sub,
									   "local_networks",
									   rspamd_rcl_parse_struct_ucl,
									   G_STRUCT_OFFSET(struct rspamd_config, local_addrs),
									   0,
									   "Use the specified addresses as local ones (alias for `local_addrs`)");
		rspamd_rcl_add_default_handler(sub,
									   "trusted_keys",
									   rspamd_rcl_parse_struct_string_list,
									   G_STRUCT_OFFSET(struct rspamd_config, trusted_keys),
									   RSPAMD_CL_FLAG_STRING_LIST_HASH,
									   "List of trusted public keys used for signatures in base32 encoding");
		rspamd_rcl_add_default_handler(sub,
									   "enable_shutdown_workaround",
									   rspamd_rcl_parse_struct_boolean,
									   G_STRUCT_OFFSET(struct rspamd_config, enable_shutdown_workaround),
									   0,
									   "Enable workaround for legacy clients");
		rspamd_rcl_add_default_handler(sub,
									   "ignore_received",
									   rspamd_rcl_parse_struct_boolean,
									   G_STRUCT_OFFSET(struct rspamd_config, ignore_received),
									   0,
									   "Ignore data from the first received header");
		rspamd_rcl_add_default_handler(sub,
									   "ssl_ca_path",
									   rspamd_rcl_parse_struct_string,
									   G_STRUCT_OFFSET(struct rspamd_config, ssl_ca_path),
									   RSPAMD_CL_FLAG_STRING_PATH,
									   "Path to ssl CA file");
		rspamd_rcl_add_default_handler(sub,
									   "ssl_ciphers",
									   rspamd_rcl_parse_struct_string,
									   G_STRUCT_OFFSET(struct rspamd_config, ssl_ciphers),
									   0,
									   "List of ssl ciphers (e.g. HIGH:!anullptr:!kRSA:!PSK:!SRP:!MD5:!RC4)");
		rspamd_rcl_add_default_handler(sub,
									   "max_message",
									   rspamd_rcl_parse_struct_integer,
									   G_STRUCT_OFFSET(struct rspamd_config, max_message),
									   RSPAMD_CL_FLAG_INT_SIZE,
									   "Maximum size of the message to be scanned (50Mb by default)");
		rspamd_rcl_add_default_handler(sub,
									   "max_pic",
									   rspamd_rcl_parse_struct_integer,
									   G_STRUCT_OFFSET(struct rspamd_config, max_pic_size),
									   RSPAMD_CL_FLAG_INT_SIZE,
									   "Maximum size of the picture to be normalized (1Mb by default)");
		rspamd_rcl_add_default_handler(sub,
									   "images_cache",
									   rspamd_rcl_parse_struct_integer,
									   G_STRUCT_OFFSET(struct rspamd_config, max_pic_size),
									   RSPAMD_CL_FLAG_INT_SIZE,
									   "Size of DCT data cache for images (256 elements by default)");
		rspamd_rcl_add_default_handler(sub,
									   "zstd_input_dictionary",
									   rspamd_rcl_parse_struct_string,
									   G_STRUCT_OFFSET(struct rspamd_config, zstd_input_dictionary),
									   RSPAMD_CL_FLAG_STRING_PATH,
									   "Dictionary for zstd inbound protocol compression");
		rspamd_rcl_add_default_handler(sub,
									   "zstd_output_dictionary",
									   rspamd_rcl_parse_struct_string,
									   G_STRUCT_OFFSET(struct rspamd_config, zstd_output_dictionary),
									   RSPAMD_CL_FLAG_STRING_PATH,
									   "Dictionary for outbound zstd compression");
		rspamd_rcl_add_default_handler(sub,
									   "compat_messages",
									   rspamd_rcl_parse_struct_boolean,
									   G_STRUCT_OFFSET(struct rspamd_config, compat_messages),
									   0,
									   "Use pre 1.4 style of messages in the protocol");
		rspamd_rcl_add_default_handler(sub,
									   "max_shots",
									   rspamd_rcl_parse_struct_integer,
									   G_STRUCT_OFFSET(struct rspamd_config, default_max_shots),
									   0,
									   "Maximum number of hits per a single symbol (default: 100)");
		rspamd_rcl_add_default_handler(sub,
									   "sessions_cache",
									   rspamd_rcl_parse_struct_boolean,
									   G_STRUCT_OFFSET(struct rspamd_config, enable_sessions_cache),
									   0,
									   "Enable sessions cache to debug dangling sessions");
		rspamd_rcl_add_default_handler(sub,
									   "max_sessions_cache",
									   rspamd_rcl_parse_struct_integer,
									   G_STRUCT_OFFSET(struct rspamd_config, max_sessions_cache),
									   0,
									   "Maximum number of sessions in cache before warning (default: 100)");
		rspamd_rcl_add_default_handler(sub,
									   "task_timeout",
									   rspamd_rcl_parse_struct_time,
									   G_STRUCT_OFFSET(struct rspamd_config, task_timeout),
									   RSPAMD_CL_FLAG_TIME_FLOAT,
									   "Maximum time for checking a message");
		rspamd_rcl_add_default_handler(sub,
									   "soft_reject_on_timeout",
									   rspamd_rcl_parse_struct_boolean,
									   G_STRUCT_OFFSET(struct rspamd_config, soft_reject_on_timeout),
									   0,
									   "Emit soft reject if task timeout takes place");
		rspamd_rcl_add_default_handler(sub,
									   "check_timeout",
									   rspamd_rcl_parse_struct_time,
									   G_STRUCT_OFFSET(struct rspamd_config, task_timeout),
									   RSPAMD_CL_FLAG_TIME_FLOAT,
									   "Maximum time for checking a message (alias for task_timeout)");
		rspamd_rcl_add_default_handler(sub,
									   "lua_gc_step",
									   rspamd_rcl_parse_struct_integer,
									   G_STRUCT_OFFSET(struct rspamd_config, lua_gc_step),
									   RSPAMD_CL_FLAG_UINT,
									   "Lua garbage-collector step (default: 200)");
		rspamd_rcl_add_default_handler(sub,
									   "lua_gc_pause",
									   rspamd_rcl_parse_struct_integer,
									   G_STRUCT_OFFSET(struct rspamd_config, lua_gc_pause),
									   RSPAMD_CL_FLAG_UINT,
									   "Lua garbage-collector pause (default: 200)");
		rspamd_rcl_add_default_handler(sub,
									   "full_gc_iters",
									   rspamd_rcl_parse_struct_integer,
									   G_STRUCT_OFFSET(struct rspamd_config, full_gc_iters),
									   RSPAMD_CL_FLAG_UINT,
									   "Task scanned before memory gc is performed (default: 0 - disabled)");
		rspamd_rcl_add_default_handler(sub,
									   "heartbeat_interval",
									   rspamd_rcl_parse_struct_time,
									   G_STRUCT_OFFSET(struct rspamd_config, heartbeat_interval),
									   RSPAMD_CL_FLAG_TIME_FLOAT,
									   "Time between workers heartbeats");
		rspamd_rcl_add_default_handler(sub,
									   "heartbeats_loss_max",
									   rspamd_rcl_parse_struct_integer,
									   G_STRUCT_OFFSET(struct rspamd_config, heartbeats_loss_max),
									   RSPAMD_CL_FLAG_INT_32,
									   "Maximum count of heartbeats to be lost before trying to "
									   "terminate a worker (default: 0 - disabled)");
		rspamd_rcl_add_default_handler(sub,
									   "max_lua_urls",
									   rspamd_rcl_parse_struct_integer,
									   G_STRUCT_OFFSET(struct rspamd_config, max_lua_urls),
									   RSPAMD_CL_FLAG_INT_32,
									   "Maximum count of URLs to pass to Lua to avoid DoS (default: 1024)");
		rspamd_rcl_add_default_handler(sub,
									   "max_urls",
									   rspamd_rcl_parse_struct_integer,
									   G_STRUCT_OFFSET(struct rspamd_config, max_urls),
									   RSPAMD_CL_FLAG_INT_32,
									   "Maximum count of URLs to process to avoid DoS (default: 10240)");
		rspamd_rcl_add_default_handler(sub,
									   "max_recipients",
									   rspamd_rcl_parse_struct_integer,
									   G_STRUCT_OFFSET(struct rspamd_config, max_recipients),
									   RSPAMD_CL_FLAG_INT_32,
									   "Maximum count of recipients to process to avoid DoS (default: 1024)");
		rspamd_rcl_add_default_handler(sub,
									   "max_blas_threads",
									   rspamd_rcl_parse_struct_integer,
									   G_STRUCT_OFFSET(struct rspamd_config, max_blas_threads),
									   RSPAMD_CL_FLAG_INT_32,
									   "Maximum number of Blas threads for learning neural networks (default: 1)");
		rspamd_rcl_add_default_handler(sub,
									   "max_opts_len",
									   rspamd_rcl_parse_struct_integer,
									   G_STRUCT_OFFSET(struct rspamd_config, max_opts_len),
									   RSPAMD_CL_FLAG_INT_32,
									   "Maximum size of all options for a single symbol (default: 4096)");
		rspamd_rcl_add_default_handler(sub,
									   "events_backend",
									   rspamd_rcl_parse_struct_string,
									   G_STRUCT_OFFSET(struct rspamd_config, events_backend),
									   0,
									   "Events backend to use: kqueue, epoll, select, poll or auto (default: auto)");

		rspamd_rcl_add_doc_by_path(cfg,
								   "options",
								   "Swtich mode of gtube patterns: disable, reject, all",
								   "gtube_patterns",
								   UCL_STRING,
								   nullptr,
								   0,
								   "reject",
								   0);

		/* Neighbours configuration */
		rspamd_rcl_add_section_doc(&top, sub, "neighbours", "name",
								   rspamd_rcl_neighbours_handler,
								   UCL_OBJECT, FALSE, TRUE,
								   cfg->doc_strings,
								   "List of members of Rspamd cluster");

		/* New DNS configuration */
		auto *ssub = rspamd_rcl_add_section_doc(&top, sub, "dns", nullptr, nullptr,
												UCL_OBJECT, FALSE, TRUE,
												cfg->doc_strings,
												"Options for DNS resolver");
		rspamd_rcl_add_default_handler(ssub,
									   "nameserver",
									   rspamd_rcl_parse_struct_ucl,
									   G_STRUCT_OFFSET(struct rspamd_config, nameservers),
									   0,
									   "List of DNS servers");
		rspamd_rcl_add_default_handler(ssub,
									   "server",
									   rspamd_rcl_parse_struct_ucl,
									   G_STRUCT_OFFSET(struct rspamd_config, nameservers),
									   0,
									   "List of DNS servers");
		rspamd_rcl_add_default_handler(ssub,
									   "timeout",
									   rspamd_rcl_parse_struct_time,
									   G_STRUCT_OFFSET(struct rspamd_config, dns_timeout),
									   RSPAMD_CL_FLAG_TIME_FLOAT,
									   "DNS request timeout");
		rspamd_rcl_add_default_handler(ssub,
									   "retransmits",
									   rspamd_rcl_parse_struct_integer,
									   G_STRUCT_OFFSET(struct rspamd_config, dns_retransmits),
									   RSPAMD_CL_FLAG_INT_32,
									   "DNS request retransmits");
		rspamd_rcl_add_default_handler(ssub,
									   "sockets",
									   rspamd_rcl_parse_struct_integer,
									   G_STRUCT_OFFSET(struct rspamd_config, dns_io_per_server),
									   RSPAMD_CL_FLAG_INT_32,
									   "Number of sockets per DNS server");
		rspamd_rcl_add_default_handler(ssub,
									   "connections",
									   rspamd_rcl_parse_struct_integer,
									   G_STRUCT_OFFSET(struct rspamd_config, dns_io_per_server),
									   RSPAMD_CL_FLAG_INT_32,
									   "Number of sockets per DNS server");
		rspamd_rcl_add_default_handler(ssub,
									   "enable_dnssec",
									   rspamd_rcl_parse_struct_boolean,
									   G_STRUCT_OFFSET(struct rspamd_config, enable_dnssec),
									   0,
									   "Enable DNSSEC support in Rspamd");


		/* New upstreams configuration */
		ssub = rspamd_rcl_add_section_doc(&top, sub, "upstream", nullptr, nullptr,
										  UCL_OBJECT, FALSE, TRUE,
										  cfg->doc_strings,
										  "Upstreams configuration parameters");
		rspamd_rcl_add_default_handler(ssub,
									   "max_errors",
									   rspamd_rcl_parse_struct_integer,
									   G_STRUCT_OFFSET(struct rspamd_config, upstream_max_errors),
									   RSPAMD_CL_FLAG_UINT,
									   "Maximum number of errors during `error_time` to consider upstream down");
		rspamd_rcl_add_default_handler(ssub,
									   "error_time",
									   rspamd_rcl_parse_struct_time,
									   G_STRUCT_OFFSET(struct rspamd_config, upstream_error_time),
									   RSPAMD_CL_FLAG_TIME_FLOAT,
									   "Time frame to check errors");
		rspamd_rcl_add_default_handler(ssub,
									   "revive_time",
									   rspamd_rcl_parse_struct_time,
									   G_STRUCT_OFFSET(struct rspamd_config, upstream_revive_time),
									   RSPAMD_CL_FLAG_TIME_FLOAT,
									   "Time before attempting to recover upstream after an error");
		rspamd_rcl_add_default_handler(ssub,
									   "lazy_resolve_time",
									   rspamd_rcl_parse_struct_time,
									   G_STRUCT_OFFSET(struct rspamd_config, upstream_lazy_resolve_time),
									   RSPAMD_CL_FLAG_TIME_FLOAT,
									   "Time to resolve upstreams addresses in lazy mode");
	}

	if (!(skip_sections && g_hash_table_lookup(skip_sections, "actions"))) {
		/**
		 * Symbols and actions sections
		 */
		auto *sub = rspamd_rcl_add_section_doc(&top, nullptr,
											   "actions", nullptr,
											   rspamd_rcl_actions_handler,
											   UCL_OBJECT,
											   FALSE,
											   TRUE,
											   cfg->doc_strings,
											   "Actions configuration");
		rspamd_rcl_add_default_handler(sub,
									   "unknown_weight",
									   rspamd_rcl_parse_struct_double,
									   G_STRUCT_OFFSET(struct rspamd_config, unknown_weight),
									   0,
									   "Accept unknown symbols with the specified weight");
		rspamd_rcl_add_default_handler(sub,
									   "grow_factor",
									   rspamd_rcl_parse_struct_double,
									   G_STRUCT_OFFSET(struct rspamd_config, grow_factor),
									   0,
									   "Multiply the subsequent symbols by this number "
									   "(does not affect symbols with score less or "
									   "equal to zero)");
		rspamd_rcl_add_default_handler(sub,
									   "subject",
									   rspamd_rcl_parse_struct_string,
									   G_STRUCT_OFFSET(struct rspamd_config, subject),
									   0,
									   "Rewrite subject with this value");
	}

	if (!(skip_sections && g_hash_table_lookup(skip_sections, "group"))) {
		auto *sub = rspamd_rcl_add_section_doc(&top, nullptr,
											   "group", "name",
											   rspamd_rcl_group_handler,
											   UCL_OBJECT,
											   FALSE,
											   TRUE,
											   cfg->doc_strings,
											   "Symbol groups configuration");
		rspamd_rcl_add_section_doc(&top, sub, "symbols", "name",
								   rspamd_rcl_symbol_handler,
								   UCL_OBJECT, FALSE, TRUE,
								   cfg->doc_strings,
								   "Symbols configuration");

		/* Group part */
		rspamd_rcl_add_default_handler(sub,
									   "max_score",
									   rspamd_rcl_parse_struct_double,
									   G_STRUCT_OFFSET(struct rspamd_symbols_group, max_score),
									   0,
									   "Maximum score that could be reached by this symbols group");
	}

	if (!(skip_sections && g_hash_table_lookup(skip_sections, "worker"))) {
		/**
		 * Worker section
		 */
		auto *sub = rspamd_rcl_add_section_doc(&top, nullptr, "worker", "type",
											   rspamd_rcl_worker_handler,
											   UCL_OBJECT,
											   FALSE,
											   TRUE,
											   cfg->doc_strings,
											   "Workers common options");
		rspamd_rcl_add_default_handler(sub,
									   "count",
									   rspamd_rcl_parse_struct_integer,
									   G_STRUCT_OFFSET(struct rspamd_worker_conf, count),
									   RSPAMD_CL_FLAG_INT_16,
									   "Number of workers to spawn");
		rspamd_rcl_add_default_handler(sub,
									   "max_files",
									   rspamd_rcl_parse_struct_integer,
									   G_STRUCT_OFFSET(struct rspamd_worker_conf, rlimit_nofile),
									   RSPAMD_CL_FLAG_INT_64,
									   "Maximum number of opened files per worker");
		rspamd_rcl_add_default_handler(sub,
									   "max_core",
									   rspamd_rcl_parse_struct_integer,
									   G_STRUCT_OFFSET(struct rspamd_worker_conf, rlimit_maxcore),
									   RSPAMD_CL_FLAG_INT_64,
									   "Max size of core file in bytes");
		rspamd_rcl_add_default_handler(sub,
									   "enabled",
									   rspamd_rcl_parse_struct_boolean,
									   G_STRUCT_OFFSET(struct rspamd_worker_conf, enabled),
									   0,
									   "Enable or disable a worker (true by default)");
	}

	if (!(skip_sections && g_hash_table_lookup(skip_sections, "modules"))) {
		/**
		 * Modules handler
		 */
		rspamd_rcl_add_section_doc(&top, nullptr,
								   "modules", nullptr,
								   rspamd_rcl_modules_handler,
								   UCL_OBJECT,
								   FALSE,
								   FALSE,
								   cfg->doc_strings,
								   "Lua plugins to load");
	}

	if (!(skip_sections && g_hash_table_lookup(skip_sections, "classifier"))) {
		/**
		 * Classifiers handler
		 */
		auto *sub = rspamd_rcl_add_section_doc(&top, nullptr,
											   "classifier", "type",
											   rspamd_rcl_classifier_handler,
											   UCL_OBJECT,
											   FALSE,
											   TRUE,
											   cfg->doc_strings,
											   "CLassifier options");
		/* Default classifier is 'bayes' for now */
		sub->default_key = "bayes";

		rspamd_rcl_add_default_handler(sub,
									   "min_tokens",
									   rspamd_rcl_parse_struct_integer,
									   G_STRUCT_OFFSET(struct rspamd_classifier_config, min_tokens),
									   RSPAMD_CL_FLAG_INT_32,
									   "Minimum count of tokens (words) to be considered for statistics");
		rspamd_rcl_add_default_handler(sub,
									   "min_token_hits",
									   rspamd_rcl_parse_struct_integer,
									   G_STRUCT_OFFSET(struct rspamd_classifier_config, min_token_hits),
									   RSPAMD_CL_FLAG_UINT,
									   "Minimum number of hits for a token to be considered");
		rspamd_rcl_add_default_handler(sub,
									   "min_prob_strength",
									   rspamd_rcl_parse_struct_double,
									   G_STRUCT_OFFSET(struct rspamd_classifier_config, min_token_hits),
									   0,
									   "Use only tokens with probability in [0.5 - MPS, 0.5 + MPS]");
		rspamd_rcl_add_default_handler(sub,
									   "max_tokens",
									   rspamd_rcl_parse_struct_integer,
									   G_STRUCT_OFFSET(struct rspamd_classifier_config, max_tokens),
									   RSPAMD_CL_FLAG_INT_32,
									   "Maximum count of tokens (words) to be considered for statistics");
		rspamd_rcl_add_default_handler(sub,
									   "min_learns",
									   rspamd_rcl_parse_struct_integer,
									   G_STRUCT_OFFSET(struct rspamd_classifier_config, min_learns),
									   RSPAMD_CL_FLAG_UINT,
									   "Minimum number of learns for each statfile to use this classifier");
		rspamd_rcl_add_default_handler(sub,
									   "backend",
									   rspamd_rcl_parse_struct_string,
									   G_STRUCT_OFFSET(struct rspamd_classifier_config, backend),
									   0,
									   "Statfiles engine");
		rspamd_rcl_add_default_handler(sub,
									   "name",
									   rspamd_rcl_parse_struct_string,
									   G_STRUCT_OFFSET(struct rspamd_classifier_config, name),
									   0,
									   "Name of classifier");

		/*
		 * Statfile defaults
		 */
		auto *ssub = rspamd_rcl_add_section_doc(&top, sub,
												"statfile", "symbol",
												rspamd_rcl_statfile_handler,
												UCL_OBJECT,
												TRUE,
												TRUE,
												sub->doc_ref,
												"Statfiles options");
		rspamd_rcl_add_default_handler(ssub,
									   "label",
									   rspamd_rcl_parse_struct_string,
									   G_STRUCT_OFFSET(struct rspamd_statfile_config, label),
									   0,
									   "Statfile unique label");
		rspamd_rcl_add_default_handler(ssub,
									   "spam",
									   rspamd_rcl_parse_struct_boolean,
									   G_STRUCT_OFFSET(struct rspamd_statfile_config, is_spam),
									   0,
									   "Sets if this statfile contains spam samples");
	}

	if (!(skip_sections && g_hash_table_lookup(skip_sections, "composite"))) {
		/**
		 * Composites handlers
		 */
		rspamd_rcl_add_section_doc(&top, nullptr,
								   "composite", "name",
								   rspamd_rcl_composite_handler,
								   UCL_OBJECT,
								   FALSE,
								   TRUE,
								   cfg->doc_strings,
								   "Rspamd composite symbols");
		rspamd_rcl_add_section_doc(&top, nullptr,
								   "composites", nullptr,
								   rspamd_rcl_composites_handler,
								   UCL_OBJECT,
								   FALSE,
								   TRUE,
								   cfg->doc_strings,
								   "Rspamd composite symbols");
	}

	if (!(skip_sections && g_hash_table_lookup(skip_sections, "lua"))) {
		/**
		 * Lua handler
		 */
		rspamd_rcl_add_section_doc(&top, nullptr,
								   "lua", nullptr,
								   rspamd_rcl_lua_handler,
								   UCL_STRING,
								   FALSE,
								   TRUE,
								   cfg->doc_strings,
								   "Lua files to load");
	}

	cfg->rcl_top_section = top;

	return top;
}

static bool
rspamd_rcl_process_section(struct rspamd_config *cfg,
						   const struct rspamd_rcl_section &sec,
						   gpointer ptr, const ucl_object_t *obj, rspamd_mempool_t *pool,
						   GError **err)
{
	ucl_object_iter_t it;
	const ucl_object_t *cur;
	auto is_nested = true;
	const gchar *key = nullptr;

	if (sec.processed) {
		/* Section has been already processed */
		return TRUE;
	}

	g_assert(obj != nullptr);
	g_assert(sec.handler != nullptr);

	if (sec.key_attr) {
		it = ucl_object_iterate_new(obj);

		while ((cur = ucl_object_iterate_full(it, UCL_ITERATE_EXPLICIT)) != nullptr) {
			if (ucl_object_type(cur) != UCL_OBJECT) {
				is_nested = false;
				break;
			}
		}

		ucl_object_iterate_free(it);
	}
	else {
		is_nested = false;
	}

	if (is_nested) {
		/* Just reiterate on all subobjects */
		it = ucl_object_iterate_new(obj);

		while ((cur = ucl_object_iterate_full(it, UCL_ITERATE_EXPLICIT)) != nullptr) {
			if (!sec.handler(pool, cur, ucl_object_key(cur), ptr, const_cast<rspamd_rcl_section *>(&sec), err)) {
				ucl_object_iterate_free(it);

				return false;
			}
		}

		ucl_object_iterate_free(it);

		return true;
	}
	else {
		if (sec.key_attr) {
			/* First of all search for required attribute and use it as a key */
			cur = ucl_object_lookup(obj, sec.key_attr.value().c_str());

			if (cur == nullptr) {
				if (!sec.default_key) {
					g_set_error(err, CFG_RCL_ERROR, EINVAL, "required attribute "
															"'%s' is missing for section '%s', current key: %s",
								sec.key_attr.value().c_str(),
								sec.name.c_str(),
								ucl_object_key(obj));

					return false;
				}
				else {
					msg_info("using default key '%s' for mandatory field '%s' "
							 "for section '%s'",
							 sec.default_key.value().c_str(), sec.key_attr.value().c_str(),
							 sec.name.c_str());
					key = sec.default_key.value().c_str();
				}
			}
			else if (ucl_object_type(cur) != UCL_STRING) {
				g_set_error(err, CFG_RCL_ERROR, EINVAL, "required attribute %s"
														" is not a string for section %s",
							sec.key_attr.value().c_str(), sec.name.c_str());

				return false;
			}
			else {
				key = ucl_object_tostring(cur);
			}
		}
	}

	return sec.handler(pool, obj, key, ptr, const_cast<rspamd_rcl_section *>(&sec), err);
}

gboolean
rspamd_rcl_parse(struct rspamd_rcl_sections_map *top,
				 struct rspamd_config *cfg,
				 gpointer ptr, rspamd_mempool_t *pool,
				 const ucl_object_t *obj, GError **err)
{
	if (obj->type != UCL_OBJECT) {
		g_set_error(err,
					CFG_RCL_ERROR,
					EINVAL,
					"top configuration must be an object");
		return FALSE;
	}

	/* Iterate over known sections and ignore unknown ones */
	for (const auto &sec_ptr: top->sections_order) {
		if (sec_ptr->name == "*") {
			/* Default section handler */
			const auto *cur_obj = obj;
			LL_FOREACH(obj, cur_obj)
			{
				if (!top->sections.contains(ucl_object_key(cur_obj))) {
					if (sec_ptr->handler != nullptr) {
						if (!rspamd_rcl_process_section(cfg, *sec_ptr, ptr, cur_obj,
														pool, err)) {
							return FALSE;
						}
					}
					else {
						rspamd_rcl_section_parse_defaults(cfg,
														  *sec_ptr,
														  pool,
														  cur_obj,
														  ptr,
														  err);
					}
				}
			}
		}
		else {
			const auto *found = ucl_object_lookup(obj, sec_ptr->name.c_str());
			if (found == nullptr) {
				if (sec_ptr->required) {
					g_set_error(err, CFG_RCL_ERROR, ENOENT,
								"required section %s is missing", sec_ptr->name.c_str());
					return FALSE;
				}
			}
			else {
				/* Check type */
				if (sec_ptr->strict_type) {
					if (sec_ptr->type != found->type) {
						g_set_error(err, CFG_RCL_ERROR, EINVAL,
									"object in section %s has invalid type", sec_ptr->name.c_str());
						return FALSE;
					}
				}

				const auto *cur_obj = found;
				LL_FOREACH(found, cur_obj)
				{
					if (sec_ptr->handler != nullptr) {
						if (!rspamd_rcl_process_section(cfg, *sec_ptr, ptr, cur_obj,
														pool, err)) {
							return FALSE;
						}
					}
					else {
						rspamd_rcl_section_parse_defaults(cfg, *sec_ptr,
														  pool,
														  cur_obj,
														  ptr,
														  err);
					}
				}
			}
		}
		if (sec_ptr->fin) {
			sec_ptr->fin(pool, sec_ptr->fin_ud);
		}
	}

	return TRUE;
}

static bool
rspamd_rcl_section_parse_defaults(struct rspamd_config *cfg,
								  const struct rspamd_rcl_section &section,
								  rspamd_mempool_t *pool, const ucl_object_t *obj, gpointer ptr,
								  GError **err)
{

	if (obj->type != UCL_OBJECT) {
		g_set_error(err,
					CFG_RCL_ERROR,
					EINVAL,
					"default configuration must be an object for section %s "
					"(actual type is %s)",
					section.name.c_str(), ucl_object_type_to_string(ucl_object_type(obj)));
		return FALSE;
	}

	for (const auto &cur: section.default_parser) {
		const auto *found = ucl_object_lookup(obj, cur.first.c_str());
		if (found != nullptr) {
			auto new_pd = cur.second.pd;
			new_pd.user_struct = ptr;
			new_pd.cfg = cfg;
			const auto *cur_obj = found;

			LL_FOREACH(found, cur_obj)
			{
				if (!cur.second.handler(pool, cur_obj, &new_pd, const_cast<rspamd_rcl_section *>(&section), err)) {
					return FALSE;
				}

				if (!(new_pd.flags & RSPAMD_CL_FLAG_MULTIPLE)) {
					break;
				}
			}
		}
	}

	return TRUE;
}

gboolean
rspamd_rcl_parse_struct_string(rspamd_mempool_t *pool,
							   const ucl_object_t *obj,
							   gpointer ud,
							   struct rspamd_rcl_section *section,
							   GError **err)
{
	auto *pd = (struct rspamd_rcl_struct_parser *) ud;
	const gsize num_str_len = 32;

	auto target = (gchar **) (((gchar *) pd->user_struct) + pd->offset);
	switch (obj->type) {
	case UCL_STRING:
		*target =
			rspamd_mempool_strdup(pool, ucl_copy_value_trash(obj));
		break;
	case UCL_INT:
		*target = (gchar *) rspamd_mempool_alloc(pool, num_str_len);
		rspamd_snprintf(*target, num_str_len, "%L", obj->value.iv);
		break;
	case UCL_FLOAT:
		*target = (gchar *) rspamd_mempool_alloc(pool, num_str_len);
		rspamd_snprintf(*target, num_str_len, "%f", obj->value.dv);
		break;
	case UCL_BOOLEAN:
		*target = (gchar *) rspamd_mempool_alloc(pool, num_str_len);
		rspamd_snprintf(*target, num_str_len, "%s",
						((gboolean) obj->value.iv) ? "true" : "false");
		break;
	case UCL_NULL:
		/* String is enforced to be null */
		*target = nullptr;
		break;
	default:
		g_set_error(err,
					CFG_RCL_ERROR,
					EINVAL,
					"cannot convert %s to string in option %s",
					ucl_object_type_to_string(ucl_object_type(obj)),
					ucl_object_key(obj));
		return FALSE;
	}

	return TRUE;
}

gboolean
rspamd_rcl_parse_struct_integer(rspamd_mempool_t *pool,
								const ucl_object_t *obj,
								gpointer ud,
								struct rspamd_rcl_section *section,
								GError **err)
{
	auto *pd = (struct rspamd_rcl_struct_parser *) ud;
	union {
		gint *ip;
		gint32 *i32p;
		gint16 *i16p;
		gint64 *i64p;
		guint *up;
		gsize *sp;
	} target;
	int64_t val;

	if (pd->flags == RSPAMD_CL_FLAG_INT_32) {
		target.i32p = (gint32 *) (((gchar *) pd->user_struct) + pd->offset);
		if (!ucl_object_toint_safe(obj, &val)) {
			g_set_error(err,
						CFG_RCL_ERROR,
						EINVAL,
						"cannot convert %s to integer in option %s",
						ucl_object_type_to_string(ucl_object_type(obj)),
						ucl_object_key(obj));
			return FALSE;
		}
		*target.i32p = val;
	}
	else if (pd->flags == RSPAMD_CL_FLAG_INT_64) {
		target.i64p = (gint64 *) (((gchar *) pd->user_struct) + pd->offset);
		if (!ucl_object_toint_safe(obj, &val)) {
			g_set_error(err,
						CFG_RCL_ERROR,
						EINVAL,
						"cannot convert %s to integer in option %s",
						ucl_object_type_to_string(ucl_object_type(obj)),
						ucl_object_key(obj));
			return FALSE;
		}
		*target.i64p = val;
	}
	else if (pd->flags == RSPAMD_CL_FLAG_INT_SIZE) {
		target.sp = (gsize *) (((gchar *) pd->user_struct) + pd->offset);
		if (!ucl_object_toint_safe(obj, &val)) {
			g_set_error(err,
						CFG_RCL_ERROR,
						EINVAL,
						"cannot convert %s to integer in option %s",
						ucl_object_type_to_string(ucl_object_type(obj)),
						ucl_object_key(obj));
			return FALSE;
		}
		*target.sp = val;
	}
	else if (pd->flags == RSPAMD_CL_FLAG_INT_16) {
		target.i16p = (gint16 *) (((gchar *) pd->user_struct) + pd->offset);
		if (!ucl_object_toint_safe(obj, &val)) {
			g_set_error(err,
						CFG_RCL_ERROR,
						EINVAL,
						"cannot convert %s to integer in option %s",
						ucl_object_type_to_string(ucl_object_type(obj)),
						ucl_object_key(obj));
			return FALSE;
		}
		*target.i16p = val;
	}
	else if (pd->flags == RSPAMD_CL_FLAG_UINT) {
		target.up = (guint *) (((gchar *) pd->user_struct) + pd->offset);
		if (!ucl_object_toint_safe(obj, &val)) {
			g_set_error(err,
						CFG_RCL_ERROR,
						EINVAL,
						"cannot convert %s to integer in option %s",
						ucl_object_type_to_string(ucl_object_type(obj)),
						ucl_object_key(obj));
			return FALSE;
		}
		*target.up = val;
	}
	else {
		target.ip = (gint *) (((gchar *) pd->user_struct) + pd->offset);
		if (!ucl_object_toint_safe(obj, &val)) {
			g_set_error(err,
						CFG_RCL_ERROR,
						EINVAL,
						"cannot convert %s to integer in option %s",
						ucl_object_type_to_string(ucl_object_type(obj)),
						ucl_object_key(obj));
			return FALSE;
		}
		*target.ip = val;
	}

	return TRUE;
}

gboolean
rspamd_rcl_parse_struct_double(rspamd_mempool_t *pool,
							   const ucl_object_t *obj,
							   gpointer ud,
							   struct rspamd_rcl_section *section,
							   GError **err)
{
	auto *pd = (struct rspamd_rcl_struct_parser *) ud;
	gdouble *target;

	target = (gdouble *) (((gchar *) pd->user_struct) + pd->offset);

	if (!ucl_object_todouble_safe(obj, target)) {
		g_set_error(err,
					CFG_RCL_ERROR,
					EINVAL,
					"cannot convert %s to double in option %s",
					ucl_object_type_to_string(ucl_object_type(obj)),
					ucl_object_key(obj));
		return FALSE;
	}

	return TRUE;
}

gboolean
rspamd_rcl_parse_struct_time(rspamd_mempool_t *pool,
							 const ucl_object_t *obj,
							 gpointer ud,
							 struct rspamd_rcl_section *section,
							 GError **err)
{
	auto *pd = (struct rspamd_rcl_struct_parser *) ud;
	union {
		gint *psec;
		guint32 *pu32;
		gdouble *pdv;
		struct timeval *ptv;
		struct timespec *pts;
	} target;
	gdouble val;

	if (!ucl_object_todouble_safe(obj, &val)) {
		g_set_error(err,
					CFG_RCL_ERROR,
					EINVAL,
					"cannot convert %s to double in option %s",
					ucl_object_type_to_string(ucl_object_type(obj)),
					ucl_object_key(obj));
		return FALSE;
	}

	if (pd->flags == RSPAMD_CL_FLAG_TIME_TIMEVAL) {
		target.ptv =
			(struct timeval *) (((gchar *) pd->user_struct) + pd->offset);
		target.ptv->tv_sec = (glong) val;
		target.ptv->tv_usec = (val - (glong) val) * 1000000;
	}
	else if (pd->flags == RSPAMD_CL_FLAG_TIME_TIMESPEC) {
		target.pts =
			(struct timespec *) (((gchar *) pd->user_struct) + pd->offset);
		target.pts->tv_sec = (glong) val;
		target.pts->tv_nsec = (val - (glong) val) * 1000000000000LL;
	}
	else if (pd->flags == RSPAMD_CL_FLAG_TIME_FLOAT) {
		target.pdv = (double *) (((gchar *) pd->user_struct) + pd->offset);
		*target.pdv = val;
	}
	else if (pd->flags == RSPAMD_CL_FLAG_TIME_INTEGER) {
		target.psec = (gint *) (((gchar *) pd->user_struct) + pd->offset);
		*target.psec = val * 1000;
	}
	else if (pd->flags == RSPAMD_CL_FLAG_TIME_UINT_32) {
		target.pu32 = (guint32 *) (((gchar *) pd->user_struct) + pd->offset);
		*target.pu32 = val * 1000;
	}
	else {
		g_set_error(err,
					CFG_RCL_ERROR,
					EINVAL,
					"cannot convert %s to time in option %s",
					ucl_object_type_to_string(ucl_object_type(obj)),
					ucl_object_key(obj));
		return FALSE;
	}

	return TRUE;
}

gboolean
rspamd_rcl_parse_struct_keypair(rspamd_mempool_t *pool,
								const ucl_object_t *obj,
								gpointer ud,
								struct rspamd_rcl_section *section,
								GError **err)
{
	auto *pd = (struct rspamd_rcl_struct_parser *) ud;
	struct rspamd_cryptobox_keypair **target, *kp;

	target = (struct rspamd_cryptobox_keypair **) (((gchar *) pd->user_struct) +
												   pd->offset);
	if (obj->type == UCL_OBJECT) {
		kp = rspamd_keypair_from_ucl(obj);

		if (kp != nullptr) {
			rspamd_mempool_add_destructor(pool,
										  (rspamd_mempool_destruct_t) rspamd_keypair_unref, kp);
			*target = kp;
		}
		else {
			gchar *dump = (char *) ucl_object_emit(obj, UCL_EMIT_JSON_COMPACT);
			g_set_error(err,
						CFG_RCL_ERROR,
						EINVAL,
						"cannot load the keypair specified: %s; section: %s; value: %s",
						ucl_object_key(obj), section->name.c_str(), dump);
			free(dump);

			return FALSE;
		}
	}
	else {
		g_set_error(err,
					CFG_RCL_ERROR,
					EINVAL,
					"no sane pubkey or privkey found in the keypair: %s",
					ucl_object_key(obj));
		return FALSE;
	}

	return TRUE;
}

gboolean
rspamd_rcl_parse_struct_pubkey(rspamd_mempool_t *pool,
							   const ucl_object_t *obj,
							   gpointer ud,
							   struct rspamd_rcl_section *section,
							   GError **err)
{
	auto *pd = (struct rspamd_rcl_struct_parser *) ud;
	struct rspamd_cryptobox_pubkey **target, *pk;
	gsize len;
	const gchar *str;
	rspamd_cryptobox_keypair_type keypair_type = RSPAMD_KEYPAIR_KEX;
	rspamd_cryptobox_mode keypair_mode = RSPAMD_CRYPTOBOX_MODE_25519;

	if (pd->flags & RSPAMD_CL_FLAG_SIGNKEY) {
		keypair_type = RSPAMD_KEYPAIR_SIGN;
	}
	if (pd->flags & RSPAMD_CL_FLAG_NISTKEY) {
		keypair_mode = RSPAMD_CRYPTOBOX_MODE_NIST;
	}

	target = (struct rspamd_cryptobox_pubkey **) (((gchar *) pd->user_struct) +
												  pd->offset);
	if (obj->type == UCL_STRING) {
		str = ucl_object_tolstring(obj, &len);
		pk = rspamd_pubkey_from_base32(str, len, keypair_type,
									   keypair_mode);

		if (pk != nullptr) {
			*target = pk;
		}
		else {
			g_set_error(err,
						CFG_RCL_ERROR,
						EINVAL,
						"cannot load the pubkey specified: %s",
						ucl_object_key(obj));
			return FALSE;
		}
	}
	else {
		g_set_error(err,
					CFG_RCL_ERROR,
					EINVAL,
					"no sane pubkey found in the element: %s",
					ucl_object_key(obj));
		return FALSE;
	}

	rspamd_mempool_add_destructor(pool,
								  (rspamd_mempool_destruct_t) rspamd_pubkey_unref, pk);

	return TRUE;
}

static void
rspamd_rcl_insert_string_list_item(gpointer *target, rspamd_mempool_t *pool,
								   std::string_view elt, gboolean is_hash)
{
	union {
		GHashTable *hv;
		GList *lv;
		gpointer p;
	} d;
	gchar *val;

	d.p = *target;

	if (is_hash) {
		if (d.hv == nullptr) {
			d.hv = g_hash_table_new(rspamd_str_hash, rspamd_str_equal);
			rspamd_mempool_add_destructor(pool,
										  (rspamd_mempool_destruct_t) g_hash_table_unref, d.hv);
		}

		val = rspamd_mempool_strdup_len(pool, elt.data(), elt.size());
		g_hash_table_insert(d.hv, val, val);
	}
	else {
		val = rspamd_mempool_strdup_len(pool, elt.data(), elt.size());
		d.lv = g_list_prepend(d.lv, val);
	}

	*target = d.p;
}

gboolean
rspamd_rcl_parse_struct_string_list(rspamd_mempool_t *pool,
									const ucl_object_t *obj,
									gpointer ud,
									struct rspamd_rcl_section *section,
									GError **err)
{
	auto *pd = (struct rspamd_rcl_struct_parser *) ud;
	constexpr const auto num_str_len = 32;
	auto need_destructor = true;


	auto is_hash = pd->flags & RSPAMD_CL_FLAG_STRING_LIST_HASH;
	auto *target = (gpointer *) (((gchar *) pd->user_struct) + pd->offset);

	if (!is_hash && *target != nullptr) {
		need_destructor = FALSE;
	}

	auto iter = ucl_object_iterate_new(obj);
	const auto *cur = obj;

	while ((cur = ucl_object_iterate_safe(iter, true)) != nullptr) {
		switch (cur->type) {
		case UCL_STRING: {
			rspamd::string_foreach_delim(ucl_object_tostring(cur), ", ", [&](const auto &elt) {
				rspamd_rcl_insert_string_list_item(target, pool, elt, is_hash);
			});

			/* Go to the next object */
			continue;
		}
		case UCL_INT: {
			auto *val = (gchar *) rspamd_mempool_alloc(pool, num_str_len);
			rspamd_snprintf(val, num_str_len, "%L", cur->value.iv);
			rspamd_rcl_insert_string_list_item(target, pool, val, is_hash);
			break;
		}
		case UCL_FLOAT: {
			auto *val = (gchar *) rspamd_mempool_alloc(pool, num_str_len);
			rspamd_snprintf(val, num_str_len, "%f", cur->value.dv);
			rspamd_rcl_insert_string_list_item(target, pool, val, is_hash);
			break;
		}
		case UCL_BOOLEAN: {
			auto *val = (gchar *) rspamd_mempool_alloc(pool, num_str_len);
			rspamd_snprintf(val, num_str_len, "%s",
							((gboolean) cur->value.iv) ? "true" : "false");
			rspamd_rcl_insert_string_list_item(target, pool, val, is_hash);
			break;
		}
		default:
			g_set_error(err,
						CFG_RCL_ERROR,
						EINVAL,
						"cannot convert %s to a string list in option %s",
						ucl_object_type_to_string(ucl_object_type(obj)),
						ucl_object_key(obj));
			ucl_object_iterate_free(iter);

			return FALSE;
		}
	}

	ucl_object_iterate_free(iter);

#if 0
	/* WTF: why don't we allow empty list here?? */
	if (*target == nullptr) {
		g_set_error (err,
				CFG_RCL_ERROR,
				EINVAL,
				"non-empty array of strings is expected: %s, "
				"got: %s, of length: %d",
				ucl_object_key (obj), ucl_object_type_to_string (obj->type),
				obj->len);
		return FALSE;
	}
#endif

	if (!is_hash && *target != nullptr) {
		*target = g_list_reverse(*(GList **) target);

		if (need_destructor) {
			rspamd_mempool_add_destructor(pool,
										  (rspamd_mempool_destruct_t) g_list_free,
										  *target);
		}
	}

	return TRUE;
}

gboolean
rspamd_rcl_parse_struct_ucl(rspamd_mempool_t *pool,
							const ucl_object_t *obj,
							gpointer ud,
							struct rspamd_rcl_section *section,
							GError **err)
{
	auto *pd = (struct rspamd_rcl_struct_parser *) ud;
	const ucl_object_t **target;

	target = (const ucl_object_t **) (((gchar *) pd->user_struct) + pd->offset);

	*target = obj;

	return TRUE;
}


gboolean
rspamd_rcl_parse_struct_boolean(rspamd_mempool_t *pool,
								const ucl_object_t *obj,
								gpointer ud,
								struct rspamd_rcl_section *section,
								GError **err)
{
	auto *pd = (struct rspamd_rcl_struct_parser *) ud;
	gboolean *target;

	target = (gboolean *) (((gchar *) pd->user_struct) + pd->offset);

	if (obj->type == UCL_BOOLEAN) {
		*target = obj->value.iv;
	}
	else if (obj->type == UCL_INT) {
		*target = obj->value.iv;
	}
	else {
		g_set_error(err,
					CFG_RCL_ERROR,
					EINVAL,
					"cannot convert %s to boolean in option %s",
					ucl_object_type_to_string(ucl_object_type(obj)),
					ucl_object_key(obj));
		return FALSE;
	}

	if (pd->flags & RSPAMD_CL_FLAG_BOOLEAN_INVERSE) {
		*target = !*target;
	}

	return TRUE;
}

gboolean
rspamd_rcl_parse_struct_addr(rspamd_mempool_t *pool,
							 const ucl_object_t *obj,
							 gpointer ud,
							 struct rspamd_rcl_section *section,
							 GError **err)
{
	auto *pd = (struct rspamd_rcl_struct_parser *) ud;
	rspamd_inet_addr_t **target;
	const gchar *val;
	gsize size;

	target = (rspamd_inet_addr_t **) (((gchar *) pd->user_struct) + pd->offset);

	if (ucl_object_type(obj) == UCL_STRING) {
		val = ucl_object_tolstring(obj, &size);

		if (!rspamd_parse_inet_address(target, val, size,
									   RSPAMD_INET_ADDRESS_PARSE_DEFAULT)) {
			g_set_error(err,
						CFG_RCL_ERROR,
						EINVAL,
						"cannot parse inet address: %s", val);
			return FALSE;
		}
	}
	else {
		g_set_error(err,
					CFG_RCL_ERROR,
					EINVAL,
					"cannot convert %s to inet address in option %s",
					ucl_object_type_to_string(ucl_object_type(obj)),
					ucl_object_key(obj));
		return FALSE;
	}

	return TRUE;
}

gboolean
rspamd_rcl_parse_struct_mime_addr(rspamd_mempool_t *pool,
								  const ucl_object_t *obj,
								  gpointer ud,
								  struct rspamd_rcl_section *section,
								  GError **err)
{
	auto *pd = (struct rspamd_rcl_struct_parser *) ud;
	GPtrArray **target, *tmp_addr = nullptr;
	const gchar *val;
	ucl_object_iter_t it;
	const ucl_object_t *cur;

	target = (GPtrArray **) (((gchar *) pd->user_struct) + pd->offset);
	it = ucl_object_iterate_new(obj);

	while ((cur = ucl_object_iterate_safe(it, true)) != nullptr) {
		if (ucl_object_type(cur) == UCL_STRING) {
			val = ucl_object_tostring(obj);
			tmp_addr = rspamd_email_address_from_mime(pool, val,
													  strlen(val), tmp_addr, -1);
		}
		else {
			g_set_error(err,
						CFG_RCL_ERROR,
						EINVAL,
						"cannot get inet address from ucl object in %s",
						ucl_object_key(obj));
			ucl_object_iterate_free(it);

			return FALSE;
		}
	}

	ucl_object_iterate_free(it);
	*target = tmp_addr;

	return TRUE;
}

void rspamd_rcl_register_worker_option(struct rspamd_config *cfg,
									   GQuark type,
									   const gchar *name,
									   rspamd_rcl_default_handler_t handler,
									   gpointer target,
									   glong offset,
									   gint flags,
									   const gchar *doc_string)
{
	auto parser_it = cfg->rcl_top_section->workers_parser.try_emplace(type, rspamd_worker_cfg_parser{});
	auto &parser = parser_it.first->second;
	auto handler_it = parser.parsers.try_emplace(std::make_pair(std::string{name}, target), rspamd_worker_param_parser{});

	if (!handler_it.second) {
		msg_warn_config(
			"handler for parameter %s is already registered for worker type %s",
			name,
			g_quark_to_string(type));
		return;
	}

	auto &nhandler = handler_it.first->second;
	nhandler.parser.flags = flags;
	nhandler.parser.offset = offset;
	nhandler.parser.user_struct = target;
	nhandler.handler = handler;

	const auto *doc_workers = ucl_object_lookup(cfg->doc_strings, "workers");

	if (doc_workers == nullptr) {
		auto *doc_obj = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(cfg->doc_strings, doc_obj, "workers", 0, false);
		doc_workers = doc_obj;
	}

	const auto *doc_target = ucl_object_lookup(doc_workers, g_quark_to_string(type));

	if (doc_target == nullptr) {
		auto *doc_obj = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key((ucl_object_t *) doc_workers, doc_obj,
							  g_quark_to_string(type), 0, true);
		doc_target = doc_obj;
	}

	rspamd_rcl_add_doc_obj((ucl_object_t *) doc_target,
						   doc_string,
						   name,
						   UCL_NULL,
						   handler,
						   flags,
						   nullptr,
						   0);
}

/* Checksum functions */
static int
rspamd_rcl_emitter_append_c(unsigned char c, size_t nchars, void *ud)
{
	auto *hs = (rspamd_cryptobox_hash_state_t *) ud;
	guint64 d[2];

	d[0] = nchars;
	d[1] = c;

	rspamd_cryptobox_hash_update(hs, (const guchar *) d, sizeof(d));

	return 0;
}

static int
rspamd_rcl_emitter_append_len(unsigned const char *str, size_t len, void *ud)
{
	auto *hs = (rspamd_cryptobox_hash_state_t *) ud;

	rspamd_cryptobox_hash_update(hs, str, len);

	return 0;
}
static int
rspamd_rcl_emitter_append_int(int64_t elt, void *ud)
{
	auto *hs = (rspamd_cryptobox_hash_state_t *) ud;

	rspamd_cryptobox_hash_update(hs, (const guchar *) &elt, sizeof(elt));

	return 0;
}

static int
rspamd_rcl_emitter_append_double(double elt, void *ud)
{
	auto *hs = (rspamd_cryptobox_hash_state_t *) ud;

	rspamd_cryptobox_hash_update(hs, (const guchar *) &elt, sizeof(elt));

	return 0;
}

void rspamd_rcl_sections_free(struct rspamd_rcl_sections_map *sections)
{
	delete sections;
}

/**
 * Calls for an external lua function to apply potential config transformations
 * if needed. This function can change the cfg->rcl_obj.
 *
 * Example of transformation function:
 *
 * function(obj)
 *   if obj.something == 'foo' then
 *     obj.something = "bla"
 *     return true, obj
 *   end
 *
 *   return false, nil
 * end
 *
 * If function returns 'false' then rcl_obj is not touched. Otherwise,
 * it is changed, then rcl_obj is imported from lua. Old config is dereferenced.
 * @param cfg
 */
void rspamd_rcl_maybe_apply_lua_transform(struct rspamd_config *cfg)
{
	auto *L = RSPAMD_LUA_CFG_STATE(cfg);
	static const char *transform_script = "lua_cfg_transform";

	g_assert(L != nullptr);

	if (!rspamd_lua_require_function(L, transform_script, nullptr)) {
		/* No function defined */
		msg_warn_config("cannot execute lua script %s: %s",
						transform_script, lua_tostring(L, -1));

		return;
	}

	lua_pushcfunction(L, &rspamd_lua_traceback);
	auto err_idx = lua_gettop(L);

	/* Push function */
	lua_pushvalue(L, -2);

	/* Push the existing config */
	ucl_object_push_lua(L, cfg->cfg_ucl_obj, true);

	if (auto ret = lua_pcall(L, 1, 2, err_idx); ret != 0) {
		msg_err("call to rspamadm lua script failed (%d): %s", ret,
				lua_tostring(L, -1));
		lua_settop(L, 0);

		return;
	}

	if (lua_toboolean(L, -2) && lua_type(L, -1) == LUA_TTABLE) {
		ucl_object_t *old_cfg = cfg->cfg_ucl_obj;

		msg_info_config("configuration has been transformed in Lua");
		cfg->cfg_ucl_obj = ucl_object_lua_import(L, -1);
		ucl_object_unref(old_cfg);
	}

	/* error function */
	lua_settop(L, 0);
}

static bool
rspamd_rcl_decrypt_handler(struct ucl_parser *parser,
						   const unsigned char *source, size_t source_len,
						   unsigned char **destination, size_t *dest_len,
						   void *user_data)
{
	GError *err = nullptr;
	auto *kp = (struct rspamd_cryptobox_keypair *) user_data;

	if (!rspamd_keypair_decrypt(kp, source, source_len,
								destination, dest_len, &err)) {
		msg_err("cannot decrypt file: %e", err);
		g_error_free(err);

		return false;
	}

	return true;
}

static bool
rspamd_rcl_jinja_handler(struct ucl_parser *parser,
						 const unsigned char *source, size_t source_len,
						 unsigned char **destination, size_t *dest_len,
						 void *user_data)
{
	auto *cfg = (struct rspamd_config *) user_data;
	auto *L = RSPAMD_LUA_CFG_STATE(cfg);

	lua_pushcfunction(L, &rspamd_lua_traceback);
	auto err_idx = lua_gettop(L);

	/* Obtain function */
	if (!rspamd_lua_require_function(L, "lua_util", "jinja_template")) {
		msg_err_config("cannot require lua_util.jinja_template");
		lua_settop(L, err_idx - 1);

		return false;
	}

	lua_pushlstring(L, (const char *) source, source_len);
	lua_getglobal(L, "rspamd_env");
	lua_pushboolean(L, false);

	if (lua_pcall(L, 3, 1, err_idx) != 0) {
		msg_err_config("cannot call lua jinja_template script: %s",
					   lua_tostring(L, -1));
		lua_settop(L, err_idx - 1);

		return false;
	}

	if (lua_type(L, -1) == LUA_TSTRING) {
		const char *ndata;
		gsize nsize;

		ndata = lua_tolstring(L, -1, &nsize);
		*destination = (unsigned char *) UCL_ALLOC(nsize);
		memcpy(*destination, ndata, nsize);
		*dest_len = nsize;
	}
	else {
		msg_err_config("invalid return type when templating jinja %s",
					   lua_typename(L, lua_type(L, -1)));
		lua_settop(L, err_idx - 1);

		return false;
	}

	lua_settop(L, err_idx - 1);

	return true;
}

static void
rspamd_rcl_decrypt_free(unsigned char *data, size_t len, void *user_data)
{
	g_free(data);
}

void rspamd_config_calculate_cksum(struct rspamd_config *cfg)
{
	rspamd_cryptobox_hash_state_t hs;
	unsigned char cksumbuf[rspamd_cryptobox_HASHBYTES];
	struct ucl_emitter_functions f;

	/* Calculate checksum */
	rspamd_cryptobox_hash_init(&hs, nullptr, 0);
	f.ucl_emitter_append_character = rspamd_rcl_emitter_append_c;
	f.ucl_emitter_append_double = rspamd_rcl_emitter_append_double;
	f.ucl_emitter_append_int = rspamd_rcl_emitter_append_int;
	f.ucl_emitter_append_len = rspamd_rcl_emitter_append_len;
	f.ucl_emitter_free_func = nullptr;
	f.ud = &hs;
	ucl_object_emit_full(cfg->cfg_ucl_obj, UCL_EMIT_MSGPACK,
						 &f, cfg->config_comments);
	rspamd_cryptobox_hash_final(&hs, cksumbuf);
	cfg->checksum = rspamd_encode_base32(cksumbuf, sizeof(cksumbuf), RSPAMD_BASE32_DEFAULT);
	/* Also change the tag of cfg pool to be equal to the checksum */
	rspamd_strlcpy(cfg->cfg_pool->tag.uid, cfg->checksum,
				   MIN(sizeof(cfg->cfg_pool->tag.uid), strlen(cfg->checksum)));
}

gboolean
rspamd_config_parse_ucl(struct rspamd_config *cfg,
						const gchar *filename,
						GHashTable *vars,
						ucl_include_trace_func_t inc_trace,
						void *trace_data,
						gboolean skip_jinja,
						GError **err)
{
	struct rspamd_cryptobox_keypair *decrypt_keypair = nullptr;
	auto cfg_file_maybe = rspamd::util::raii_mmaped_file::mmap_shared(filename, O_RDONLY, PROT_READ, 0);

	if (!cfg_file_maybe) {
		g_set_error(err, cfg_rcl_error_quark(), errno,
					"cannot open %s: %*s", filename, (int) cfg_file_maybe.error().error_message.size(),
					cfg_file_maybe.error().error_message.data());
		return FALSE;
	}

	auto &cfg_file = cfg_file_maybe.value();

	/* Try to load keyfile if available */
	rspamd::util::raii_file::open(fmt::format("{}.key", filename), O_RDONLY).map([&](const auto &keyfile) {
		auto *kp_parser = ucl_parser_new(0);
		if (ucl_parser_add_fd(kp_parser, keyfile.get_fd())) {
			auto *kp_obj = ucl_parser_get_object(kp_parser);

			g_assert(kp_obj != nullptr);
			decrypt_keypair = rspamd_keypair_from_ucl(kp_obj);

			if (decrypt_keypair == nullptr) {
				msg_err_config_forced("cannot load keypair from %s.key: invalid keypair",
									  filename);
			}
			else {
				/* Add decryption support to UCL */
				rspamd_mempool_add_destructor(cfg->cfg_pool,
											  (rspamd_mempool_destruct_t) rspamd_keypair_unref,
											  decrypt_keypair);
			}

			ucl_object_unref(kp_obj);
		}
		else {
			msg_err_config_forced("cannot load keypair from %s.key: %s",
								  filename, ucl_parser_get_error(kp_parser));
		}
		ucl_parser_free(kp_parser);
	});

	auto parser = std::shared_ptr<ucl_parser>(ucl_parser_new(UCL_PARSER_SAVE_COMMENTS), ucl_parser_free);
	rspamd_ucl_add_conf_variables(parser.get(), vars);
	rspamd_ucl_add_conf_macros(parser.get(), cfg);
	ucl_parser_set_filevars(parser.get(), filename, true);

	if (inc_trace) {
		ucl_parser_set_include_tracer(parser.get(), inc_trace, trace_data);
	}

	if (decrypt_keypair) {
		auto *decrypt_handler = rspamd_mempool_alloc0_type(cfg->cfg_pool,
														   struct ucl_parser_special_handler);
		decrypt_handler->user_data = decrypt_keypair;
		decrypt_handler->magic = encrypted_magic;
		decrypt_handler->magic_len = sizeof(encrypted_magic);
		decrypt_handler->handler = rspamd_rcl_decrypt_handler;
		decrypt_handler->free_function = rspamd_rcl_decrypt_free;

		ucl_parser_add_special_handler(parser.get(), decrypt_handler);
	}

	if (!skip_jinja) {
		auto *jinja_handler = rspamd_mempool_alloc0_type(cfg->cfg_pool,
														 struct ucl_parser_special_handler);
		jinja_handler->user_data = cfg;
		jinja_handler->flags = UCL_SPECIAL_HANDLER_PREPROCESS_ALL;
		jinja_handler->handler = rspamd_rcl_jinja_handler;

		ucl_parser_add_special_handler(parser.get(), jinja_handler);
	}

	if (!ucl_parser_add_chunk(parser.get(), (unsigned char *) cfg_file.get_map(), cfg_file.get_size())) {
		g_set_error(err, cfg_rcl_error_quark(), errno,
					"ucl parser error: %s", ucl_parser_get_error(parser.get()));

		return FALSE;
	}

	cfg->cfg_ucl_obj = ucl_parser_get_object(parser.get());
	cfg->config_comments = ucl_object_ref(ucl_parser_get_comments(parser.get()));

	return TRUE;
}

gboolean
rspamd_config_read(struct rspamd_config *cfg,
				   const gchar *filename,
				   rspamd_rcl_section_fin_t logger_fin,
				   gpointer logger_ud,
				   GHashTable *vars,
				   gboolean skip_jinja,
				   gchar **lua_env)
{
	GError *err = nullptr;

	rspamd_lua_set_path(RSPAMD_LUA_CFG_STATE(cfg), nullptr, vars);

	if (!rspamd_lua_set_env(RSPAMD_LUA_CFG_STATE(cfg), vars, lua_env, &err)) {
		msg_err_config_forced("failed to set up environment: %e", err);
		g_error_free(err);

		return FALSE;
	}

	if (!rspamd_config_parse_ucl(cfg, filename, vars, nullptr, nullptr, skip_jinja, &err)) {
		msg_err_config_forced("failed to load config: %e", err);
		g_error_free(err);

		return FALSE;
	}

	auto *top = rspamd_rcl_config_init(cfg, nullptr);
	cfg->rcl_top_section = top;
	/* Add new paths if defined in options */
	rspamd_lua_set_path(RSPAMD_LUA_CFG_STATE(cfg), cfg->cfg_ucl_obj, vars);
	rspamd_lua_set_globals(cfg, RSPAMD_LUA_CFG_STATE(cfg));
	rspamd_mempool_add_destructor(cfg->cfg_pool, (rspamd_mempool_destruct_t) rspamd_rcl_sections_free, top);
	err = nullptr;

	/* Pre-init logging if possible */
	if (logger_fin != nullptr) {
		auto logging_section_maybe = rspamd::find_map(top->sections, "logging");

		if (logging_section_maybe) {
			const auto *logger_obj = ucl_object_lookup_any(cfg->cfg_ucl_obj, "logging",
														   "logger", nullptr);

			if (logger_obj == nullptr) {
				logger_fin(cfg->cfg_pool, logger_ud);
			}
			else {
				if (!rspamd_rcl_process_section(cfg, *logging_section_maybe.value().get().get(), cfg,
												logger_obj, cfg->cfg_pool, &err)) {
					msg_err_config_forced("cannot init logger: %e", err);
					g_error_free(err);

					return FALSE;
				}
				else {
					logger_fin(cfg->cfg_pool, logger_ud);
				}

				/* Init lua logging */
				lua_pushcfunction(RSPAMD_LUA_CFG_STATE(cfg), &rspamd_lua_traceback);
				auto err_idx = lua_gettop(RSPAMD_LUA_CFG_STATE(cfg));

				/* Obtain function */
				if (!rspamd_lua_require_function(RSPAMD_LUA_CFG_STATE(cfg), "lua_util",
												 "init_debug_logging")) {
					msg_err_config("cannot require lua_util.init_debug_logging");
					lua_settop(RSPAMD_LUA_CFG_STATE(cfg), err_idx - 1);

					return FALSE;
				}

				void *pcfg = lua_newuserdata(RSPAMD_LUA_CFG_STATE(cfg), sizeof(void *));
				memcpy(pcfg, &cfg, sizeof(void *));
				rspamd_lua_setclass(RSPAMD_LUA_CFG_STATE(cfg), "rspamd{config}", -1);

				if (lua_pcall(RSPAMD_LUA_CFG_STATE(cfg), 1, 0, err_idx) != 0) {
					msg_err_config("cannot call lua init_debug_logging script: %s",
								   lua_tostring(RSPAMD_LUA_CFG_STATE(cfg), -1));
					lua_settop(RSPAMD_LUA_CFG_STATE(cfg), err_idx - 1);

					return FALSE;
				}

				lua_settop(RSPAMD_LUA_CFG_STATE(cfg), err_idx - 1);
			}
		}
	}

	/* Transform config if needed */
	rspamd_rcl_maybe_apply_lua_transform(cfg);
	rspamd_config_calculate_cksum(cfg);

	if (!rspamd_rcl_parse(top, cfg, cfg, cfg->cfg_pool, cfg->cfg_ucl_obj, &err)) {
		msg_err_config("rcl parse error: %e", err);

		if (err) {
			g_error_free(err);
		}

		return FALSE;
	}

	cfg->lang_det = rspamd_language_detector_init(cfg);
	rspamd_mempool_add_destructor(cfg->cfg_pool,
								  (rspamd_mempool_destruct_t) rspamd_language_detector_unref,
								  cfg->lang_det);

	return TRUE;
}

static void
rspamd_rcl_doc_obj_from_handler(ucl_object_t *doc_obj,
								rspamd_rcl_default_handler_t handler,
								gint flags)
{
	auto has_example = ucl_object_lookup(doc_obj, "example") != nullptr;
	auto has_type = ucl_object_lookup(doc_obj, "type") != nullptr;

	if (handler == rspamd_rcl_parse_struct_string) {
		if (!has_type) {
			ucl_object_insert_key(doc_obj, ucl_object_fromstring("string"),
								  "type", 0, false);
		}
	}
	else if (handler == rspamd_rcl_parse_struct_integer) {
		auto *type = "int";

		if (flags & RSPAMD_CL_FLAG_INT_16) {
			type = "int16";
		}
		else if (flags & RSPAMD_CL_FLAG_INT_32) {
			type = "int32";
		}
		else if (flags & RSPAMD_CL_FLAG_INT_64) {
			type = "int64";
		}
		else if (flags & RSPAMD_CL_FLAG_INT_SIZE) {
			type = "size";
		}
		else if (flags & RSPAMD_CL_FLAG_UINT) {
			type = "uint";
		}

		if (!has_type) {
			ucl_object_insert_key(doc_obj, ucl_object_fromstring(type),
								  "type", 0, false);
		}
	}
	else if (handler == rspamd_rcl_parse_struct_double) {
		if (!has_type) {
			ucl_object_insert_key(doc_obj, ucl_object_fromstring("double"),
								  "type", 0, false);
		}
	}
	else if (handler == rspamd_rcl_parse_struct_time) {
		auto *type = "time";

		if (!has_type) {
			ucl_object_insert_key(doc_obj, ucl_object_fromstring(type),
								  "type", 0, false);
		}
	}
	else if (handler == rspamd_rcl_parse_struct_string_list) {
		if (!has_type) {
			ucl_object_insert_key(doc_obj, ucl_object_fromstring("string list"),
								  "type", 0, false);
		}
		if (!has_example) {
			ucl_object_insert_key(doc_obj,
								  ucl_object_fromstring_common("param = \"str1, str2, str3\" OR "
															   "param = [\"str1\", \"str2\", \"str3\"]",
															   0, static_cast<ucl_string_flags>(0)),
								  "example",
								  0,
								  false);
		}
	}
	else if (handler == rspamd_rcl_parse_struct_boolean) {
		if (!has_type) {
			ucl_object_insert_key(doc_obj,
								  ucl_object_fromstring("bool"),
								  "type",
								  0,
								  false);
		}
	}
	else if (handler == rspamd_rcl_parse_struct_keypair) {
		if (!has_type) {
			ucl_object_insert_key(doc_obj,
								  ucl_object_fromstring("keypair"),
								  "type",
								  0,
								  false);
		}
		if (!has_example) {
			ucl_object_insert_key(doc_obj,
								  ucl_object_fromstring("keypair { "
														"pubkey = <base32_string>;"
														" privkey = <base32_string>; "
														"}"),
								  "example",
								  0,
								  false);
		}
	}
	else if (handler == rspamd_rcl_parse_struct_addr) {
		if (!has_type) {
			ucl_object_insert_key(doc_obj,
								  ucl_object_fromstring("socket address"),
								  "type",
								  0,
								  false);
		}
	}
	else if (handler == rspamd_rcl_parse_struct_mime_addr) {
		if (!has_type) {
			ucl_object_insert_key(doc_obj,
								  ucl_object_fromstring("email address"),
								  "type",
								  0,
								  false);
		}
	}
}

ucl_object_t *
rspamd_rcl_add_doc_obj(ucl_object_t *doc_target,
					   const char *doc_string,
					   const char *doc_name,
					   ucl_type_t type,
					   rspamd_rcl_default_handler_t handler,
					   gint flags,
					   const char *default_value,
					   gboolean required)
{
	ucl_object_t *doc_obj;

	if (doc_target == nullptr || doc_name == nullptr) {
		return nullptr;
	}

	doc_obj = ucl_object_typed_new(UCL_OBJECT);

	/* Insert doc string itself */
	if (doc_string) {
		ucl_object_insert_key(doc_obj,
							  ucl_object_fromstring_common(doc_string, 0, static_cast<ucl_string_flags>(0)),
							  "data", 0, false);
	}
	else {
		ucl_object_insert_key(doc_obj, ucl_object_fromstring("undocumented"),
							  "data", 0, false);
	}

	if (type != UCL_NULL) {
		ucl_object_insert_key(doc_obj,
							  ucl_object_fromstring(ucl_object_type_to_string(type)),
							  "type", 0, false);
	}

	rspamd_rcl_doc_obj_from_handler(doc_obj, handler, flags);

	ucl_object_insert_key(doc_obj,
						  ucl_object_frombool(required),
						  "required", 0, false);

	if (default_value) {
		ucl_object_insert_key(doc_obj,
							  ucl_object_fromstring_common(default_value, 0, static_cast<ucl_string_flags>(0)),
							  "default", 0, false);
	}

	ucl_object_insert_key(doc_target, doc_obj, doc_name, 0, true);

	return doc_obj;
}

ucl_object_t *
rspamd_rcl_add_doc_by_path(struct rspamd_config *cfg,
						   const gchar *doc_path,
						   const char *doc_string,
						   const char *doc_name,
						   ucl_type_t type,
						   rspamd_rcl_default_handler_t handler,
						   gint flags,
						   const char *default_value,
						   gboolean required)
{
	const auto *cur = cfg->doc_strings;

	if (doc_path == nullptr) {
		/* Assume top object */
		return rspamd_rcl_add_doc_obj(cfg->doc_strings,
									  doc_string,
									  doc_name,
									  type,
									  handler,
									  flags,
									  default_value,
									  required);
	}
	else {
		const auto *found = ucl_object_lookup_path(cfg->doc_strings, doc_path);

		if (found != nullptr) {
			return rspamd_rcl_add_doc_obj((ucl_object_t *) found,
										  doc_string,
										  doc_name,
										  type,
										  handler,
										  flags,
										  default_value,
										  required);
		}

		/* Otherwise we need to insert all components of the path */
		rspamd::string_foreach_delim(doc_path, ".", [&](const std::string_view &elt) {
			if (ucl_object_type(cur) != UCL_OBJECT) {
				msg_err_config("Bad path while lookup for '%s' at %*s",
							   doc_path, (int) elt.size(), elt.data());
			}
			const auto *found = ucl_object_lookup_len(cur, elt.data(), elt.size());
			if (found == nullptr) {
				auto *obj = ucl_object_typed_new(UCL_OBJECT);
				ucl_object_insert_key((ucl_object_t *) cur,
									  obj,
									  elt.data(),
									  elt.size(),
									  true);
				cur = obj;
			}
			else {
				cur = found;
			}
		});
	}

	return rspamd_rcl_add_doc_obj(ucl_object_ref(cur),
								  doc_string,
								  doc_name,
								  type,
								  handler,
								  flags,
								  default_value,
								  required);
}

static void
rspamd_rcl_add_doc_from_comments(struct rspamd_config *cfg,
								 ucl_object_t *top_doc, const ucl_object_t *obj,
								 const ucl_object_t *comments, gboolean is_top)
{
	ucl_object_iter_t it = nullptr;
	const ucl_object_t *cur, *cmt;
	ucl_object_t *cur_doc;

	if (ucl_object_type(obj) == UCL_OBJECT) {
		while ((cur = ucl_object_iterate(obj, &it, true)) != nullptr) {
			cur_doc = nullptr;

			if ((cmt = ucl_comments_find(comments, cur)) != nullptr) {
				cur_doc = rspamd_rcl_add_doc_obj(top_doc,
												 ucl_object_tostring(cmt), ucl_object_key(cur),
												 ucl_object_type(cur), nullptr, 0, nullptr, FALSE);
			}

			if (ucl_object_type(cur) == UCL_OBJECT) {
				if (cur_doc) {
					rspamd_rcl_add_doc_from_comments(cfg, cur_doc, cur,
													 comments,
													 FALSE);
				}
				else {
					rspamd_rcl_add_doc_from_comments(cfg, top_doc, cur,
													 comments,
													 FALSE);
				}
			}
		}
	}
	else if (!is_top) {
		if ((cmt = ucl_comments_find(comments, obj)) != nullptr) {
			rspamd_rcl_add_doc_obj(top_doc,
								   ucl_object_tostring(cmt), ucl_object_key(obj),
								   ucl_object_type(obj), nullptr, 0, nullptr, FALSE);
		}
	}
}

ucl_object_t *
rspamd_rcl_add_doc_by_example(struct rspamd_config *cfg,
							  const gchar *root_path,
							  const gchar *doc_string,
							  const gchar *doc_name,
							  const gchar *example_data, gsize example_len)
{
	auto parser = std::shared_ptr<ucl_parser>(ucl_parser_new(UCL_PARSER_NO_FILEVARS | UCL_PARSER_SAVE_COMMENTS), ucl_parser_free);

	if (!ucl_parser_add_chunk(parser.get(), reinterpret_cast<const unsigned char *>(example_data), example_len)) {
		msg_err_config("cannot parse example: %s",
					   ucl_parser_get_error(parser.get()));

		return nullptr;
	}

	auto *top = ucl_parser_get_object(parser.get());
	const auto *comments = ucl_parser_get_comments(parser.get());

	/* Add top object */
	auto *top_doc = rspamd_rcl_add_doc_by_path(cfg, root_path, doc_string,
											   doc_name, ucl_object_type(top), nullptr, 0, nullptr, FALSE);
	ucl_object_insert_key(top_doc,
						  ucl_object_fromstring_common(example_data, example_len, static_cast<ucl_string_flags>(0)),
						  "example", 0, false);

	rspamd_rcl_add_doc_from_comments(cfg, top_doc, top, comments, TRUE);

	return top_doc;
}
