/*-
 * Copyright 2021 Vsevolod Stakhov
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

#include <memory>
#include <vector>
#include <cmath>
#include "contrib/ankerl/unordered_dense.h"

#include "composites.h"
#include "composites_internal.hxx"
#include "libserver/cfg_file.h"
#include "libserver/logger.h"
#include "libserver/maps/map.h"
#include "libutil/cxx/util.hxx"

namespace rspamd::composites {

static auto
composite_policy_from_str(const std::string_view &inp) -> enum rspamd_composite_policy
{
	const static ankerl::unordered_dense::map<std::string_view,
			enum rspamd_composite_policy> names{
			{"remove",        rspamd_composite_policy::RSPAMD_COMPOSITE_POLICY_REMOVE_ALL},
			{"remove_all",    rspamd_composite_policy::RSPAMD_COMPOSITE_POLICY_REMOVE_ALL},
			{"default",       rspamd_composite_policy::RSPAMD_COMPOSITE_POLICY_REMOVE_ALL},
			{"remove_symbol", rspamd_composite_policy::RSPAMD_COMPOSITE_POLICY_REMOVE_SYMBOL},
			{"remove_weight", rspamd_composite_policy::RSPAMD_COMPOSITE_POLICY_REMOVE_WEIGHT},
			{"leave",         rspamd_composite_policy::RSPAMD_COMPOSITE_POLICY_LEAVE},
			{"remove_none",   rspamd_composite_policy::RSPAMD_COMPOSITE_POLICY_LEAVE},
	};

	auto found = names.find(inp);
	if (found != names.end()) {
		return found->second;
	}

	return rspamd_composite_policy::RSPAMD_COMPOSITE_POLICY_UNKNOWN;
}

auto
composites_manager::add_composite(std::string_view composite_name, const ucl_object_t *obj, bool silent_duplicate) -> rspamd_composite *
{

	const auto *val = ucl_object_lookup(obj, "enabled");
	if (val != nullptr && !ucl_object_toboolean(val)) {
		msg_info_config ("composite %s is disabled", composite_name.data());
		return nullptr;
	}

	if (composites.contains(composite_name)) {
		if (silent_duplicate) {
			msg_debug_config ("composite %s is redefined", composite_name.data());
			return nullptr;
		}
		else {
			msg_warn_config ("composite %s is redefined", composite_name.data());
		}
	}

	const char *composite_expression = nullptr;
	val = ucl_object_lookup(obj, "expression");

	if (val == NULL || !ucl_object_tostring_safe(val, &composite_expression)) {
		msg_err_config ("composite must have an expression defined in %s",
				composite_name.data());
		return nullptr;
	}

	GError *err = nullptr;
	rspamd_expression *expr = nullptr;

	if (!rspamd_parse_expression(composite_expression, 0, &composite_expr_subr,
			NULL, cfg->cfg_pool, &err, &expr)) {
		msg_err_config ("cannot parse composite expression for %s: %e",
				composite_name.data(), err);

		if (err) {
			g_error_free(err);
		}

		return nullptr;
	}

	const auto &composite = new_composite(composite_name, expr, composite_expression);

	auto score = std::isnan(cfg->unknown_weight) ? 0.0 : cfg->unknown_weight;
	val = ucl_object_lookup(obj, "score");

	if (val != nullptr) {
		ucl_object_todouble_safe(val, &score);
	}

	/* Also set score in the metric */
	const auto *group = "composite";
	val = ucl_object_lookup(obj, "group");
	if (val != nullptr) {
		group = ucl_object_tostring(val);
	}

	const auto *description = composite_expression;
	val = ucl_object_lookup(obj, "description");
	if (val != nullptr) {
		description = ucl_object_tostring(val);
	}

	rspamd_config_add_symbol(cfg, composite_name.data(), score,
			description, group,
			0,
			ucl_object_get_priority(obj), /* No +1 as it is default... */
			1);

	const auto *elt = ucl_object_lookup(obj, "groups");
	if (elt && ucl_object_type(elt) == UCL_ARRAY) {
		const ucl_object_t *cur_gr;
		auto *gr_it = ucl_object_iterate_new(elt);

		while ((cur_gr = ucl_object_iterate_safe(gr_it, true)) != nullptr) {
			rspamd_config_add_symbol_group(cfg, composite_name.data(),
					ucl_object_tostring(cur_gr));
		}

		ucl_object_iterate_free(gr_it);
	}

	val = ucl_object_lookup(obj, "policy");
	if (val) {
		composite->policy = composite_policy_from_str(ucl_object_tostring(val));

		if (composite->policy == rspamd_composite_policy::RSPAMD_COMPOSITE_POLICY_UNKNOWN) {
			msg_err_config("composite %s has incorrect policy", composite_name.data());
			return nullptr;
		}
	}

	return composite.get();
}

auto
composites_manager::add_composite(std::string_view composite_name,
								  std::string_view composite_expression,
								  bool silent_duplicate, double score) -> rspamd_composite *
{
	GError *err = nullptr;
	rspamd_expression *expr = nullptr;

	if (composites.contains(composite_name)) {
		/* Duplicate composite - refuse to add */
		if (silent_duplicate) {
			msg_debug_config ("composite %s is redefined", composite_name.data());
			return nullptr;
		}
		else {
			msg_warn_config ("composite %s is redefined", composite_name.data());
		}
	}

	if (!rspamd_parse_expression(composite_expression.data(),
			composite_expression.size(), &composite_expr_subr,
			nullptr, cfg->cfg_pool, &err, &expr)) {
		msg_err_config ("cannot parse composite expression for %s: %e",
				composite_name.data(), err);

		if (err) {
			g_error_free(err);
		}

		return nullptr;
	}

	auto final_score = std::isnan(score) ? (std::isnan(cfg->unknown_weight) ? 0.0 : cfg->unknown_weight) : score;
	rspamd_config_add_symbol(cfg, composite_name.data(), final_score,
			composite_name.data(), "composite",
			0,
			0,
			1);

	return new_composite(composite_name, expr, composite_expression).get();
}

struct map_cbdata {
	composites_manager *cm;
	struct rspamd_config *cfg;
	std::string buf;

	explicit map_cbdata(struct rspamd_config *cfg) : cfg(cfg) {
		cm = COMPOSITE_MANAGER_FROM_PTR(cfg->composites_manager);
	}

	static char *map_read(char *chunk, int len,
				  struct map_cb_data *data,
				  gboolean _final) {

		if (data->cur_data == nullptr) {
			data->cur_data = data->prev_data;
			reinterpret_cast<map_cbdata *>(data->cur_data)->buf.clear();
		}

		auto *cbd = reinterpret_cast<map_cbdata *>(data->cur_data);

		cbd->buf.append(chunk, len);
		return nullptr;
	}

	static void
	map_fin(struct map_cb_data *data, void **target) {
		auto *cbd = reinterpret_cast<map_cbdata *>(data->cur_data);

		if (data->errored) {
			if (cbd) {
				cbd->buf.clear();
			}
		}
		else if (cbd != nullptr) {
			if (target) {
				*target = data->cur_data;
			}

			rspamd::string_foreach_line(cbd->buf, [&](std::string_view line) {
				auto [name_and_score, expr] = rspamd::string_split_on(line, ' ');
				auto [name, score] = rspamd::string_split_on(name_and_score, ':');

				if (!score.empty()) {
					/* I wish it was supported properly */
					//auto conv_res = std::from_chars(value->data(), value->size(), num);
					char numbuf[128], *endptr = nullptr;
					rspamd_strlcpy(numbuf, score.data(), MIN(score.size(), sizeof(numbuf)));
					auto num = g_ascii_strtod(numbuf, &endptr);

					if (fabs(num) >= G_MAXFLOAT || std::isnan(num)) {
						msg_err("invalid score for %*s", (int)name_and_score.size(), name_and_score.data());
						return;
					}

					auto ret = cbd->cm->add_composite(name, expr, true, num);

					if (ret == nullptr) {
						msg_err("cannot add composite %*s", (int)name_and_score.size(), name_and_score.data());
						return;
					}
				}
				else {
					msg_err("missing score for %*s", (int)name_and_score.size(), name_and_score.data());
					return;
				}
			});

		}
		else {
			msg_err ("no data read for composites map");
		}
	}

	static void
	map_dtor (struct map_cb_data *data) {
		auto *cbd = reinterpret_cast<map_cbdata *>(data->cur_data);

		if (cbd) {
			delete cbd;
		}
	}
};

}


void*
rspamd_composites_manager_create(struct rspamd_config *cfg)
{
	auto *cm = new rspamd::composites::composites_manager(cfg);

	return reinterpret_cast<void *>(cm);
}


gsize
rspamd_composites_manager_nelts(void *ptr)
{
	return COMPOSITE_MANAGER_FROM_PTR(ptr)->size();
}

void*
rspamd_composites_manager_add_from_ucl(void *cm, const char *sym, const ucl_object_t *obj)
{
	return reinterpret_cast<void *>(COMPOSITE_MANAGER_FROM_PTR(cm)->add_composite(sym, obj, false));
}

void*
rspamd_composites_manager_add_from_string(void *cm, const char *sym, const char *expr)
{
	return reinterpret_cast<void *>(COMPOSITE_MANAGER_FROM_PTR(cm)->add_composite(sym, expr, false));
}

void*
rspamd_composites_manager_add_from_ucl_silent(void *cm, const char *sym, const ucl_object_t *obj)
{
	return reinterpret_cast<void *>(COMPOSITE_MANAGER_FROM_PTR(cm)->add_composite(sym, obj, true));
}

void*
rspamd_composites_manager_add_from_string_silent(void *cm, const char *sym, const char *expr)
{
	return reinterpret_cast<void *>(COMPOSITE_MANAGER_FROM_PTR(cm)->add_composite(sym, expr, true));
}



bool
rspamd_composites_add_map_handlers(const ucl_object_t *obj, struct rspamd_config *cfg)
{
	auto **pcbdata = rspamd_mempool_alloc_type(cfg->cfg_pool, rspamd::composites::map_cbdata *);
	auto *cbdata = new rspamd::composites::map_cbdata{cfg};
	*pcbdata = cbdata;

	if (struct rspamd_map *m; (m = rspamd_map_add_from_ucl(cfg, obj, "composites map",
		rspamd::composites::map_cbdata::map_read, rspamd::composites::map_cbdata::map_fin,
		rspamd::composites::map_cbdata::map_dtor, (void **)pcbdata,
		nullptr, RSPAMD_MAP_DEFAULT)) == nullptr) {
		msg_err_config("cannot load composites map from %s", ucl_object_key(obj));
		return false;
	}

	return true;
}