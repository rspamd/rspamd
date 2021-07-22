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
#include "contrib/robin-hood/robin_hood.h"

#include "composites.h"
#include "composites_internal.hxx"
#include "libserver/cfg_file.h"
#include "libserver/logger.h"

namespace rspamd::composites {

static auto
composite_policy_from_str(const std::string_view &inp) -> enum rspamd_composite_policy
{
	const static robin_hood::unordered_flat_map<std::string_view,
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
composites_manager::add_composite(std::string_view composite_name, const ucl_object_t *obj) -> rspamd_composite *
{

	const auto *val = ucl_object_lookup(obj, "enabled");
	if (val != nullptr && !ucl_object_toboolean(val)) {
		msg_info_config ("composite %s is disabled", composite_name.data());
		return nullptr;
	}

	if (composites.contains(composite_name)) {
		msg_warn_config ("composite %s is redefined", composite_name.data());
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

	double score;
	val = ucl_object_lookup(obj, "score");
	if (val != nullptr && ucl_object_todouble_safe(val, &score)) {
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
		else {
			description = composite_expression;
		}

		rspamd_config_add_symbol(cfg, composite_name.data(), score,
				description, group,
				0,
				ucl_object_get_priority(obj), /* No +1 as it is default... */
				1);

		const auto *elt = ucl_object_lookup(obj, "groups");
		if (elt) {
			const ucl_object_t *cur_gr;
			auto *gr_it = ucl_object_iterate_new(elt);

			while ((cur_gr = ucl_object_iterate_safe(gr_it, true)) != nullptr) {
				rspamd_config_add_symbol_group(cfg, composite_name.data(),
						ucl_object_tostring(cur_gr));
			}

			ucl_object_iterate_free(gr_it);
		}
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
								  std::string_view composite_expression) -> rspamd_composite *
{
	GError *err = nullptr;
	rspamd_expression *expr = nullptr;

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

	return new_composite(composite_name, expr, composite_expression).get();
}

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
	return reinterpret_cast<void *>(COMPOSITE_MANAGER_FROM_PTR(cm)->add_composite(sym, obj));
}

void*
rspamd_composites_manager_add_from_string(void *cm, const char *sym, const char *expr)
{
	return reinterpret_cast<void *>(COMPOSITE_MANAGER_FROM_PTR(cm)->add_composite(sym, expr));
}
