/*
 * Copyright 2026 Vsevolod Stakhov
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

/*
 * The metric of a configuration (thresholds of actions, scores of symbols and
 * the symbols that are switched off) as dynamic configuration modules.
 *
 * Three modules are registered with the Lua registry, all of them with
 * subscriber keys (the entries are not described by any static section: the
 * subscribers know which actions and symbols exist) and without a static
 * configuration in the registry (the subscribers remember the static state of
 * every entry they change, so the effective values they get are the overrides):
 *
 *  - `actions`: `{["add header"] = 8.0, reject = 20}`: threshold of an action
 *    (both `add header` and `add_header` spellings are accepted);
 *  - `scores`: `{SYMBOL = 4.5}`: score of a symbol;
 *  - `symbols`: `{SYMBOL = {enabled = false}}`: a symbol that is not executed
 *    and does not insert its results.
 *
 * An override has the priority that the legacy dynamic configuration used (3), and it is
 * compared with the priority of the definition in the configuration the same way for actions
 * and for symbols: an override replaces what the configuration says with a lower priority (the
 * main file 0, `local.d` 1) or with the same one, but not what has a higher priority, for
 * example `override.d` (10). Such an entry is not applied: a lenient update (see below) skips it
 * with a warning, a strict one (a write of the controller) is rejected with an error that says so.
 *
 * Entries that the subscribers cannot apply because of the state of the configuration (an unknown
 * symbol or action: a plugin is disabled now, a symbol was renamed) are treated the same way. A
 * malformed entry (a threshold that is not a number) always rejects the update.
 *
 * An entry that disappears from the overrides gets its static state back, but
 * only if it still holds what the override has set: a value that somebody else
 * has written in the meantime (a map reload, a higher priority update) is kept.
 */

#include "config.h"
#include "cfg_dynamic.h"
#include "cfg_file.h"
#include "cfg_file_private.h"
#include "rspamd_symcache.h"
#include "libserver/logger.h"
#include "libutil/mem_pool.h"
#include "libutil/cxx/hash_util.hxx"
#include "contrib/ankerl/unordered_dense.h"

#include <cmath>
#include <string>
#include <vector>

namespace {

/* The priority of dynamic values (the legacy dynamic configuration used the same one) */
constexpr const unsigned int dynconf_priority = 3;
constexpr const char *const metric_state_var = "dynconf_metric_state";

struct saved_action {
	double threshold;
	int flags;
	unsigned int priority;
	/* The threshold that the override has set */
	double applied;
};

struct saved_score {
	double score;
	unsigned int priority;
	unsigned int flags;
	/* The score that the override has set */
	double applied;
};

/*
 * The score that is in effect for a symbol. `weight_ptr` is what the scan reads,
 * and it is not always the same as `score`: a symbol that was added by
 * `unknown_weight` has a zero `score` and a `weight_ptr` that points to the
 * weight of the cache item
 */
auto symbol_score(const struct rspamd_symbol *sym) -> double
{
	return sym->weight_ptr != nullptr ? *sym->weight_ptr : sym->score;
}

void set_symbol_score(struct rspamd_symbol *sym, double score)
{
	if (sym->weight_ptr != nullptr) {
		*sym->weight_ptr = score;
	}
	sym->score = score;
}

template<typename T>
using name_map = ankerl::unordered_dense::map<std::string, T,
											  rspamd::smart_str_hash, rspamd::smart_str_equal>;

/* The static state of what has been changed, per configuration */
struct metric_state {
	name_map<saved_action> actions;
	name_map<saved_score> scores;
	ankerl::unordered_dense::set<std::string, rspamd::smart_str_hash, rspamd::smart_str_equal> disabled;
};

auto get_state(struct rspamd_config *cfg) -> metric_state *
{
	return static_cast<metric_state *>(rspamd_mempool_get_variable(cfg->cfg_pool, metric_state_var));
}

void state_dtor(void *p)
{
	delete static_cast<metric_state *>(p);
}

void set_error(GError **err, const std::string &msg)
{
	g_set_error(err, g_quark_from_static_string("dynconf"), EINVAL, "%s", msg.c_str());
}

/*
 * An entry that cannot be applied because of the state of the configuration: skipped (and reported)
 * by a lenient update. Returns true if the subscriber has to carry on with the other entries, false
 * if the update is rejected (`err` is set to `reason` then)
 */
auto skip_or_reject(struct rspamd_dynconf_apply_info *info, const char *module,
					const char *key, const std::string &reason, GError **err) -> bool
{
	if (rspamd_dynconf_apply_skip(info, module, key, reason.c_str())) {
		return true;
	}

	set_error(err, reason);

	return false;
}

/* Why an entry that is defined with a higher priority cannot be changed */
auto masked_reason(const char *what, const std::string &name, unsigned int priority) -> std::string
{
	return std::string{"the "} + what + " " + name + " is defined with the priority " +
		   std::to_string(priority) + " (override.d, for example), which is higher than the priority " +
		   "of the dynamic configuration (" + std::to_string(dynconf_priority) +
		   "): it cannot be changed dynamically";
}

/* Returns the canonical name of an action (`add_header` -> `add header`) */
auto canonical_action_name(const char *name) -> std::string
{
	enum rspamd_action_type type;

	if (rspamd_action_from_str(name, &type) && type != METRIC_ACTION_CUSTOM) {
		return rspamd_action_to_str(type);
	}

	return name;
}

auto is_number(const ucl_object_t *obj) -> bool
{
	return obj != nullptr && (ucl_object_type(obj) == UCL_INT || ucl_object_type(obj) == UCL_FLOAT);
}

/*
 * Iterates over the entries of an override object. A missing object, or an empty
 * one (a Lua table without entries becomes an empty array), has no entries.
 * Returns false (and the error) if the object is not an object
 */
template<typename Func>
auto foreach_entry(const ucl_object_t *values, GError **err, Func &&func) -> bool
{
	if (values == nullptr) {
		return true;
	}

	if (ucl_object_type(values) != UCL_OBJECT) {
		if (ucl_object_type(values) == UCL_ARRAY && ucl_array_size(values) == 0) {
			return true;
		}

		g_set_error(err, g_quark_from_static_string("dynconf"), EINVAL,
					"the values must be an object");

		return false;
	}

	ucl_object_iter_t it = nullptr;
	const ucl_object_t *cur;

	while ((cur = ucl_object_iterate(values, &it, true)) != nullptr) {
		if (!func(cur)) {
			return false;
		}
	}

	return true;
}

/* actions ------------------------------------------------------------------ */

struct wanted_action {
	std::string name;
	double threshold;
	struct rspamd_action *act;
};

gboolean
actions_apply(struct rspamd_config *cfg, const char *module,
			  const ucl_object_t *values, void *ud,
			  struct rspamd_dynconf_apply_info *info, GError **err)
{
	auto *st = static_cast<metric_state *>(ud);
	std::vector<wanted_action> wanted;
	name_map<bool> seen;

	auto valid = foreach_entry(values, err, [&](const ucl_object_t *cur) -> bool {
		const char *key = ucl_object_key(cur);

		if (key == nullptr) {
			g_set_error(err, g_quark_from_static_string("dynconf"), EINVAL, "an action has no name");
			return false;
		}

		if (!is_number(cur) || !std::isfinite(ucl_object_todouble(cur))) {
			set_error(err, std::string{"the threshold of the action "} + key + " must be a number");
			return false;
		}

		auto name = canonical_action_name(key);
		auto *act = rspamd_config_get_action(cfg, name.c_str());

		if (act == nullptr) {
			return skip_or_reject(info, module, key, std::string{"unknown action "} + key, err);
		}

		if (act->priority > dynconf_priority) {
			return skip_or_reject(info, module, key,
								  masked_reason("threshold of the action", name, act->priority), err);
		}

		if (!seen.emplace(name, true).second) {
			set_error(err, "the action " + name + " is given twice (with different spellings)");
			return false;
		}

		wanted.push_back({std::move(name), ucl_object_todouble(cur), act});

		return true;
	});

	if (!valid) {
		return FALSE;
	}

	auto changed = false;

	for (const auto &w: wanted) {
		auto sit = st->actions.find(w.name);

		if (sit == st->actions.end()) {
			sit = st->actions.emplace(w.name, saved_action{w.act->threshold, w.act->flags,
														   w.act->priority, w.threshold})
					  .first;
		}
		else {
			sit->second.applied = w.threshold;
		}

		if (w.act->threshold != w.threshold || (w.act->flags & RSPAMD_ACTION_NO_THRESHOLD) ||
			w.act->priority != dynconf_priority) {
			msg_info_config("dynamic configuration: set the threshold of the action %s to %.2f "
							"(it was %.2f)",
							w.name.c_str(), w.threshold, w.act->threshold);
			w.act->threshold = w.threshold;
			w.act->flags &= ~RSPAMD_ACTION_NO_THRESHOLD;
			w.act->priority = dynconf_priority;
			changed = true;
		}
	}

	/* Whatever has no override anymore gets its static state back */
	std::vector<std::string> restore;

	for (const auto &kv: st->actions) {
		if (!seen.contains(kv.first)) {
			restore.push_back(kv.first);
		}
	}

	for (const auto &name: restore) {
		auto *act = rspamd_config_get_action(cfg, name.c_str());
		const auto saved = st->actions.find(name)->second;

		if (act != nullptr) {
			if (act->priority == dynconf_priority && act->threshold == saved.applied &&
				!(act->flags & RSPAMD_ACTION_NO_THRESHOLD)) {
				msg_info_config("dynamic configuration: restore the threshold of the action %s to %.2f",
								name.c_str(), saved.threshold);
				act->threshold = saved.threshold;
				act->flags = saved.flags;
				act->priority = saved.priority;
				changed = true;
			}
			else {
				msg_info_config("dynamic configuration: the action %s has been changed by somebody else "
								"(threshold %.2f), keep it",
								name.c_str(), act->threshold);
			}
		}

		st->actions.erase(name);
	}

	if (changed) {
		rspamd_config_actions_resort(cfg);
	}

	return TRUE;
}

/* scores ------------------------------------------------------------------- */

struct wanted_score {
	std::string name;
	double score;
	struct rspamd_symbol *sym;
};

gboolean
scores_apply(struct rspamd_config *cfg, const char *module,
			 const ucl_object_t *values, void *ud,
			 struct rspamd_dynconf_apply_info *info, GError **err)
{
	auto *st = static_cast<metric_state *>(ud);
	std::vector<wanted_score> wanted;
	name_map<bool> seen;

	auto valid = foreach_entry(values, err, [&](const ucl_object_t *cur) -> bool {
		const char *key = ucl_object_key(cur);

		if (key == nullptr) {
			g_set_error(err, g_quark_from_static_string("dynconf"), EINVAL, "a symbol has no name");
			return false;
		}

		if (!is_number(cur) || !std::isfinite(ucl_object_todouble(cur))) {
			set_error(err, std::string{"the score of the symbol "} + key + " must be a number");
			return false;
		}

		auto *sym = reinterpret_cast<struct rspamd_symbol *>(g_hash_table_lookup(cfg->symbols, key));

		if (sym == nullptr) {
			return skip_or_reject(info, module, key, std::string{"unknown symbol "} + key, err);
		}

		if (sym->priority > dynconf_priority) {
			return skip_or_reject(info, module, key,
								  masked_reason("score of the symbol", key, sym->priority), err);
		}

		seen.emplace(key, true);
		wanted.push_back({key, ucl_object_todouble(cur), sym});

		return true;
	});

	if (!valid) {
		return FALSE;
	}

	for (const auto &w: wanted) {
		auto *sym = w.sym;
		auto sit = st->scores.find(w.name);

		if (sit == st->scores.end()) {
			sit = st->scores.emplace(w.name, saved_score{symbol_score(sym), sym->priority, sym->flags, w.score})
					  .first;
		}
		else {
			sit->second.applied = w.score;
		}

		if (symbol_score(sym) != w.score || sym->priority != dynconf_priority ||
			(sym->flags & RSPAMD_SYMBOL_FLAG_UNSCORED)) {
			msg_info_config("dynamic configuration: set the score of the symbol %s to %.2f (it was %.2f)",
							w.name.c_str(), w.score, symbol_score(sym));
			set_symbol_score(sym, w.score);
			sym->priority = dynconf_priority;
			sym->flags &= ~RSPAMD_SYMBOL_FLAG_UNSCORED;
		}
	}

	std::vector<std::string> restore;

	for (const auto &kv: st->scores) {
		if (!seen.contains(kv.first)) {
			restore.push_back(kv.first);
		}
	}

	for (const auto &name: restore) {
		auto *sym = reinterpret_cast<struct rspamd_symbol *>(g_hash_table_lookup(cfg->symbols, name.c_str()));
		const auto saved = st->scores.find(name)->second;

		if (sym != nullptr) {
			if (sym->priority == dynconf_priority && symbol_score(sym) == saved.applied) {
				msg_info_config("dynamic configuration: restore the score of the symbol %s to %.2f",
								name.c_str(), saved.score);
				set_symbol_score(sym, saved.score);
				sym->priority = saved.priority;
				sym->flags = (sym->flags & ~RSPAMD_SYMBOL_FLAG_UNSCORED) |
							 (saved.flags & RSPAMD_SYMBOL_FLAG_UNSCORED);
			}
			else {
				msg_info_config("dynamic configuration: the symbol %s has been changed by somebody else "
								"(score %.2f), keep it",
								name.c_str(), symbol_score(sym));
			}
		}

		st->scores.erase(name);
	}

	return TRUE;
}

/* symbols ------------------------------------------------------------------ */

gboolean
symbols_apply(struct rspamd_config *cfg, const char *module,
			  const ucl_object_t *values, void *ud,
			  struct rspamd_dynconf_apply_info *info, GError **err)
{
	auto *st = static_cast<metric_state *>(ud);
	ankerl::unordered_dense::set<std::string, rspamd::smart_str_hash, rspamd::smart_str_equal> want_disabled;

	if (cfg->cache == nullptr) {
		g_set_error(err, g_quark_from_static_string("dynconf"), EINVAL,
					"the symbols cache is not available");
		return FALSE;
	}

	auto valid = foreach_entry(values, err, [&](const ucl_object_t *cur) -> bool {
		const char *key = ucl_object_key(cur);

		if (key == nullptr) {
			g_set_error(err, g_quark_from_static_string("dynconf"), EINVAL, "a symbol has no name");
			return false;
		}

		if (ucl_object_type(cur) != UCL_OBJECT) {
			set_error(err, std::string{"the settings of the symbol "} + key + " must be an object");
			return false;
		}

		if (rspamd_symcache_find_symbol(cfg->cache, key) < 0) {
			return skip_or_reject(info, module, key, std::string{"unknown symbol "} + key, err);
		}

		const auto *enabled = ucl_object_lookup(cur, "enabled");

		if (enabled != nullptr) {
			if (ucl_object_type(enabled) != UCL_BOOLEAN) {
				set_error(err, std::string{"`enabled` of the symbol "} + key + " must be a boolean");
				return false;
			}

			/* `true` is what an absent override means */
			if (!ucl_object_toboolean(enabled)) {
				want_disabled.emplace(std::string{key});
			}
		}

		return true;
	});

	if (!valid) {
		return FALSE;
	}

	for (const auto &name: want_disabled) {
		if (!st->disabled.contains(name)) {
			msg_info_config("dynamic configuration: switch off the symbol %s", name.c_str());
			rspamd_symcache_set_symbol_enabled_runtime(cfg->cache, name.c_str(), FALSE);
			st->disabled.emplace(name);
		}
	}

	std::vector<std::string> restore;

	for (const auto &name: st->disabled) {
		if (!want_disabled.contains(name)) {
			restore.push_back(name);
		}
	}

	for (const auto &name: restore) {
		msg_info_config("dynamic configuration: switch on the symbol %s", name.c_str());
		rspamd_symcache_set_symbol_enabled_runtime(cfg->cache, name.c_str(), TRUE);
		st->disabled.erase(name);
	}

	return TRUE;
}

}// namespace

extern "C" {

gboolean
rspamd_dynconf_register_metric_modules(struct rspamd_config *cfg)
{
	static const char *const actions_paths[] = {"*", nullptr};
	static const char *const symbols_paths[] = {"*.enabled", nullptr};
	const auto flags = RSPAMD_DYNCONF_MODULE_SUBSCRIBER_KEYS | RSPAMD_DYNCONF_MODULE_NO_STATIC;

	if (get_state(cfg) != nullptr) {
		/* Registered already */
		return TRUE;
	}

	auto *st = new metric_state();

	rspamd_mempool_set_variable(cfg->cfg_pool, metric_state_var, st, state_dtor);

	auto ret = rspamd_dynconf_register_module_flags(cfg, "actions", actions_paths,
													actions_apply, st, flags);
	ret = rspamd_dynconf_register_module_flags(cfg, "scores", actions_paths,
											   scores_apply, st, flags) &&
		  ret;
	ret = rspamd_dynconf_register_module_flags(cfg, "symbols", symbols_paths,
											   symbols_apply, st, flags) &&
		  ret;

	return ret;
}

gboolean
rspamd_dynconf_metric_baseline(struct rspamd_config *cfg,
							   const char *module,
							   const char *key,
							   double *value,
							   gboolean *overridden,
							   gboolean *known)
{
	auto *st = get_state(cfg);
	auto is_overridden = false;
	double result;

	if (overridden) {
		*overridden = FALSE;
	}

	if (known) {
		*known = FALSE;
	}

	if (module == nullptr || key == nullptr) {
		return FALSE;
	}

	if (strcmp(module, "actions") == 0) {
		auto name = canonical_action_name(key);
		auto *act = rspamd_config_get_action(cfg, name.c_str());

		if (act == nullptr) {
			return FALSE;
		}

		if (known) {
			*known = TRUE;
		}

		auto threshold = act->threshold;
		auto flags = act->flags;

		if (st != nullptr) {
			auto it = st->actions.find(name);

			if (it != st->actions.end()) {
				threshold = it->second.threshold;
				flags = it->second.flags;
				is_overridden = true;
			}
		}

		result = (flags & RSPAMD_ACTION_NO_THRESHOLD) ? NAN : threshold;
	}
	else if (strcmp(module, "scores") == 0) {
		auto *sym = reinterpret_cast<struct rspamd_symbol *>(g_hash_table_lookup(cfg->symbols, key));

		if (sym == nullptr) {
			return FALSE;
		}

		if (known) {
			*known = TRUE;
		}

		result = symbol_score(sym);

		if (st != nullptr) {
			auto it = st->scores.find(std::string_view{key});

			if (it != st->scores.end()) {
				result = it->second.score;
				is_overridden = true;
			}
		}
	}
	else if (strcmp(module, "symbols") == 0) {
		/* A symbol has no numeric state: only whether it is known and switched off now */
		if (cfg->cache == nullptr || rspamd_symcache_find_symbol(cfg->cache, key) < 0) {
			return FALSE;
		}

		if (known) {
			*known = TRUE;
		}

		if (overridden && st != nullptr) {
			*overridden = st->disabled.contains(std::string{key});
		}

		return FALSE;
	}
	else {
		return FALSE;
	}

	if (overridden) {
		*overridden = is_overridden;
	}

	if (std::isnan(result)) {
		return FALSE;
	}

	if (value) {
		*value = result;
	}

	return TRUE;
}

gboolean
rspamd_dynconf_metric_masked(struct rspamd_config *cfg,
							 const char *module,
							 const char *key)
{
	if (cfg == nullptr || module == nullptr || key == nullptr) {
		return FALSE;
	}

	auto *st = get_state(cfg);

	if (strcmp(module, "actions") == 0) {
		auto name = canonical_action_name(key);
		auto *act = rspamd_config_get_action(cfg, name.c_str());

		if (act == nullptr) {
			return FALSE;
		}

		auto priority = act->priority;

		if (st != nullptr) {
			auto it = st->actions.find(name);

			if (it != st->actions.end()) {
				priority = it->second.priority;
			}
		}

		return priority > dynconf_priority;
	}
	else if (strcmp(module, "scores") == 0) {
		auto *sym = reinterpret_cast<struct rspamd_symbol *>(g_hash_table_lookup(cfg->symbols, key));

		if (sym == nullptr) {
			return FALSE;
		}

		auto priority = sym->priority;

		if (st != nullptr) {
			auto it = st->scores.find(std::string_view{key});

			if (it != st->scores.end()) {
				priority = it->second.priority;
			}
		}

		return priority > dynconf_priority;
	}

	return FALSE;
}
}
