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

#include "lua/lua_common.h"
#include "settings_merge.h"
#include "cfg_file.h"
#include "contrib/ankerl/unordered_dense.h"

#include <algorithm>
#include <string>
#include <vector>

#define msg_debug_settings(...) rspamd_conditional_debug_fast(NULL, NULL,                                           \
															  rspamd_settings_merge_log_id, "settings_merge", NULL, \
															  G_STRFUNC,                                            \
															  __VA_ARGS__)

INIT_LOG_MODULE(settings_merge)

/**
 * Tracks per-symbol enable/disable provenance for conflict resolution
 */
struct symbol_resolution {
	enum source_type {
		SOURCE_SYMBOL, /* Explicit per-symbol entry */
		SOURCE_GROUP,  /* Expanded from a group */
	};

	source_type source;
	enum rspamd_settings_layer layer;
	bool is_enabled;
};

struct layer_entry {
	enum rspamd_settings_layer level;
	std::string name;
	uint32_t settings_id;
	const ucl_object_t *settings;

	layer_entry(enum rspamd_settings_layer _level, std::string _name,
				uint32_t _id, const ucl_object_t *_settings)
		: level(_level), name(std::move(_name)), settings_id(_id),
		  settings(ucl_object_ref(_settings))
	{
	}
	~layer_entry()
	{
		if (settings) {
			ucl_object_unref(const_cast<ucl_object_t *>(settings));
		}
	}
	layer_entry(const layer_entry &) = delete;
	layer_entry &operator=(const layer_entry &) = delete;
	layer_entry(layer_entry &&other) noexcept
		: level(other.level), name(std::move(other.name)),
		  settings_id(other.settings_id), settings(other.settings)
	{
		other.settings = nullptr;
	}
	layer_entry &operator=(layer_entry &&other) noexcept
	{
		if (this != &other) {
			if (settings) {
				ucl_object_unref(const_cast<ucl_object_t *>(settings));
			}
			level = other.level;
			name = std::move(other.name);
			settings_id = other.settings_id;
			settings = other.settings;
			other.settings = nullptr;
		}
		return *this;
	}
};

struct rspamd_settings_merge_ctx {
	rspamd_mempool_t *pool;
	struct rspamd_config *cfg;
	std::vector<layer_entry> layers;
};


extern "C" struct rspamd_settings_merge_ctx *
rspamd_settings_merge_ctx_create(rspamd_mempool_t *pool, struct rspamd_config *cfg)
{
	auto *ctx = new rspamd_settings_merge_ctx();
	ctx->pool = pool;
	ctx->cfg = cfg;

	/* Register destructor in the pool */
	rspamd_mempool_add_destructor(pool, [](void *p) {
									  auto *c = static_cast<rspamd_settings_merge_ctx *>(p);
									  delete c; }, ctx);

	return ctx;
}

extern "C" void
rspamd_settings_merge_add_layer(struct rspamd_settings_merge_ctx *ctx,
								enum rspamd_settings_layer level,
								const char *name,
								uint32_t settings_id,
								const ucl_object_t *settings)
{
	if (!ctx || !settings) {
		return;
	}

	ctx->layers.emplace_back(level,
							 name ? std::string(name) : std::string("unknown"),
							 settings_id,
							 settings);

	msg_debug_settings("added layer %d (%s) id=%ud", (int) level, name, settings_id);
}


/**
 * Merge "override" fields: per-key, higher layer wins
 * Used for: actions, scores, variables
 */
static void
merge_override_object(ucl_object_t *result, const char *key,
					  const std::vector<layer_entry> &layers)
{
	ucl_object_t *merged = nullptr;

	for (const auto &layer: layers) {
		const auto *obj = ucl_object_lookup(layer.settings, key);
		if (obj && ucl_object_type(obj) == UCL_OBJECT) {
			if (!merged) {
				merged = ucl_object_copy(obj);
			}
			else {
				/* Higher layer overrides per-key */
				ucl_object_iter_t it = nullptr;
				const ucl_object_t *cur;
				while ((cur = ucl_object_iterate(obj, &it, true)) != nullptr) {
					/* Replace existing key or insert new */
					ucl_object_replace_key(merged,
										   ucl_object_ref(cur),
										   ucl_object_key(cur),
										   strlen(ucl_object_key(cur)),
										   true);
				}
			}
		}
	}

	if (merged) {
		ucl_object_insert_key(result, merged, key, strlen(key), false);
	}
}

/**
 * Expand a group name to its symbol names using the config
 */
static void
expand_group_symbols(struct rspamd_config *cfg, const char *group_name,
					 ankerl::unordered_dense::map<std::string, symbol_resolution> &map,
					 enum rspamd_settings_layer layer, bool is_enabled)
{
	if (!cfg->groups) {
		return;
	}

	auto *gr = static_cast<struct rspamd_symbols_group *>(
		g_hash_table_lookup(cfg->groups, group_name));

	if (gr && gr->symbols) {
		GHashTableIter it;
		gpointer k, v;
		g_hash_table_iter_init(&it, gr->symbols);

		while (g_hash_table_iter_next(&it, &k, &v)) {
			auto sym_name = std::string(static_cast<const char *>(k));

			auto existing = map.find(sym_name);
			if (existing == map.end()) {
				map[sym_name] = symbol_resolution{
					symbol_resolution::SOURCE_GROUP,
					layer,
					is_enabled};
			}
			else {
				/* Conflict resolution: symbol > group, then higher layer, then disable wins */
				auto &cur = existing->second;
				if (cur.source == symbol_resolution::SOURCE_SYMBOL) {
					/* Existing is per-symbol, keep it */
					continue;
				}
				if (layer > cur.layer) {
					cur.layer = layer;
					cur.is_enabled = is_enabled;
				}
				else if (layer == cur.layer && !is_enabled) {
					/* Same layer, disable wins */
					cur.is_enabled = false;
				}
			}
		}
	}
}

/**
 * Process symbols_enabled/symbols_disabled/groups_enabled/groups_disabled
 * from all layers, resolving conflicts
 */
static void
merge_symbol_controls(ucl_object_t *result, struct rspamd_config *cfg,
					  const std::vector<layer_entry> &layers)
{
	ankerl::unordered_dense::map<std::string, symbol_resolution> resolutions;

	for (const auto &layer: layers) {
		/* symbols_enabled: explicit per-symbol enable */
		const auto *se = ucl_object_lookup(layer.settings, "symbols_enabled");
		if (se) {
			ucl_object_iter_t it = nullptr;
			const ucl_object_t *cur;
			while ((cur = ucl_object_iterate(se, &it, true)) != nullptr) {
				auto name = std::string(ucl_object_tostring(cur));
				auto existing = resolutions.find(name);
				if (existing == resolutions.end()) {
					resolutions[name] = symbol_resolution{
						symbol_resolution::SOURCE_SYMBOL,
						layer.level,
						true};
				}
				else {
					auto &r = existing->second;
					/* Per-symbol source always wins over group source */
					if (r.source == symbol_resolution::SOURCE_GROUP ||
						layer.level > r.layer) {
						r.source = symbol_resolution::SOURCE_SYMBOL;
						r.layer = layer.level;
						r.is_enabled = true;
					}
				}
			}
		}

		/* symbols_disabled: explicit per-symbol disable */
		const auto *sd = ucl_object_lookup(layer.settings, "symbols_disabled");
		if (sd) {
			ucl_object_iter_t it = nullptr;
			const ucl_object_t *cur;
			while ((cur = ucl_object_iterate(sd, &it, true)) != nullptr) {
				auto name = std::string(ucl_object_tostring(cur));
				auto existing = resolutions.find(name);
				if (existing == resolutions.end()) {
					resolutions[name] = symbol_resolution{
						symbol_resolution::SOURCE_SYMBOL,
						layer.level,
						false};
				}
				else {
					auto &r = existing->second;
					if (r.source == symbol_resolution::SOURCE_GROUP) {
						/* Per-symbol wins over group */
						r.source = symbol_resolution::SOURCE_SYMBOL;
						r.layer = layer.level;
						r.is_enabled = false;
					}
					else if (layer.level > r.layer) {
						r.layer = layer.level;
						r.is_enabled = false;
					}
					else if (layer.level == r.layer &&
							 r.source == symbol_resolution::SOURCE_SYMBOL) {
						/* Same layer, same specificity: disable wins */
						r.is_enabled = false;
					}
				}
			}
		}

		/* groups_enabled: expand to per-symbol with group source */
		const auto *ge = ucl_object_lookup(layer.settings, "groups_enabled");
		if (ge) {
			ucl_object_iter_t it = nullptr;
			const ucl_object_t *cur;
			while ((cur = ucl_object_iterate(ge, &it, true)) != nullptr) {
				expand_group_symbols(cfg, ucl_object_tostring(cur),
									 resolutions, layer.level, true);
			}
		}

		/* groups_disabled: expand to per-symbol with group source */
		const auto *gd = ucl_object_lookup(layer.settings, "groups_disabled");
		if (gd) {
			ucl_object_iter_t it = nullptr;
			const ucl_object_t *cur;
			while ((cur = ucl_object_iterate(gd, &it, true)) != nullptr) {
				expand_group_symbols(cfg, ucl_object_tostring(cur),
									 resolutions, layer.level, false);
			}
		}
	}

	/* Build final symbols_enabled and symbols_disabled arrays */
	ucl_object_t *enabled_arr = nullptr;
	ucl_object_t *disabled_arr = nullptr;

	for (const auto &[name, res]: resolutions) {
		if (res.is_enabled) {
			if (!enabled_arr) {
				enabled_arr = ucl_object_typed_new(UCL_ARRAY);
			}
			ucl_array_append(enabled_arr,
							 ucl_object_fromstring(name.c_str()));
		}
		else {
			if (!disabled_arr) {
				disabled_arr = ucl_object_typed_new(UCL_ARRAY);
			}
			ucl_array_append(disabled_arr,
							 ucl_object_fromstring(name.c_str()));
		}
	}

	if (enabled_arr) {
		ucl_object_insert_key(result, enabled_arr, "symbols_enabled", 0, false);
	}
	if (disabled_arr) {
		ucl_object_insert_key(result, disabled_arr, "symbols_disabled", 0, false);
	}
}

/**
 * Merge scalar fields where highest layer wins
 */
static void
merge_scalar_field(ucl_object_t *result, const char *key,
				   const std::vector<layer_entry> &layers)
{
	const ucl_object_t *winner = nullptr;

	for (const auto &layer: layers) {
		const auto *obj = ucl_object_lookup(layer.settings, key);
		if (obj) {
			winner = obj;
		}
	}

	if (winner) {
		ucl_object_insert_key(result, ucl_object_ref(winner),
							  key, strlen(key), false);
	}
}

/**
 * Merge boolean fields where any layer setting it to true wins
 */
static void
merge_boolean_any(ucl_object_t *result, const char *key,
				  const std::vector<layer_entry> &layers)
{
	for (const auto &layer: layers) {
		const auto *obj = ucl_object_lookup(layer.settings, key);
		if (obj && ucl_object_toboolean(obj)) {
			ucl_object_insert_key(result, ucl_object_frombool(true),
								  key, strlen(key), false);
			return;
		}
	}
}

/**
 * Merge array fields with union semantics
 */
static void
merge_array_union(ucl_object_t *result, const char *key,
				  const std::vector<layer_entry> &layers)
{
	ankerl::unordered_dense::set<std::string> seen;
	ucl_object_t *merged = nullptr;

	for (const auto &layer: layers) {
		const auto *arr = ucl_object_lookup(layer.settings, key);
		if (arr) {
			ucl_object_iter_t it = nullptr;
			const ucl_object_t *cur;
			while ((cur = ucl_object_iterate(arr, &it, true)) != nullptr) {
				auto val = std::string(ucl_object_tostring(cur));
				if (seen.insert(val).second) {
					if (!merged) {
						merged = ucl_object_typed_new(UCL_ARRAY);
					}
					ucl_array_append(merged, ucl_object_ref(cur));
				}
			}
		}
	}

	if (merged) {
		ucl_object_insert_key(result, merged, key, strlen(key), false);
	}
}

extern "C" ucl_object_t *
rspamd_settings_merge_finalize(struct rspamd_settings_merge_ctx *ctx)
{
	if (!ctx || ctx->layers.empty()) {
		return nullptr;
	}

	/* Sort layers by priority (lowest first, so higher layers override) */
	std::sort(ctx->layers.begin(), ctx->layers.end(),
			  [](const layer_entry &a, const layer_entry &b) {
				  return a.level < b.level;
			  });

	/* Single layer: just ref and return */
	if (ctx->layers.size() == 1) {
		auto *result = ucl_object_ref(ctx->layers[0].settings);
		msg_debug_settings("single layer %s, no merge needed", ctx->layers[0].name.c_str());
		return const_cast<ucl_object_t *>(result);
	}

	auto *result = ucl_object_typed_new(UCL_OBJECT);

	/* Override fields: per-key, higher layer wins */
	merge_override_object(result, "actions", ctx->layers);
	merge_override_object(result, "scores", ctx->layers);
	merge_override_object(result, "variables", ctx->layers);
	merge_override_object(result, "add_headers", ctx->layers);

	/* Symbol enable/disable with conflict resolution */
	merge_symbol_controls(result, ctx->cfg, ctx->layers);

	/* Scalar fields: highest layer wins */
	merge_scalar_field(result, "subject", ctx->layers);

	/* Boolean any: whitelist */
	merge_boolean_any(result, "whitelist", ctx->layers);

	/* Array union: flags, remove_headers */
	merge_array_union(result, "flags", ctx->layers);
	merge_array_union(result, "remove_headers", ctx->layers);

	/* Messages: per-category override (treat as override object) */
	merge_override_object(result, "messages", ctx->layers);

	/* Symbols to inject: union */
	merge_override_object(result, "symbols", ctx->layers);

	/* Build merge metadata */
	auto *meta = ucl_object_typed_new(UCL_ARRAY);
	for (const auto &layer: ctx->layers) {
		auto *entry = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(entry,
							  ucl_object_fromint(layer.level),
							  "layer", 0, false);
		ucl_object_insert_key(entry,
							  ucl_object_fromstring(layer.name.c_str()),
							  "name", 0, false);
		if (layer.settings_id) {
			ucl_object_insert_key(entry,
								  ucl_object_fromint(layer.settings_id),
								  "settings_id", 0, false);
		}
		ucl_array_append(meta, entry);
	}
	ucl_object_insert_key(result, meta, "_merge_info", 0, false);

	msg_debug_settings("merged %d layers", (int) ctx->layers.size());

	return result;
}
