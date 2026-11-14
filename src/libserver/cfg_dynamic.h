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

#ifndef RSPAMD_CFG_DYNAMIC_H
#define RSPAMD_CFG_DYNAMIC_H

#include "config.h"
#include "cfg_file.h"
#include "ucl.h"

#ifdef __cplusplus
extern "C" {
#endif

struct ev_loop;

/*
 * Dynamic configuration: the C side of the Lua registry (lualib/lua_dynconf.lua).
 *
 * The registry owns the data; this file provides
 *  - a subscription API for C modules (they get the effective values of
 *    the options they declared dynamic after every accepted update);
 *  - a generation counter bumped on every applied change;
 *  - a cheap per-task trigger for the "on access" update policy.
 *
 * All state is per configuration (and hence per worker): it dies with the
 * configuration on reload.
 */

/**
 * Flags of an update that is delivered to a subscriber
 */
enum rspamd_dynconf_apply_flags {
	/** A write (the controller): an entry that the subscriber cannot apply rejects the update */
	RSPAMD_DYNCONF_APPLY_STRICT = 0,
	/**
	 * Something that is delivered by a backend (a periodic or on-access check, the load at
	 * start, an offline load): an entry that the subscriber cannot apply because of the state of
	 * the configuration (the name is unknown now: a plugin was disabled, a symbol was renamed;
	 * a higher priority definition wins) is skipped and reported, and the rest is applied. It
	 * does not make the subscriber accept entries that are malformed.
	 */
	RSPAMD_DYNCONF_APPLY_LENIENT = (1u << 0),
	/**
	 * The update offers again what was delivered before (a periodic retry of the entries that were
	 * skipped, maybe the configuration has them now): the skipped entries are still reported to the
	 * caller, but not logged again
	 */
	RSPAMD_DYNCONF_APPLY_QUIET = (1u << 1),
};

/**
 * How an update is delivered to a subscriber. Created by the caller of
 * `rspamd_dynconf_notify`, the subscriber only reads `flags` and reports what it has skipped
 * through `rspamd_dynconf_apply_skip`.
 */
struct rspamd_dynconf_apply_info {
	unsigned int flags; /**< `enum rspamd_dynconf_apply_flags` */
	/**
	 * NULL terminated array of the keys (the entries of the module, as the `*` of its paths)
	 * that a lenient update must still validate strictly: the entries that a write changes
	 */
	const char *const *strict_keys;
	/** (out) the reasons of the entries that the subscriber has skipped (g_free'd strings), created on demand */
	GPtrArray *skipped;
};

/**
 * Called after every accepted update of a module.
 * `dyn_values` is a UCL object that mirrors the module configuration and
 * contains the EFFECTIVE values of the dynamic paths only (the override if
 * present, otherwise the static value, otherwise the path is absent, which
 * means "use the module default"). Wildcards in paths are expanded, so for a
 * pattern `rule.*.max_score` the object looks like
 * `{rule = {name1 = {max_score = 1.0}}}`.
 * The object is owned by the caller: C modules MUST copy any strings they
 * want to keep.
 * `info` is never NULL; subscribers that have nothing that can become stale (the
 * options of a plugin) ignore it.
 * @return TRUE to accept the update, FALSE (and `err`) to reject it
 */
typedef gboolean (*rspamd_dynconf_apply_cb)(struct rspamd_config *cfg,
											const char *module,
											const ucl_object_t *dyn_values,
											void *ud,
											struct rspamd_dynconf_apply_info *info,
											GError **err);

/**
 * To be called by a subscriber for an entry `key` that it cannot apply because of the state of the
 * configuration (not because the entry is malformed). In a lenient update (and for a key that is not
 * listed in `strict_keys`) the entry is skipped: the function logs a warning, remembers `reason` in
 * `info->skipped` and returns TRUE; the subscriber carries on with the other entries. Otherwise
 * it returns FALSE and the subscriber must reject the update (with an error that says `reason`).
 */
gboolean rspamd_dynconf_apply_skip(struct rspamd_dynconf_apply_info *info,
								   const char *module,
								   const char *key,
								   const char *reason);

/**
 * Registration flags of a C module
 */
enum rspamd_dynconf_module_flags {
	RSPAMD_DYNCONF_MODULE_DEFAULT = 0,
	/**
	 * A `*` segment of a dynamic path also matches keys that are absent from the
	 * static configuration: the subscriber validates them (and rejects the update
	 * when it does not know a key)
	 */
	RSPAMD_DYNCONF_MODULE_SUBSCRIBER_KEYS = (1u << 0),
	/**
	 * The module has no static configuration in the registry: the subscriber knows
	 * the static state itself, so the effective values it gets are the overrides
	 */
	RSPAMD_DYNCONF_MODULE_NO_STATIC = (1u << 1),
};

/**
 * Registers a C module with the Lua registry. The static configuration is the
 * configuration section named `module`.
 * Must be called from module_config (it is safe to call it again after a
 * reconfiguration: every configuration has its own state).
 * @param dynamic_paths NULL-terminated array of dotted path patterns (`*` matches one segment)
 * @param cb subscriber (may not be NULL)
 * @return TRUE if the module has been registered
 */
gboolean rspamd_dynconf_register_module(struct rspamd_config *cfg,
										const char *module,
										const char *const *dynamic_paths,
										rspamd_dynconf_apply_cb cb,
										void *ud);

/**
 * The same as `rspamd_dynconf_register_module` with `enum rspamd_dynconf_module_flags`
 */
gboolean rspamd_dynconf_register_module_flags(struct rspamd_config *cfg,
											  const char *module,
											  const char *const *dynamic_paths,
											  rspamd_dynconf_apply_cb cb,
											  void *ud,
											  unsigned int flags);

/**
 * Registers the modules that make the metric dynamic: `actions` (thresholds of
 * actions), `scores` (scores of symbols) and `symbols` (symbols that are switched
 * off at runtime). See cfg_dynamic_metric.cxx for the shape of the overrides.
 * Must be called once the configuration is loaded and the symbols cache exists.
 */
gboolean rspamd_dynconf_register_metric_modules(struct rspamd_config *cfg);

/**
 * Returns the static state of an entry of the `actions`, `scores` or `symbols` module (the one
 * the configuration had before any override was applied)
 * @param module `actions`, `scores` or `symbols`
 * @param key action name (any spelling) or symbol name
 * @param value (out) static threshold or score; for an action that is disabled
 *              (or not configured) the function returns FALSE
 * @param overridden (out, optional) TRUE if an override is applied to the entry now
 * @param known (out, optional) TRUE if the entry exists, even without a numeric static value
 *              (an action that is not configured has no threshold, but it can be given one)
 * @return TRUE if the entry is known and has a numeric static value (never for `symbols`)
 */
gboolean rspamd_dynconf_metric_baseline(struct rspamd_config *cfg,
										const char *module,
										const char *key,
										double *value,
										gboolean *overridden,
										gboolean *known);

/**
 * Tells whether an entry of the `actions` or `scores` module is defined with a priority that is
 * higher than the one of the dynamic configuration (`override.d`, for example), so that no
 * override can change it. An entry that is overridden now is judged by the priority of its static
 * definition. Always FALSE for an unknown entry and for the `symbols` module.
 */
gboolean rspamd_dynconf_metric_masked(struct rspamd_config *cfg,
									  const char *module,
									  const char *key);

/**
 * Delivers `values` to the subscriber of `module` (used by the Lua binding,
 * also useful for tests).
 * @param info how the update is delivered (NULL: strict); `info->skipped` is filled by the
 *             subscriber and owned by the caller
 * @return TRUE if the subscriber accepted the values
 */
gboolean rspamd_dynconf_notify(struct rspamd_config *cfg,
							   const char *module,
							   const ucl_object_t *values,
							   struct rspamd_dynconf_apply_info *info,
							   GError **err);

/**
 * Returns the generation counter: it is bumped on every applied change
 */
uint64_t rspamd_dynconf_generation(struct rspamd_config *cfg);

/**
 * Increases the generation counter (called by the Lua registry)
 */
void rspamd_dynconf_bump_generation(struct rspamd_config *cfg);

/**
 * Arms or disarms the per-task trigger. Used by the Lua binding.
 * @param when absolute time (as in `ev_time()`) after which the next task
 *             calls `cbref`; 0 (or a negative number) disarms the trigger
 * @param cbref a reference of the Lua function in the registry of
 *              `cfg->lua_state`, ownership is taken by this call. `LUA_NOREF`
 *              (or `LUA_REFNIL`) keeps the function that is already set
 */
void rspamd_dynconf_set_next_check(struct rspamd_config *cfg, double when, int cbref);

/**
 * Slow part of the trigger, do not call directly
 */
void rspamd_dynconf_run_check(struct rspamd_config *cfg,
							  struct ev_loop *loop,
							  double now);

/**
 * Cheap per-task trigger: if the trigger is armed and `now >= next_check`
 * calls the Lua check function. The function must not block: it starts an
 * asynchronous check and returns. When the trigger is disarmed (the default)
 * this is a single compare.
 */
static inline void
rspamd_dynconf_maybe_check(struct rspamd_config *cfg,
						   struct ev_loop *loop,
						   double now)
{
	if (cfg->dyn_next_check <= 0.0 || now < cfg->dyn_next_check) {
		return;
	}

	rspamd_dynconf_run_check(cfg, loop, now);
}

/**
 * Releases all the dynamic configuration state of `cfg`
 */
void rspamd_dynconf_free(struct rspamd_config *cfg);

#ifdef __cplusplus
}
#endif

#endif
