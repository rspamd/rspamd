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
 * Called after every accepted update of a module.
 * `dyn_values` is a UCL object that mirrors the module configuration and
 * contains the EFFECTIVE values of the dynamic paths only (the override if
 * present, otherwise the static value, otherwise the path is absent, which
 * means "use the module default"). Wildcards in paths are expanded, so for a
 * pattern `rule.*.max_score` the object looks like
 * `{rule = {name1 = {max_score = 1.0}}}`.
 * The object is owned by the caller: C modules MUST copy any strings they
 * want to keep.
 * @return TRUE to accept the update, FALSE (and `err`) to reject it
 */
typedef gboolean (*rspamd_dynconf_apply_cb)(struct rspamd_config *cfg,
											const char *module,
											const ucl_object_t *dyn_values,
											void *ud,
											GError **err);

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
 * Delivers `values` to the subscriber of `module` (used by the Lua binding,
 * also useful for tests).
 * @return TRUE if the subscriber accepted the values
 */
gboolean rspamd_dynconf_notify(struct rspamd_config *cfg,
							   const char *module,
							   const ucl_object_t *values,
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
