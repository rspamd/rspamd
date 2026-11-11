/*-
 * Copyright 2020 Vsevolod Stakhov
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
#ifndef RSPAMD_LUA_URL_H
#define RSPAMD_LUA_URL_H

#include "lua_common.h"

#ifdef __cplusplus
extern "C" {
#endif

struct lua_tree_cb_data {
	lua_State *L;
	int i;
	int metatable_pos;
	unsigned int flags_mask;
	unsigned int flags_exclude_mask;
	unsigned int protocols_mask;
	enum {
		url_flags_mode_include_any,
		url_flags_mode_include_explicit,
		url_flags_mode_exclude_include,
	} flags_mode;
	gboolean sort;
	gsize max_urls;
	/* Sampling state: pick `sample_pick` out of the `sample_total` urls left */
	gsize sample_total;
	gsize sample_pick;
	uint64_t random_seed;
};

/**
 * Returns TRUE if the url passes the protocol and flags filter of the cbdata
 */
gboolean lua_url_cbdata_match(const struct lua_tree_cb_data *cb,
							  const struct rspamd_url *url);

/**
 * Applies the sampling to a url that passed `lua_url_cbdata_match`:
 * returns TRUE if the url should be returned to Lua. Must be called for
 * every matching url, in the same order as the urls were counted
 */
gboolean lua_url_cbdata_sample_take(struct lua_tree_cb_data *cb);

/**
 * Pushes the url to the table on the top of the stack
 */
void lua_url_cbdata_push(struct lua_tree_cb_data *cb, struct rspamd_url *url);

void lua_tree_url_callback(gpointer key, gpointer value, gpointer ud);

/**
 * Fills a cbdata table based on the parameter at position pos
 * @param L
 * @param pos
 * @param cbd
 * @return
 */
gboolean lua_url_cbdata_fill(lua_State *L, int pos,
							 struct lua_tree_cb_data *cbd,
							 unsigned int default_protocols,
							 unsigned int default_flags,
							 gsize max_urls);

gboolean lua_url_cbdata_fill_exclude_include(lua_State *L, int pos,
											 struct lua_tree_cb_data *cbd,
											 unsigned int default_protocols,
											 gsize max_urls);

/**
 * Cleanup url cbdata
 * @param cbd
 */
void lua_url_cbdata_dtor(struct lua_tree_cb_data *cbd);

/**
 * Sets up the sampling of the urls that passed the filter of the cbdata.
 * If there are more of them than `max_urls`, exactly `max_urls` are chosen
 * with a pseudo random sequence that is the same for the same task, but
 * depends on a per process secret.
 * @param timestamp task timestamp
 * @param digest message digest
 * @param cb
 * @param matched number of urls that passed the filter
 * @return number of urls that will be returned
 */
gsize lua_url_adjust_skip_prob(float timestamp,
							   unsigned char digest[16],
							   struct lua_tree_cb_data *cb,
							   gsize matched);

#ifdef __cplusplus
}
#endif

#endif
