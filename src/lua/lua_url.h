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

#ifdef  __cplusplus
extern "C" {
#endif

struct lua_tree_cb_data {
	lua_State *L;
	int i;
	int metatable_pos;
	guint flags_mask;
	guint flags_exclude_mask;
	guint protocols_mask;
	enum {
		url_flags_mode_include_any,
		url_flags_mode_include_explicit,
		url_flags_mode_exclude_include,
	} flags_mode;
	gboolean sort;
	gsize max_urls;
	gdouble skip_prob;
	guint64 xoroshiro_state[4];
};

void lua_tree_url_callback (gpointer key, gpointer value, gpointer ud);

/**
 * Fills a cbdata table based on the parameter at position pos
 * @param L
 * @param pos
 * @param cbd
 * @return
 */
gboolean lua_url_cbdata_fill (lua_State *L, gint pos,
							  struct lua_tree_cb_data *cbd,
							  guint default_protocols,
							  guint default_flags,
							  gsize max_urls);

gboolean lua_url_cbdata_fill_exclude_include (lua_State *L, gint pos,
							  struct lua_tree_cb_data *cbd,
							  guint default_protocols,
							  gsize max_urls);

/**
 * Cleanup url cbdata
 * @param cbd
 */
void lua_url_cbdata_dtor (struct lua_tree_cb_data *cbd);

/**
 * Adjust probabilistic skip of the urls
 * @param timestamp
 * @param digest
 * @param cb
 * @param sz
 * @param max_urls
 * @return
 */
gsize lua_url_adjust_skip_prob (gdouble timestamp,
								guchar *digest,
								struct lua_tree_cb_data *cb,
								gsize sz);

#ifdef  __cplusplus
}
#endif

#endif
