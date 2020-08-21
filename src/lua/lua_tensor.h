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
#ifndef RSPAMD_LUA_TENSOR_H
#define RSPAMD_LUA_TENSOR_H

#define TENSOR_CLASS "rspamd{tensor}"

typedef float rspamd_tensor_num_t;

struct rspamd_lua_tensor {
	int ndims;
	int size; /* overall size (product of dims) */
	int dim[2];
	rspamd_tensor_num_t *data;
};

struct rspamd_lua_tensor *lua_check_tensor (lua_State *L, int pos);
struct rspamd_lua_tensor *lua_newtensor (lua_State *L, int ndims,
		const int *dim, bool zero_fill, bool own);

#endif
