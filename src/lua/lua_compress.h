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

#ifndef RSPAMD_LUA_COMPRESS_H
#define RSPAMD_LUA_COMPRESS_H

#include "lua_common.h"

#ifdef  __cplusplus
extern "C" {
#endif

gint lua_compress_zstd_compress (lua_State *L);
gint lua_compress_zstd_decompress (lua_State *L);
gint lua_compress_zlib_compress (lua_State *L);
gint lua_compress_zlib_decompress (lua_State *L, bool is_gzip);

void luaopen_compress (lua_State *L);

#ifdef  __cplusplus
}
#endif

#endif //RSPAMD_LUA_COMPRESS_H
