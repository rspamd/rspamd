/*-
 * Copyright 2016 Vsevolod Stakhov
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
#ifndef SRC_LUA_LUA_MAP_H_
#define SRC_LUA_LUA_MAP_H_

#include "lua_common.h"

#ifdef  __cplusplus
extern "C" {
#endif

LUA_PUBLIC_FUNCTION_DEF (config, add_radix_map);
LUA_PUBLIC_FUNCTION_DEF (config, radix_from_config);
LUA_PUBLIC_FUNCTION_DEF (config, radix_from_ucl);
LUA_PUBLIC_FUNCTION_DEF (config, add_map);
LUA_PUBLIC_FUNCTION_DEF (config, add_hash_map);
LUA_PUBLIC_FUNCTION_DEF (config, add_kv_map);
LUA_PUBLIC_FUNCTION_DEF (config, add_map);
LUA_PUBLIC_FUNCTION_DEF (config, get_maps);

#ifdef  __cplusplus
}
#endif

#endif /* SRC_LUA_LUA_MAP_H_ */
