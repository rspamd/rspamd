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

#pragma once

#ifndef RSPAMD_UTF8_UTIL_H
#define RSPAMD_UTF8_UTIL_H

#include "config.h"
#include "mem_pool.h"

#ifdef  __cplusplus
extern "C" {
#endif

/**
 * Removes all unicode spaces from a string
 * @param str start of the string
 * @param len length
 * @return new length of the string trimmed
 */
char* rspamd_string_unicode_trim_inplace (char *str, size_t *len);

#ifdef  __cplusplus
}
#endif

#endif //RSPAMD_UTF8_UTIL_H
