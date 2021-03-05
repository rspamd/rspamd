/*-
 * Copyright 2019 Vsevolod Stakhov
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

#ifndef RSPAMD_HTTP_UTIL_H
#define RSPAMD_HTTP_UTIL_H

#include "config.h"

#ifdef  __cplusplus
extern "C" {
#endif

/**
 * Parse HTTP date header and return it as time_t
 * @param header HTTP date header
 * @param len length of header
 * @return time_t or (time_t)-1 in case of error
 */
time_t rspamd_http_parse_date (const gchar *header, gsize len);

/**
 * Prints HTTP date from `time` to `buf` using standard HTTP date format
 * @param buf date buffer
 * @param len length of buffer
 * @param time time in unix seconds
 * @return number of bytes written
 */
glong rspamd_http_date_format (gchar *buf, gsize len, time_t time);

/**
 * Normalize HTTP path removing dot sequences and repeating '/' symbols as
 * per rfc3986#section-5.2
 * @param path
 * @param len
 * @param nlen
 */
void rspamd_http_normalize_path_inplace (gchar *path, guint len, gsize *nlen);

#ifdef  __cplusplus
}
#endif

#endif
