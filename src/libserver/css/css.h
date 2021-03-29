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

#ifndef RSPAMD_CSS_H
#define RSPAMD_CSS_H

#include "config.h"
#include "mem_pool.h"

#ifdef  __cplusplus
extern "C" {
#endif
typedef void * rspamd_css_ptr;

rspamd_css_ptr rspamd_css_parse_style (rspamd_mempool_t *pool,
									   const guchar *begin,
									   gsize len,
									   rspamd_css_ptr existing_style,
									   GError **err);

/*
 * Unescape css
 */
const gchar *rspamd_css_unescape (rspamd_mempool_t *pool,
							const guchar *begin,
							gsize len,
							gsize *outlen);
#ifdef  __cplusplus
}
#endif

#endif //RSPAMD_CSS_H
