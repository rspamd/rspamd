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

#ifndef RSPAMD_HTML_URL_HXX
#define RSPAMD_HTML_URL_HXX
#pragma once

#include "libutil/mem_pool.h"
#include <string_view>
#include <optional>

struct rspamd_url; /* Forward declaration */

namespace rspamd::html {


/**
 * Checks if an html url is likely phished by some displayed url
 * @param pool
 * @param href_url
 * @param text_data
 * @return
 */
auto html_url_is_phished(rspamd_mempool_t *pool,
					struct rspamd_url *href_url,
					std::string_view text_data) -> std::optional<rspamd_url *>;


}

#endif //RSPAMD_HTML_URL_HXX