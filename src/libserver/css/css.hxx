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

#ifndef RSPAMD_CSS_HXX
#define RSPAMD_CSS_HXX

#include <string>
#include <memory>
#include "logger.h"
#include "css_rule.hxx"
#include "css_selector.hxx"

namespace rspamd::html {
/* Forward declaration */
struct html_tag;
struct html_block;
}

namespace rspamd::css {

extern int rspamd_css_log_id;

#define msg_debug_css(...)  rspamd_conditional_debug_fast (NULL, NULL, \
        rspamd_css_log_id, "css", pool->tag.uid, \
        __FUNCTION__, \
        __VA_ARGS__)
#define msg_err_css(...) rspamd_default_log_function (G_LOG_LEVEL_CRITICAL, \
        "css", pool->tag.uid, \
        __FUNCTION__, \
        __VA_ARGS__)

class css_style_sheet {
public:
	css_style_sheet(rspamd_mempool_t *pool);
	~css_style_sheet(); /* must be declared separately due to pimpl */
	auto add_selector_rule(std::unique_ptr<css_selector> &&selector,
						   css_declarations_block_ptr decls) -> void;

	auto check_tag_block(const rspamd::html::html_tag *tag) ->
		rspamd::html::html_block *;
private:
	class impl;
	rspamd_mempool_t *pool;
	std::unique_ptr<impl> pimpl;
};

using css_return_pair = std::pair<std::shared_ptr<css_style_sheet>, css_parse_error>;
auto css_parse_style(rspamd_mempool_t *pool,
					 std::string_view input,
					 std::shared_ptr<css_style_sheet> &&existing) ->
					 css_return_pair;

}

#endif //RSPAMD_CSS_H