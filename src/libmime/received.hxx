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


#ifndef RSPAMD_RECEIVED_HXX
#define RSPAMD_RECEIVED_HXX
#pragma once

#include "config.h"
#include "received.h"
#include "mime_string.hxx"
#include "libmime/email_addr.h"
#include "libserver/task.h"
#include <vector>
#include <string_view>
#include <utility>
#include <optional>

namespace rspamd::mime {

static inline auto
received_char_filter(UChar32 uc) -> UChar32
{
	if (u_isprint(uc)) {
		return u_tolower(uc);
	}

	return 0;
}

struct received_header {
	mime_string from_hostname;
	std::string_view from_ip;
	mime_string real_hostname;
	mime_string real_ip;
	mime_string by_hostname;
	std::string_view for_mbox;
	struct rspamd_email_address *for_addr = nullptr;
	rspamd_inet_addr_t *addr = nullptr;
	struct rspamd_mime_header *hdr = nullptr;
	time_t timestamp = 0;
	int flags = 0; /* See enum rspamd_received_type */

	received_header() noexcept
			: from_hostname(received_char_filter),
			  real_hostname(received_char_filter),
			  real_ip(received_char_filter),
			  by_hostname(received_char_filter) {}

	~received_header() {
		if (for_addr) {
			rspamd_email_address_free(for_addr);
		}
	}
};

class received_header_chain {
public:
	explicit received_header_chain(struct rspamd_task *_task) : task(_task) {
		headers.reserve(2);
		rspamd_mempool_add_destructor(task->task_pool,
				received_header_chain::received_header_chain_pool_dtor, this);
	}

	enum class append_type {
		append_tail,
		append_head
	};

	auto new_received(append_type how = append_type::append_tail) -> received_header & {
		if (how == append_type::append_tail) {
			headers.emplace_back();

			return headers.back();
		}
		else {
			headers.insert(std::begin(headers), {});

			return headers.front();
		}
	}
	auto get_received(std::size_t nth) -> std::optional<std::reference_wrapper<received_header>>{
		if (nth < headers.size()) {
			return headers[nth];
		}

		return std::nullopt;
	}
private:
	static auto received_header_chain_pool_dtor(void *ptr) -> void {
		delete static_cast<received_header_chain *>(ptr);
	}
	std::vector<received_header> headers;
	struct rspamd_task *task;
};

}

#endif //RSPAMD_RECEIVED_HXX
