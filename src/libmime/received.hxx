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

enum class received_flags {
	DEFAULT = 0,
	SMTP = 1u << 0u,
	ESMTP = 1u << 1u,
	ESMTPA = 1u << 2u,
	ESMTPS = 1u << 3u,
	ESMTPSA = 1u << 4u,
	LMTP = 1u << 5u,
	IMAP = 1u << 6u,
	LOCAL = 1u << 7u,
	HTTP = 1u << 8u,
	MAPI = 1u << 9u,
	UNKNOWN = 1u << 10u,
	ARTIFICIAL = (1u << 11u),
	SSL = (1u << 12u),
	AUTHENTICATED = (1u << 13u),
};

#define RSPAMD_RECEIVED_FLAG_TYPE_MASK (received_flags::SMTP| \
            RSPAMD_RECEIVED_ESMTP| \
            RSPAMD_RECEIVED_ESMTPA| \
            RSPAMD_RECEIVED_ESMTPS| \
            RSPAMD_RECEIVED_ESMTPSA| \
            RSPAMD_RECEIVED_LMTP| \
            RSPAMD_RECEIVED_IMAP| \
            RSPAMD_RECEIVED_LOCAL| \
            RSPAMD_RECEIVED_HTTP| \
            RSPAMD_RECEIVED_MAPI| \
            RSPAMD_RECEIVED_UNKNOWN)

constexpr received_flags operator |(received_flags lhs, received_flags rhs)
{
	using ut = std::underlying_type<received_flags>::type;
	return static_cast<received_flags>(static_cast<ut>(lhs) | static_cast<ut>(rhs));
}

constexpr received_flags operator |=(received_flags &lhs, const received_flags rhs)
{
	using ut = std::underlying_type<received_flags>::type;
	lhs = static_cast<received_flags>(static_cast<ut>(lhs) | static_cast<ut>(rhs));
	return lhs;
}

constexpr received_flags operator &(received_flags lhs, received_flags rhs)
{
	using ut = std::underlying_type<received_flags>::type;
	return static_cast<received_flags>(static_cast<ut>(lhs) & static_cast<ut>(rhs));
}

constexpr bool operator !(received_flags fl)
{
	return fl == received_flags::DEFAULT;
}

constexpr received_flags received_type_apply_maks(received_flags fl) {
	return fl & (received_flags::SMTP|
			received_flags::ESMTP|
			received_flags::ESMTPA|
			received_flags::ESMTPS|
			received_flags::ESMTPSA|
			received_flags::IMAP|
			received_flags::HTTP|
			received_flags::LOCAL|
			received_flags::MAPI|
			received_flags::LMTP);
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
	received_flags flags = received_flags::DEFAULT; /* See enum rspamd_received_type */

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
	auto size() const -> std::size_t {
		return headers.size();
	}
	constexpr auto as_vector() const -> const std::vector<received_header>& {
		return headers;
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
