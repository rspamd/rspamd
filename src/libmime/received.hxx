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
#include "contrib/robin-hood/robin_hood.h"
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

constexpr received_flags received_type_apply_protocols_mask(received_flags fl) {
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

constexpr const char *received_protocol_to_string(received_flags fl) {
	const auto *proto = "unknown";

	switch (received_type_apply_protocols_mask(fl)) {
	case received_flags::SMTP:
		proto = "smtp";
		break;
	case received_flags::ESMTP:
		proto = "esmtp";
		break;
	case received_flags::ESMTPS:
		proto = "esmtps";
		break;
	case received_flags::ESMTPA:
		proto = "esmtpa";
		break;
	case received_flags::ESMTPSA:
		proto = "esmtpsa";
		break;
	case received_flags::LMTP:
		proto = "lmtp";
		break;
	case received_flags::IMAP:
		proto = "imap";
		break;
	case received_flags::HTTP:
		proto = "http";
		break;
	case received_flags::LOCAL:
		proto = "local";
		break;
	case received_flags::MAPI:
		proto = "mapi";
		break;
	default:
		break;
	}

	return proto;
}

struct received_header {
	mime_string from_hostname;
	mime_string real_hostname;
	mime_string real_ip;
	mime_string by_hostname;
	mime_string for_mbox;
	struct rspamd_email_address *for_addr = nullptr;
	rspamd_inet_addr_t *addr = nullptr;
	struct rspamd_mime_header *hdr = nullptr;
	time_t timestamp = 0;
	received_flags flags = received_flags::DEFAULT; /* See enum rspamd_received_type */

	received_header() noexcept
			: from_hostname(received_char_filter),
			  real_hostname(received_char_filter),
			  real_ip(received_char_filter),
			  by_hostname(received_char_filter),
			  for_mbox() {}
	/* We have raw C pointers, so copy is explicitly disabled */
	received_header(const received_header &other) = delete;
	received_header(received_header &&other) noexcept {
		*this = std::move(other);
	}

	received_header& operator=(received_header &&other) noexcept {
		if (this != &other) {
			from_hostname = std::move(other.from_hostname);
			real_hostname = std::move(other.real_hostname);
			real_ip = std::move(other.real_ip);
			by_hostname = std::move(other.by_hostname);
			for_mbox = std::move(other.for_mbox);
			timestamp = other.timestamp;
			flags = other.flags;
			std::swap(for_addr, other.for_addr);
			std::swap(addr, other.addr);
			std::swap(hdr, other.hdr);
		}
		return *this;
	}

	/* Unit tests helper */
	static auto from_map(const robin_hood::unordered_flat_map<std::string_view, std::string_view> &map) -> received_header {
		using namespace std::string_view_literals;
		received_header rh;

		if (map.contains("from_hostname")) {
			rh.from_hostname.assign_copy(map.at("from_hostname"sv));
		}
		if (map.contains("real_hostname")) {
			rh.real_hostname.assign_copy(map.at("real_hostname"sv));
		}
		if (map.contains("by_hostname")) {
			rh.by_hostname.assign_copy(map.at("by_hostname"sv));
		}
		if (map.contains("real_ip")) {
			rh.real_ip.assign_copy(map.at("real_ip"sv));
		}
		if (map.contains("for_mbox")) {
			rh.for_mbox.assign_copy(map.at("for_mbox"sv));
		}

		return rh;
	}

	auto as_map() const -> robin_hood::unordered_flat_map<std::string_view, std::string_view>
	{
		robin_hood::unordered_flat_map<std::string_view, std::string_view> map;

		if (!from_hostname.empty()) {
			map["from_hostname"] = from_hostname.as_view();
		}
		if (!real_hostname.empty()) {
			map["real_hostname"] = real_hostname.as_view();
		}
		if (!by_hostname.empty()) {
			map["by_hostname"] = by_hostname.as_view();
		}
		if (!real_ip.empty()) {
			map["real_ip"] = real_ip.as_view();
		}
		if (!for_mbox.empty()) {
			map["for_mbox"] = for_mbox.as_view();
		}

		return map;
	}

	~received_header() {
		if (for_addr) {
			rspamd_email_address_free(for_addr);
		}
	}
};

class received_header_chain {
public:
	explicit received_header_chain(struct rspamd_task *task) {
		headers.reserve(2);
		rspamd_mempool_add_destructor(task->task_pool,
				received_header_chain::received_header_chain_pool_dtor, this);
	}
	explicit received_header_chain() {
		headers.reserve(2);
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
			headers.insert(std::begin(headers), received_header());

			return headers.front();
		}
	}
	auto new_received(received_header &&hdr, append_type how = append_type::append_tail) -> received_header & {
		if (how == append_type::append_tail) {
			headers.emplace_back(std::move(hdr));

			return headers.back();
		}
		else {
			headers.insert(std::begin(headers), std::move(hdr));

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
};

} // namespace rspamd::mime

#endif //RSPAMD_RECEIVED_HXX
