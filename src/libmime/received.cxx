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

#include <mempool_vars_internal.h>
#include "config.h"
#include "libserver/url.h"
#include "lua/lua_common.h"
#include "libserver/cfg_file.h"
#include "mime_string.hxx"
#include "smtp_parsers.h"
#include "message.h"
#include "received.hxx"
#include "frozen/string.h"
#include "frozen/unordered_map.h"

namespace rspamd::mime {

enum class received_part_type {
	RSPAMD_RECEIVED_PART_FROM,
	RSPAMD_RECEIVED_PART_BY,
	RSPAMD_RECEIVED_PART_FOR,
	RSPAMD_RECEIVED_PART_WITH,
	RSPAMD_RECEIVED_PART_ID,
	RSPAMD_RECEIVED_PART_UNKNOWN,
};

struct received_part {
	received_part_type type;
	mime_string data;
	std::vector<mime_string> comments;

	explicit received_part(received_part_type t)
								  : type(t),
									data(received_char_filter) {}
};

static inline auto
received_part_set_or_append(const gchar *begin,
							gsize len,
							mime_string &dest) -> void
{
	if (len == 0) {
		return;
	}

	dest.append(begin, len);
	dest.trim(" \t");
}

static auto
received_process_part(const std::string_view &data,
					  received_part_type type,
					  std::ptrdiff_t &last,
					  received_part &npart) -> bool
{
	auto obraces = 0, ebraces = 0;
	auto seen_tcpinfo = false;
	enum _parse_state {
		skip_spaces,
		in_comment,
		read_data,
		read_tcpinfo,
		all_done
	} state, next_state;

	/* In this function, we just process comments and data separately */
	const auto *p = data.data();
	const auto *end = p + data.size();
	const auto *c = p;

	state = skip_spaces;
	next_state = read_data;

	while (p < end) {
		switch (state) {
		case skip_spaces:
			if (!g_ascii_isspace(*p)) {
				c = p;
				state = next_state;
			}
			else {
				p++;
			}
			break;
		case in_comment:
			if (*p == '(') {
				obraces++;
			}
			else if (*p == ')') {
				ebraces++;

				if (ebraces >= obraces) {
					if (type != received_part_type::RSPAMD_RECEIVED_PART_UNKNOWN) {
						if (p > c) {
							npart.comments.emplace_back(received_char_filter);
							auto &comment = npart.comments.back();
							received_part_set_or_append(c, p - c,
									comment);
						}
					}

					p++;
					c = p;
					state = skip_spaces;
					next_state = read_data;

					continue;
				}
			}

			p++;
			break;
		case read_data:
			if (*p == '(') {
				if (p > c) {
					if (type != received_part_type::RSPAMD_RECEIVED_PART_UNKNOWN) {
						received_part_set_or_append(c, p - c,
								npart.data);
					}
				}

				state = in_comment;
				obraces = 1;
				ebraces = 0;
				p++;
				c = p;
			}
			else if (g_ascii_isspace (*p)) {
				if (p > c) {
					if (type != received_part_type::RSPAMD_RECEIVED_PART_UNKNOWN) {
						received_part_set_or_append(c, p - c,
								npart.data);
					}
				}

				state = skip_spaces;
				next_state = read_data;
				c = p;
			}
			else if (*p == ';') {
				/* It is actually delimiter of date part if not in the comments */
				if (p > c) {
					if (type != received_part_type::RSPAMD_RECEIVED_PART_UNKNOWN) {
						received_part_set_or_append(c, p - c,
								npart.data);
					}
				}

				state = all_done;
				continue;
			}
			else if (npart.data.size() > 0) {
				/* We have already received data and find something with no ( */
				if (!seen_tcpinfo && type == received_part_type::RSPAMD_RECEIVED_PART_FROM) {
					/* Check if we have something special here, such as TCPinfo */
					if (*c == '[') {
						state = read_tcpinfo;
						p++;
					}
					else {
						state = all_done;
						continue;
					}
				}
				else {
					state = all_done;
					continue;
				}
			}
			else {
				p++;
			}
			break;
		case read_tcpinfo:
			if (*p == ']') {
				received_part_set_or_append(c, p - c + 1,
						npart.data);
				seen_tcpinfo = TRUE;
				state = skip_spaces;
				next_state = read_data;
				c = p;
			}
			p++;
			break;
		case all_done:
			if (p > data.data()) {
				last = p - data.data();
				return true;
			}
			else {
				/* Empty element */
				return false;
			}
			break;
		}
	}

	/* Leftover */
	switch (state) {
	case read_data:
		if (p > c) {
			if (type != received_part_type::RSPAMD_RECEIVED_PART_UNKNOWN) {
				received_part_set_or_append(c, p - c,
						npart.data);
			}

			last = p - data.data();

			return true;
		}
		break;
	case skip_spaces:
		if (p > data.data()) {
			last = p - data.data();

			return true;
		}
	default:
		break;
	}

	return false;
}

template <std::size_t N>
constexpr auto lit_compare_lowercase(const char lit[N], const char *in) -> bool
{
	for (auto i = 0; i < N; i ++) {
		if (lc_map[(unsigned char)in[i]] != lit[i]) {
			return false;
		}
	}

	return true;
}

static auto
received_spill(const std::string_view &in,
			   std::ptrdiff_t &date_pos) -> std::vector<received_part>
{
	std::vector<received_part> parts;
	std::ptrdiff_t pos = 0;
	auto seen_from = false, seen_by = false;

	const auto *p = in.data();
	const auto *end = p + in.size();

	auto skip_spaces = [&p, end]() {
		while (p < end && g_ascii_isspace (*p)) {
			p++;
		}
	};

	skip_spaces();

	/* Skip SMTP comments */
	if (*p == '(') {
		auto obraces = 0, ebraces = 0;

		while (p < end) {
			if (*p == ')') {
				ebraces ++;
			}
			else if (*p == '(') {
				obraces ++;
			}

			p ++;

			if (obraces == ebraces) {
				/* Skip spaces after  */
				skip_spaces();
				break;
			}
		}
	}

	auto len = end - p;

	if (len == 0) {
		return parts;
	}

	auto maybe_process_part = [&](received_part_type what) -> bool {
		parts.emplace_back(what);
		auto &rcvd_part = parts.back();
		auto chunk = std::string_view{p, (std::size_t)(end - p)};

		if (!received_process_part(chunk, what, pos, rcvd_part)) {
			parts.pop_back();

			return false;
		}

		return true;
	};

	if (len > 4 && lit_compare_lowercase<4>("from", p)) {
		p += sizeof("from") - 1;

		/* We can now store from part */
		if (!maybe_process_part(received_part_type::RSPAMD_RECEIVED_PART_FROM)) {
			/* Do not accept malformed from */
			return {};
		}

		g_assert (pos != 0);
		p += pos;
		len = end > p ? end - p : 0;
		seen_from = true;
	}

	if (len > 2 && lit_compare_lowercase<2>("by", p)) {
		p += sizeof("by") - 1;

		if (!maybe_process_part(received_part_type::RSPAMD_RECEIVED_PART_BY)) {
			return {};
		}

		g_assert (pos != 0);
		p += pos;
		len = end > p ? end - p : 0;
		seen_by = true;
	}

	if (!seen_from && !seen_by) {
		/* Useless received */
		return {};
	}

	while (p < end) {
		bool got_part = false;
		if (*p == ';') {
			/* We are at the date separator, stop here */
			date_pos = p - in.data() + 1;
			break;
		}
		else {
			if (len > sizeof("with") && lit_compare_lowercase<4>("with", p)) {
				p += sizeof("with") - 1;

				got_part = maybe_process_part(received_part_type::RSPAMD_RECEIVED_PART_WITH);
			}
			else if (len > sizeof("for") && lit_compare_lowercase<3>("for", p)) {
				p += sizeof("for") - 1;
				got_part = maybe_process_part(received_part_type::RSPAMD_RECEIVED_PART_FOR);
			}
			else if (len > sizeof("id") && lit_compare_lowercase<2>("id", p)) {
				p += sizeof("id") - 1;
				got_part = maybe_process_part(received_part_type::RSPAMD_RECEIVED_PART_ID);
			}
			else {
				while (p < end) {
					if (!(g_ascii_isspace (*p) || *p == '(' || *p == ';')) {
						p++;
					}
					else {
						break;
					}
				}

				if (p == end) {
					return {};
				}
				else if (*p == ';') {
					date_pos = p - in.data() + 1;
					break;
				}
				else {
					got_part = maybe_process_part(received_part_type::RSPAMD_RECEIVED_PART_UNKNOWN);
				}
			}

			if (!got_part) {
				p++;
				len = end > p ? end - p : 0;
			}
			else {
				g_assert (pos != 0);
				p += pos;
				len = end > p ? end - p : 0;
			}
		}
	}

	return parts;
}

#define RSPAMD_INET_ADDRESS_PARSE_RECEIVED \
	(rspamd_inet_address_parse_flags)(RSPAMD_INET_ADDRESS_PARSE_REMOTE|RSPAMD_INET_ADDRESS_PARSE_NO_UNIX)

static auto
received_process_rdns(rspamd_mempool_t *pool,
					  const std::string_view &in,
					  mime_string &dest) -> bool
{
	auto seen_dot = false;

	const auto *p = in.data();
	const auto *end = p + in.size();

	if (in.empty()) {
		return false;
	}

	if (*p == '[' && *(end - 1) == ']' && in.size() > 2) {
		/* We have enclosed ip address */
		auto *addr = rspamd_parse_inet_address_pool(p + 1,
				(end - p) - 2,
				pool,
				RSPAMD_INET_ADDRESS_PARSE_RECEIVED);

		if (addr) {
			const gchar *addr_str;

			if (rspamd_inet_address_get_port(addr) != 0) {
				addr_str = rspamd_inet_address_to_string_pretty(addr);
			}
			else {
				addr_str = rspamd_inet_address_to_string(addr);
			}

			dest.assign_copy(std::string_view{addr_str});

			return true;
		}
	}

	auto hlen = 0u;

	while (p < end) {
		if (!g_ascii_isspace(*p) && rspamd_url_is_domain(*p)) {
			if (*p == '.') {
				seen_dot = true;
			}

			hlen++;
		}
		else {
			break;
		}

		p++;
	}

	if (hlen > 0) {
		if (p == end || (seen_dot && (g_ascii_isspace(*p) || *p == '[' || *p == '('))) {
			/* All data looks like a hostname */
			dest.assign_copy(std::string_view{in.data(), hlen});

			return true;
		}
	}

	return false;
}

static auto
received_process_host_tcpinfo(rspamd_mempool_t *pool,
							  received_header &rh,
							  const std::string_view &in) -> bool
{
	rspamd_inet_addr_t *addr = nullptr;
	auto ret = false;

	if (in.empty()) {
		return false;
	}

	if (in[0] == '[') {
		/* Likely Exim version */

		auto brace_pos = in.find(']');

		if (brace_pos != std::string_view::npos) {
			auto substr_addr = in.substr(1, brace_pos - 1);
			addr = rspamd_parse_inet_address_pool(substr_addr.data(),
					substr_addr.size(),
					pool,
					RSPAMD_INET_ADDRESS_PARSE_RECEIVED);

			if (addr) {
				rh.addr = addr;
				rh.real_ip.assign_copy(std::string_view(rspamd_inet_address_to_string(addr)));
			}
		}
	}
	else {
		if (g_ascii_isxdigit(in[0])) {
			/* Try to parse IP address */
			addr = rspamd_parse_inet_address_pool(in.data(),
					in.size(), pool, RSPAMD_INET_ADDRESS_PARSE_RECEIVED);
			if (addr) {
				rh.addr = addr;
				rh.real_ip.assign_copy(std::string_view(rspamd_inet_address_to_string(addr)));
			}
		}

		if (!addr) {
			/* Try canonical Postfix version: rdns [ip] */
			auto obrace_pos = in.find('[');

			if (obrace_pos != std::string_view::npos) {
				auto ebrace_pos = in.rfind(']');

				if (ebrace_pos != std::string_view::npos && ebrace_pos > obrace_pos) {
					auto substr_addr = in.substr(obrace_pos + 1,
							ebrace_pos - obrace_pos - 1);
					addr = rspamd_parse_inet_address_pool(substr_addr.data(),
							substr_addr.size(),
							pool,
							RSPAMD_INET_ADDRESS_PARSE_RECEIVED);

					if (addr) {
						rh.addr = addr;
						rh.real_ip.assign_copy(std::string_view(rspamd_inet_address_to_string(addr)));

						/* Process with rDNS */
						auto rdns_substr = in.substr(0, obrace_pos);

						if (received_process_rdns(pool,rdns_substr,rh.real_hostname)) {
							ret = true;
						}
					}
				}
			}
			else {
				/* Hostname or some crap, sigh... */
				if (received_process_rdns(pool, in, rh.real_hostname)) {
					ret = true;
				}
			}
		}
	}

	return ret;
}

static void
received_process_from(rspamd_mempool_t *pool,
					  const received_part &rpart,
					  received_header &rh)
{
	if (rpart.data.size() > 0) {
		/* We have seen multiple cases:
		 * - [ip] (hostname/unknown [real_ip])
		 * - helo (hostname/unknown [real_ip])
		 * - [ip]
		 * - hostname
		 * - hostname ([ip]:port helo=xxx)
		 * Maybe more...
		 */
		auto seen_ip_in_data = false;

		if (!rpart.comments.empty()) {
			/* We can have info within comment as part of RFC */
			received_process_host_tcpinfo(
					pool, rh,
					rpart.comments[0].as_view());
		}

		if (rh.real_ip.size() == 0) {
			/* Try to do the same with data */
			if (received_process_host_tcpinfo(
					pool, rh,
					rpart.data.as_view())) {
				seen_ip_in_data = true;
			}
		}

		if (!seen_ip_in_data) {
			if (rh.real_ip.size() != 0) {
				/* Get anounced hostname (usually helo) */
				received_process_rdns(pool,
						rpart.data.as_view(),
						rh.from_hostname);
			}
			else {
				received_process_host_tcpinfo(pool,
						rh, rpart.data.as_view());
			}
		}
	}
	else {
		/* rpart->dlen = 0 */
		if (!rpart.comments.empty()) {
			received_process_host_tcpinfo(
					pool, rh,
					rpart.comments[0].as_view());
		}
	}
}

static auto
received_header_parse(received_header_chain &chain, rspamd_mempool_t *pool,
					  const std::string_view &in,
					  struct rspamd_mime_header *hdr) -> bool
{
	std::ptrdiff_t date_pos = -1;

	static constexpr const auto protos_map = frozen::make_unordered_map<frozen::string, received_flags>({
			{"smtp",    received_flags::SMTP},
			{"esmtp",   received_flags::ESMTP},
			{"esmtpa",  received_flags::ESMTPA |
						received_flags::AUTHENTICATED},
			{"esmtpsa", received_flags::ESMTPSA |
						received_flags::SSL |
						received_flags::AUTHENTICATED},
			{"esmtps",  received_flags::ESMTPS |
						received_flags::SSL},
			{"lmtp",    received_flags::LMTP},
			{"imap",    received_flags::IMAP},
			{"imaps",   received_flags::IMAP |
						received_flags::SSL},
			{"http",    received_flags::HTTP},
			{"https",   received_flags::HTTP |
						received_flags::SSL},
			{"local",   received_flags::LOCAL}
	});

	auto parts = received_spill(in, date_pos);

	if (parts.empty()) {
		return false;
	}

	auto &rh = chain.new_received();

	rh.flags = received_flags::UNKNOWN;
	rh.hdr = hdr;

	for (const auto &part : parts) {
		switch (part.type) {
		case received_part_type::RSPAMD_RECEIVED_PART_FROM:
			received_process_from(pool, part, rh);
			break;
		case received_part_type::RSPAMD_RECEIVED_PART_BY:
			received_process_rdns(pool,
					part.data.as_view(),
					rh.by_hostname);
			break;
		case received_part_type::RSPAMD_RECEIVED_PART_WITH:
			if (part.data.size() > 0) {
				auto proto_flag_it = protos_map.find(part.data.as_view());

				if (proto_flag_it != protos_map.end()) {
					rh.flags = proto_flag_it->second;
				}
			}
			break;
		case received_part_type::RSPAMD_RECEIVED_PART_FOR:
			rh.for_mbox.assign_copy(part.data);
			rh.for_addr = rspamd_email_address_from_smtp(rh.for_mbox.data(),
					rh.for_mbox.size());
			break;
		default:
			/* Do nothing */
			break;
		}
	}

	if (!rh.real_hostname.empty() && rh.from_hostname.empty()) {
		rh.from_hostname.assign_copy(rh.real_hostname);
	}

	if (date_pos > 0 && date_pos < in.size()) {
		auto date_sub = in.substr(date_pos);
		rh.timestamp = rspamd_parse_smtp_date((const unsigned char*)date_sub.data(),
				date_sub.size(), nullptr);
	}

	return true;
}

static auto
received_maybe_fix_task(struct rspamd_task *task) -> bool
{
	auto *recv_chain_ptr = static_cast<received_header_chain *>(MESSAGE_FIELD(task, received_headers));

	if (recv_chain_ptr) {
		auto need_recv_correction = false;

		auto top_recv_maybe = recv_chain_ptr->get_received(0);

		if (top_recv_maybe.has_value()) {
			auto &top_recv = top_recv_maybe.value().get();

			const auto *raddr = top_recv.addr;
			if (top_recv.real_ip.size() == 0 || (task->cfg && task->cfg->ignore_received)) {
				need_recv_correction = true;
			}
			else if (!(task->flags & RSPAMD_TASK_FLAG_NO_IP) && task->from_addr) {
				if (!raddr) {
					need_recv_correction = true;
				}
				else {
					if (rspamd_inet_address_compare(raddr, task->from_addr, FALSE) != 0) {
						need_recv_correction = true;
					}
				}
			}

			if (need_recv_correction && !(task->flags & RSPAMD_TASK_FLAG_NO_IP)
					&& task->from_addr) {
				msg_debug_task ("the first received seems to be"
								" not ours, prepend it with fake one");

				auto &trecv = recv_chain_ptr->new_received(received_header_chain::append_type::append_head);
				trecv.flags |= received_flags::ARTIFICIAL;

				if (task->flags & RSPAMD_TASK_FLAG_SSL) {
					trecv.flags |= received_flags::SSL;
				}

				if (task->user) {
					trecv.flags |= received_flags::AUTHENTICATED;
				}

				trecv.real_ip.assign_copy(std::string_view(rspamd_inet_address_to_string(task->from_addr)));

				const auto *mta_name = (const char*)rspamd_mempool_get_variable(task->task_pool,
						RSPAMD_MEMPOOL_MTA_NAME);

				if (mta_name) {
					trecv.by_hostname.assign_copy(std::string_view(mta_name));
				}
				trecv.addr = rspamd_inet_address_copy(task->from_addr);

				if (task->hostname) {
					trecv.real_hostname.assign_copy(std::string_view(task->hostname));
					trecv.from_hostname.assign_copy(trecv.real_hostname);
				}

				return true;
			}

			/* Extract data from received header if we were not given IP */
			if (!need_recv_correction && (task->flags & RSPAMD_TASK_FLAG_NO_IP) &&
				(task->cfg && !task->cfg->ignore_received)) {
				if (!top_recv.real_ip.empty()) {
					if (!rspamd_parse_inet_address (&task->from_addr,
							top_recv.real_ip.data(),
							top_recv.real_ip.size(),
							RSPAMD_INET_ADDRESS_PARSE_NO_UNIX)) {
						msg_warn_task ("cannot get IP from received header: '%s'",
								top_recv.real_ip.data());
						task->from_addr = nullptr;
					}
				}
				if (!top_recv.real_hostname.empty()) {
					task->hostname = top_recv.real_hostname.data();
				}

				return true;
			}
		}
	}

	return false;
}

static auto
received_export_to_lua(received_header_chain *chain, lua_State *L) -> bool
{
	if (chain == nullptr) {
		return false;
	}

	lua_createtable(L, chain->size(), 0);

	auto push_flag = [L](const received_header &rh, received_flags fl, const char *name) {
		lua_pushboolean(L, !!(rh.flags & fl));
		lua_setfield(L, -2, name);
	};

	auto i = 1;

	for (const auto &rh : chain->as_vector()) {
		lua_createtable (L, 0, 10);

		if (rh.hdr && rh.hdr->decoded) {
			rspamd_lua_table_set(L, "raw", rh.hdr->decoded);
		}

		lua_createtable(L, 0, 3);
		push_flag(rh, received_flags::ARTIFICIAL, "artificial");
		push_flag(rh, received_flags::AUTHENTICATED, "authenticated");
		push_flag(rh, received_flags::SSL, "ssl");
		lua_setfield(L, -2, "flags");

		auto push_nullable_string = [L](const mime_string &st, const char *field) {
			if (st.empty()) {
				lua_pushnil(L);
			}
			else {
				lua_pushlstring(L, st.data(), st.size());
			}
			lua_setfield(L, -2, field);
		};

		push_nullable_string(rh.from_hostname, "from_hostname");
		push_nullable_string(rh.real_hostname, "real_hostname");
		push_nullable_string(rh.real_ip, "from_ip");
		push_nullable_string(rh.by_hostname, "by_hostname");
		push_nullable_string(rh.for_mbox, "for");

		if (rh.addr) {
			rspamd_lua_ip_push(L, rh.addr);
		}
		else {
			lua_pushnil(L);
		}
		lua_setfield(L, -2, "real_ip");

		lua_pushstring(L, received_protocol_to_string(rh.flags));
		lua_setfield(L, -2, "proto");

		lua_pushinteger(L, rh.timestamp);
		lua_setfield(L, -2, "timestamp");

		lua_rawseti(L, -2, i++);
	}

	return true;
}

} // namespace rspamd::mime

bool
rspamd_received_header_parse(struct rspamd_task *task,
							 const char *data, size_t sz,
							 struct rspamd_mime_header *hdr)
{
	auto *recv_chain_ptr = static_cast<rspamd::mime::received_header_chain *>
			(MESSAGE_FIELD(task, received_headers));

	if (recv_chain_ptr == nullptr) {
		/* This constructor automatically registers dtor in mempool */
		recv_chain_ptr = new rspamd::mime::received_header_chain(task);
		MESSAGE_FIELD(task, received_headers) = (void *)recv_chain_ptr;
	}
	return rspamd::mime::received_header_parse(*recv_chain_ptr, task->task_pool,
			std::string_view{data, sz}, hdr);
}

bool
rspamd_received_maybe_fix_task(struct rspamd_task *task)
{
	return rspamd::mime::received_maybe_fix_task(task);
}

bool
rspamd_received_export_to_lua(struct rspamd_task *task, lua_State *L)
{
	return rspamd::mime::received_export_to_lua(
			static_cast<rspamd::mime::received_header_chain *>(MESSAGE_FIELD(task, received_headers)),
			L);
}

/* Tests part */
#define DOCTEST_CONFIG_IMPLEMENTATION_IN_DLL
#include "doctest/doctest.h"

TEST_SUITE("received") {
TEST_CASE("parse received")
{
	using namespace std::string_view_literals;
	using map_type = robin_hood::unordered_flat_map<std::string_view, std::string_view>;
	std::vector<std::pair<std::string_view, map_type>> cases{
			// Simple received
			{"from smtp11.mailtrack.pl (smtp11.mailtrack.pl [185.243.30.90])"sv,
					{
							{"real_ip", "185.243.30.90"},
							{"real_hostname", "smtp11.mailtrack.pl"},
							{"from_hostname", "smtp11.mailtrack.pl"}
					}
			},
			// Real Postfix IPv6 received
			{"from server.chat-met-vreemden.nl (unknown [IPv6:2a01:7c8:aab6:26d:5054:ff:fed1:1da2])\n"
			 "\t(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))\n"
			 "\t(Client did not present a certificate)\n"
			 "\tby mx1.freebsd.org (Postfix) with ESMTPS id CF0171862\n"
			 "\tfor <test@example.com>; Mon,  6 Jul 2015 09:01:20 +0000 (UTC)\n"
			 "\t(envelope-from upwest201diana@outlook.com)"sv,
					{
							{"real_ip", "2a01:7c8:aab6:26d:5054:ff:fed1:1da2"},
							{"from_hostname", "server.chat-met-vreemden.nl"},
							{"by_hostname", "mx1.freebsd.org"},
							{"for_mbox", "<test@example.com>"}
					}
			},
			// Exim IPv4 received
			{"from localhost ([127.0.0.1]:49019 helo=hummus.csx.cam.ac.uk)\n"
			 " by hummus.csx.cam.ac.uk with esmtp (Exim 4.91-pdpfix1)\n"
			 " (envelope-from <exim-dev-bounces@exim.org>)\n"
			 " id 1fZ55o-0006DP-3H\n"
			 " for <xxx@xxx.xxx>; Sat, 30 Jun 2018 02:54:28 +0100"sv,
					{
							{"from_hostname", "localhost"},
							{"real_ip", "127.0.0.1"},
							{"for_mbox", "<xxx@xxx.xxx>"},
							{"by_hostname", "hummus.csx.cam.ac.uk"},
					}
			},
			// Exim IPv6 received
			{"from smtp.spodhuis.org ([2a02:898:31:0:48:4558:736d:7470]:38689\n"
			 " helo=mx.spodhuis.org)\n"
			 " by hummus.csx.cam.ac.uk with esmtpsa (TLSv1.3:TLS_AES_256_GCM_SHA384:256)\n"
			 " (Exim 4.91-pdpfix1+cc) (envelope-from <xxx@exim.org>)\n"
			 " id 1fZ55k-0006CO-9M\n"
			 " for exim-dev@exim.org; Sat, 30 Jun 2018 02:54:24 +0100"sv,
					{
							{"from_hostname", "smtp.spodhuis.org"},
							{"real_ip", "2a02:898:31:0:48:4558:736d:7470"},
							{"for_mbox", "exim-dev@exim.org"},
							{"by_hostname", "hummus.csx.cam.ac.uk"},
					}
			},
			// Haraka received
			{"from aaa.cn ([1.1.1.1]) by localhost.localdomain (Haraka/2.8.18) with "
			 "ESMTPA id 349C9C2B-491A-4925-A687-3EF14038C344.1 envelope-from <huxin@xxx.com> "
			 "(authenticated bits=0); Tue, 03 Jul 2018 14:18:13 +0200"sv,
					{
							{"from_hostname", "aaa.cn"},
							{"real_ip", "1.1.1.1"},
							{"by_hostname", "localhost.localdomain"},
					}
			},
			// Invalid by
			{"from [192.83.172.101] (HELLO 148.251.238.35) (148.251.238.35) "
			 "by guovswzqkvry051@sohu.com with gg login "
			 "by AOL 6.0 for Windows US sub 008 SMTP  ; Tue, 03 Jul 2018 09:01:47 -0300"sv,
					{
							{"from_hostname", "192.83.172.101"},
							{"real_ip", "192.83.172.101"},
					}
			},
			// Invalid hostinfo
			{"from example.com ([]) by example.com with ESMTP id 2019091111 ;"
			 " Thu, 26 Sep 2019 11:19:07 +0200"sv,
					{
							{"by_hostname", "example.com"},
							{"from_hostname", "example.com"},
							{"real_hostname", "example.com"},
					}
			},
			// Different real and announced hostnames + broken crap
			{"from 171-29.br (1-1-1-1.z.com.br [1.1.1.1]) by x.com.br (Postfix) "
			 "with;ESMTP id 44QShF6xj4z1X for <hey@y.br>; Thu, 21 Mar 2019 23:45:46 -0300 "
			 ": <g @yi.br>"sv,
					{
							{"real_ip", "1.1.1.1"},
							{"from_hostname", "171-29.br"},
							{"real_hostname", "1-1-1-1.z.com.br"},
							{"by_hostname", "x.com.br"},
					}
			},
			// Different real and announced ips + no hostname
			{"from [127.0.0.1] ([127.0.0.2]) by smtp.gmail.com with ESMTPSA id xxxololo"sv,
					{
							{"real_ip", "127.0.0.2"},
							{"from_hostname", "127.0.0.1"},
							{"by_hostname", "smtp.gmail.com"},
					}
			},
			// Different real and hostanes
			{"from 185.118.166.127 (steven2.zhou01.pserver.ru [185.118.166.127]) "
			 "by mail.832zsu.cn (Postfix) with ESMTPA id AAD722133E34"sv,
					{
							{"real_ip", "185.118.166.127"},
							{"from_hostname", "185.118.166.127"},
							{"real_hostname", "steven2.zhou01.pserver.ru"},
							{"by_hostname", "mail.832zsu.cn"},
					}
			},
			// \0 in received must be filtered
			{"from smtp11.mailt\0rack.pl (smtp11.mail\0track.pl [1\085.243.30.90])"sv,
					{
							{"real_ip", "185.243.30.90"},
							{"real_hostname", "smtp11.mailtrack.pl"},
							{"from_hostname", "smtp11.mailtrack.pl"}
					}
			},
			// No from part
			{"by mail.832zsu.cn (Postfix) with ESMTPA id AAD722133E34"sv,
					{
							{"by_hostname", "mail.832zsu.cn"},
					}
			},
			// From part is in the comment
			{"(from asterisk@localhost)\n"
			 "        by pbx.xxx.com (8.14.7/8.14.7/Submit) id 076Go4wD014562;\n"
			 "        Thu, 6 Aug 2020 11:50:04 -0500"sv,
					{
							{"by_hostname", "pbx.xxx.com"},
					}
			},
	};
	rspamd_mempool_t *pool = rspamd_mempool_new_default("rcvd test", 0);

	for (auto &&c : cases) {
		SUBCASE(c.first.data()) {
			rspamd::mime::received_header_chain chain;
			auto ret = rspamd::mime::received_header_parse(chain, pool,
					c.first, nullptr);
			CHECK(ret == true);
			auto &&rh = chain.get_received(0);
			CHECK(rh.has_value());
			auto res = rh.value().get().as_map();

			for (const auto &expected : c.second) {
				CHECK_MESSAGE(res.contains(expected.first), expected.first.data());
				CHECK(res[expected.first] == expected.second);
			}
			for (const auto &existing : res) {
				CHECK_MESSAGE(c.second.contains(existing.first), existing.first.data());
				CHECK(c.second[existing.first] == existing.second);
			}
		}
	}

	rspamd_mempool_delete(pool);
}
}