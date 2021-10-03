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

#include "config.h"
#include "received.h"
#include "libserver/task.h"
#include "libserver/url.h"
#include "mime_string.hxx"
#include "smtp_parsers.h"
#include "message.h"

#include <vector>
#include <string_view>
#include <utility>
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
			  by_hostname(received_char_filter),
			  for_mbox(received_char_filter) {}

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

	auto new_received() -> received_header & {
		headers.emplace_back();
		return headers.back();
	}
private:
	static auto received_header_chain_pool_dtor(void *ptr) -> void {
		delete static_cast<received_header_chain *>(ptr);
	}
	std::vector<received_header> headers;
	struct rspamd_task *task;
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
received_part_set_or_append(struct rspamd_task *task,
										const gchar *begin,
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
received_process_part(struct rspamd_task *task,
					  const std::string_view &data,
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
							received_part_set_or_append(task,
									c, p - c,
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
						received_part_set_or_append(task,
								c, p - c,
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
						received_part_set_or_append(task,
								c, p - c,
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
						received_part_set_or_append(task,
								c, p - c,
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
				received_part_set_or_append(task,
						c, p - c + 1,
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
				received_part_set_or_append(task,
						c, p - c,
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
received_spill(struct rspamd_task *task,
			   const std::string_view &in,
			   std::ptrdiff_t &date_pos) -> std::vector<received_part>
{
	std::vector<received_part> parts;
	std::ptrdiff_t pos = 0;

	const auto *p = in.data();
	const auto *end = p + in.size();

	while (p < end && g_ascii_isspace (*p)) {
		p++;
	}

	auto len = end - p;

	/* Ignore all received but those started from from part */
	if (len <= 4 || !lit_compare_lowercase<4>("from", p)) {
		return {};
	}

	p += sizeof("from") - 1;

	auto maybe_process_part = [&](received_part_type what) -> bool {
		parts.emplace_back(what);
		auto &rcvd_part = parts.back();
		auto chunk = std::string_view{p, (std::size_t)(end - p)};

		if (!received_process_part(task, chunk, what, pos, rcvd_part)) {
			parts.pop_back();

			return false;
		}

		return true;
	};

	/* We can now store from part */
	if (!maybe_process_part(received_part_type::RSPAMD_RECEIVED_PART_FROM)) {
		return {};
	}

	g_assert (pos != 0);
	p += pos;
	len = end > p ? end - p : 0;

	if (len > 2 && lit_compare_lowercase<2>("by", p)) {
		p += sizeof("by") - 1;

		if (!maybe_process_part(received_part_type::RSPAMD_RECEIVED_PART_BY)) {
			return {};
		}

		g_assert (pos != 0);
		p += pos;
		len = end > p ? end - p : 0;
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
received_process_rdns(struct rspamd_task *task,
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
				task->task_pool,
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
received_process_host_tcpinfo(struct rspamd_task *task,
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
					task->task_pool,
					RSPAMD_INET_ADDRESS_PARSE_RECEIVED);

			if (addr) {
				rh.addr = addr;
				rh.real_ip.assign_copy(std::string_view(rspamd_inet_address_to_string(addr)));
				rh.from_ip = rh.real_ip.as_view();
			}
		}
	}
	else {
		if (g_ascii_isxdigit(in[0])) {
			/* Try to parse IP address */
			addr = rspamd_parse_inet_address_pool(in.data(),
					in.size(), task->task_pool, RSPAMD_INET_ADDRESS_PARSE_RECEIVED);
			if (addr) {
				rh.addr = addr;
				rh.real_ip.assign_copy(std::string_view(rspamd_inet_address_to_string(addr)));
				rh.from_ip = rh.real_ip.as_view();
			}
		}

		if (!addr) {
			/* Try canonical Postfix version: rdns [ip] */
			auto obrace_pos = in.find('[');

			if (obrace_pos != std::string_view::npos) {
				auto ebrace_pos = in.rfind(']', obrace_pos);

				if (ebrace_pos != std::string_view::npos) {
					auto substr_addr = in.substr(obrace_pos + 1,
							ebrace_pos - obrace_pos - 1);
					addr = rspamd_parse_inet_address_pool(substr_addr.data(),
							substr_addr.size(),
							task->task_pool,
							RSPAMD_INET_ADDRESS_PARSE_RECEIVED);

					if (addr) {
						rh.addr = addr;
						rh.real_ip.assign_copy(std::string_view(rspamd_inet_address_to_string(addr)));
						rh.from_ip = rh.real_ip.as_view();

						/* Process with rDNS */
						auto rdns_substr = in.substr(0, obrace_pos);

						if (received_process_rdns(task,
								rdns_substr,
								rh.real_hostname)) {
							ret = true;
						}
					}
				}
			}
			else {
				/* Hostname or some crap, sigh... */
				if (received_process_rdns(task, in, rh.real_hostname)) {
					ret = true;
				}
			}
		}
	}

	return ret;
}

static void
received_process_from(struct rspamd_task *task,
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
					task, rh,
					rpart.comments[0].as_view());
		}

		if (rh.real_ip.size() == 0) {
			/* Try to do the same with data */
			if (received_process_host_tcpinfo(
					task, rh,
					rpart.data.as_view())) {
				seen_ip_in_data = true;
			}
		}

		if (!seen_ip_in_data) {
			if (rh.real_ip.size() != 0) {
				/* Get anounced hostname (usually helo) */
				received_process_rdns(task,
						rpart.data.as_view(),
						rh.from_hostname);
			}
			else {
				received_process_host_tcpinfo(task,
						rh, rpart.data.as_view());
			}
		}
	}
	else {
		/* rpart->dlen = 0 */
		if (!rpart.comments.empty()) {
			received_process_host_tcpinfo(
					task, rh,
					rpart.comments[0].as_view());
		}
	}
}

auto
received_header_parse(struct rspamd_task *task, const std::string_view &in,
					  struct rspamd_mime_header *hdr) -> bool
{
	std::ptrdiff_t date_pos = -1;

	static constexpr const auto protos_map = frozen::make_unordered_map<frozen::string, int>({
			{"smtp",    RSPAMD_RECEIVED_SMTP},
			{"esmtp",   RSPAMD_RECEIVED_ESMTP},
			{"esmtpa",  RSPAMD_RECEIVED_ESMTPA | RSPAMD_RECEIVED_FLAG_AUTHENTICATED},
			{"esmtpsa", RSPAMD_RECEIVED_ESMTPSA | RSPAMD_RECEIVED_FLAG_SSL | RSPAMD_RECEIVED_FLAG_AUTHENTICATED},
			{"esmtps",  RSPAMD_RECEIVED_ESMTPS | RSPAMD_RECEIVED_FLAG_SSL},
			{"lmtp",    RSPAMD_RECEIVED_LMTP},
			{"imap",    RSPAMD_RECEIVED_IMAP},
			{"imaps",   RSPAMD_RECEIVED_IMAP | RSPAMD_RECEIVED_FLAG_SSL},
			{"http",    RSPAMD_RECEIVED_HTTP},
			{"https",   RSPAMD_RECEIVED_HTTP | RSPAMD_RECEIVED_FLAG_SSL},
			{"local",   RSPAMD_RECEIVED_LOCAL}
	});

	auto parts = received_spill(task, in, date_pos);

	if (parts.empty()) {
		return false;
	}

	auto *recv_chain_ptr = static_cast<received_header_chain *>(MESSAGE_FIELD(task, received_headers));

	if (recv_chain_ptr == nullptr) {
		/* This constructor automatically registers dtor in mempool */
		recv_chain_ptr = new received_header_chain(task);
		MESSAGE_FIELD(task, received_headers) = (void *)recv_chain_ptr;
	}

	auto &rh = recv_chain_ptr->new_received();

	rh.flags = RSPAMD_RECEIVED_UNKNOWN;
	rh.hdr = hdr;

	for (const auto &part : parts) {
		switch (part.type) {
		case received_part_type::RSPAMD_RECEIVED_PART_FROM:
			received_process_from(task, part, rh);
			break;
		case received_part_type::RSPAMD_RECEIVED_PART_BY:
			received_process_rdns(task,
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
			rh.for_addr = rspamd_email_address_from_smtp(part.data.data(),
					part.data.size());

			if (rh.for_addr) {
				if (rh.for_addr->addr_len > 0) {
					rh.for_mbox = std::string_view{rh.for_addr->addr,
												   rh.for_addr->addr_len};
				}
			}
			break;
		default:
			/* Do nothing */
			break;
		}
	}

	if (!rh.real_ip.empty() && rh.from_ip.empty()) {
		rh.from_ip = rh.real_ip.as_view();
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

} // namespace rspamd::mime

bool
rspamd_received_header_parse(struct rspamd_task *task,
							 const char *data, size_t sz,
							 struct rspamd_mime_header *hdr)
{
	return rspamd::mime::received_header_parse(task, std::string_view{data, sz}, hdr);
}
