/* Copyright 2026 Vsevolod Stakhov. SPDX-License-Identifier: Apache-2.0 */
#include "mta_hooks.h"
#include "cfg_file.h"
#include "http/http_private.h"
#include "libcryptobox/cryptobox.h"
#include "libutil/str_util.h"
#include "libutil/rspamd_simdutf.h"
#include "libutil/addr.h"
#include "libmime/email_addr.h"
#include "contrib/hiredis/async.h"
#include "contrib/expected/expected.hpp"
#include <algorithm>
#include <array>
#include <charconv>
#include <chrono>
#include <ctime>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace {
using object = std::unique_ptr<ucl_object_t, decltype(&ucl_object_unref)>;
using message = std::unique_ptr<rspamd_http_message, decltype(&rspamd_http_message_unref)>;
using fstring = std::unique_ptr<rspamd_fstring_t, decltype(&rspamd_fstring_free)>;
using sv = std::string_view;
/* Errors are static literals; they remain valid across C and async boundaries. */
template<typename T>
using result = tl::expected<T, const char *>;
constexpr std::array properties = {"/stage", "/action", "/timestamp", "/protocol",
								   "/rawMessage", "/envelope", "/queue", "/client"};
constexpr unsigned registration_ttl = 3600, replay_ttl = 300;

object obj(ucl_type_t type = UCL_OBJECT)
{
	return {ucl_object_typed_new(type), ucl_object_unref};
}

const ucl_object_t *get(const ucl_object_t *o, const char *key)
{
	return ucl_object_lookup(o, key);
}

/* Views borrow the UCL tree, which must outlive the synchronous codec call. */
result<sv> str(const ucl_object_t *o)
{
	if (!o || ucl_object_type(o) != UCL_STRING) {
		return tl::make_unexpected("expected string");
	}
	size_t len;
	const char *s = ucl_object_tolstring(o, &len);
	return sv{s, len};
}

bool string_is(const ucl_object_t *o, sv value)
{
	auto s = str(o);
	return s && *s == value;
}

sv key_view(const ucl_object_t *o)
{
	size_t len;
	const char *key = ucl_object_keyl(o, &len);
	return {key, len};
}

void put(ucl_object_t *o, const char *key, ucl_object_t *value)
{
	ucl_object_insert_key(o, value, key, 0, true);
}

void put(ucl_object_t *o, const char *key, sv value)
{
	put(o, key, ucl_object_fromlstring(value.data(), value.size()));
}

fstring emit(const ucl_object_t *o)
{
	auto *buffer = rspamd_fstring_sized_new(256);
	rspamd_ucl_emit_fstring(o, UCL_EMIT_JSON_COMPACT, &buffer);
	return {buffer, rspamd_fstring_free};
}

sv view(const fstring &s)
{
	return {s->str, s->len};
}

bool clean(sv s, size_t limit = 4096)
{
	return s.size() <= limit && std::none_of(s.begin(), s.end(), [](unsigned char c) {
			   return c < 32 || c == 127;
		   });
}

bool valid_utf8(sv s)
{
	return rspamd_fast_utf8_validate(reinterpret_cast<const unsigned char *>(s.data()), s.size()) == 0;
}

bool ascii_alnum(unsigned char c)
{
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9');
}

bool identifier(sv s, size_t limit, bool registration = false)
{
	return !s.empty() && s.size() <= limit && std::all_of(s.begin(), s.end(), [=](unsigned char c) {
		return ascii_alnum(c) || c == '-' || c == '_' ||
			   (registration ? c == ':' : c == '.' || c == '~');
	});
}

result<object> parse_borrowed(sv s)
{
	if (s.empty() || !valid_utf8(s)) {
		return tl::make_unexpected("missing body or invalid UTF-8");
	}
	/* Same safe flags and explicit limits as ucl.untrusted_parser(). No
	 * secondary grammar: accepting the UCL syntax superset is intentional.
	 * The caller keeps the HTTP body or Redis reply alive until this tree is
	 * destroyed. UCL only copies values that need decoding, such as escapes. */
	auto parser = std::unique_ptr<ucl_parser, decltype(&ucl_parser_free)>(
		ucl_parser_new(UCL_PARSER_SAFE_FLAGS | UCL_PARSER_ZEROCOPY), ucl_parser_free);
	ucl_parser_limits limits{16, 20000, s.size() * 3 + 2 * 1024 * 1024, 256, s.size()};
	ucl_parser_set_limits(parser.get(), &limits);
	if (!ucl_parser_add_chunk_full(parser.get(), reinterpret_cast<const unsigned char *>(s.data()),
								   s.size(), 0, UCL_DUPLICATE_ERROR, UCL_PARSE_UCL)) {
		return tl::make_unexpected("invalid or over-budget request body");
	}
	object root{ucl_parser_get_object(parser.get()), ucl_object_unref};
	if (!root || ucl_object_type(root.get()) != UCL_OBJECT) {
		return tl::make_unexpected("expected object");
	}
	return root;
}

std::string digest(sv s)
{
	unsigned char hash[crypto_hash_sha256_BYTES];
	crypto_hash_sha256(hash, reinterpret_cast<const unsigned char *>(s.data()), s.size());
	std::string encoded(sizeof(hash) * 2, '\0');
	rspamd_encode_hex_buf(hash, sizeof(hash), encoded.data(), encoded.size());
	return encoded;
}

std::string utc(time_t when)
{
	tm date{};
	gmtime_r(&when, &date);
	char buffer[32];
	auto len = std::strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%SZ", &date);
	return {buffer, len};
}

bool valid_timestamp(sv s)
{
	/* RFC3339 UTC, with optional fractional seconds. Parse directly from the
	 * borrowed value; no NUL-terminated copy or heap-allocated date object. */
	if (s.size() < 20 || s.size() > 64 || s[4] != '-' || s[7] != '-' ||
		s[10] != 'T' || s[13] != ':' || s[16] != ':' || s.back() != 'Z') {
		return false;
	}
	auto number = [&](size_t offset, size_t len) {
		int value = -1;
		auto part = s.substr(offset, len);
		if (!std::all_of(part.begin(), part.end(), [](char c) { return c >= '0' && c <= '9'; })) {
			return -1;
		}
		std::from_chars(part.data(), part.data() + part.size(), value);
		return value;
	};
	using namespace std::chrono;
	int year_value = number(0, 4);
	auto date = year_month_day{year{year_value}, month{unsigned(number(5, 2))}, day{unsigned(number(8, 2))}};
	int hour = number(11, 2), minute = number(14, 2), second = number(17, 2);
	if (year_value < 1 || !date.ok() || hour < 0 || hour > 23 || minute < 0 || minute > 59 || second < 0 || second > 60) {
		return false;
	}
	if (s.size() == 20) {
		return true;
	}
	return s.size() > 21 && s[19] == '.' &&
		   std::all_of(s.begin() + 20, s.end() - 1, [](char c) { return c >= '0' && c <= '9'; });
}

message reply(int status, sv body)
{
	message m{rspamd_http_new_message(HTTP_RESPONSE), rspamd_http_message_unref};
	m->code = status;
	rspamd_http_message_set_body(m.get(), body.data(), body.size());
	rspamd_http_message_add_header(m.get(), "Cache-Control", "no-store");
	return m;
}

message json_reply(int status, const ucl_object_t *o)
{
	auto m = reply(status, {});
	auto body = emit(o);
	rspamd_http_message_set_body_from_fstring_steal(m.get(), body.release());
	return m;
}

/* The header value borrows the input HTTP message, never an async request. */
result<sv> header(rspamd_http_message *m, const char *name)
{
	rspamd_ftok_t key{.len = strlen(name), .begin = name};
	auto k = kh_get(rspamd_http_headers_hash, m->headers, &key);
	if (k == kh_end(m->headers)) {
		return sv{};
	}
	auto *h = kh_val(m->headers, k);
	if (h->next != nullptr) {
		return tl::make_unexpected("duplicate HTTP protocol header");
	}
	return sv{h->value.begin, h->value.len};
}

result<void> add_header(rspamd_http_message *m, const char *name, sv value)
{
	if (!clean(value)) {
		return tl::make_unexpected("invalid SMTP metadata");
	}
	rspamd_http_message_add_header_len(m, name, value.data(), value.size());
	return {};
}

result<void> add_optional_header(rspamd_http_message *m, const ucl_object_t *o,
								 const char *field, const char *name)
{
	auto *v = get(o, field);
	if (!v || ucl_object_type(v) == UCL_NULL) {
		return {};
	}
	return str(v).and_then([&](sv s) { return add_header(m, name, s); });
}

object subscription()
{
	auto o = obj(), stages = obj(UCL_ARRAY), props = obj(UCL_ARRAY);
	ucl_array_append(stages.get(), ucl_object_fromstring("data"));
	for (auto p: properties) {
		ucl_array_append(props.get(), ucl_object_fromstring(p));
	}
	put(o.get(), "stages", stages.release());
	put(o.get(), "properties", props.release());
	return o;
}

result<void> validate_subscription(const ucl_object_t *o)
{
	if (!o || ucl_object_type(o) != UCL_OBJECT) {
		return tl::make_unexpected("inbound subscription required");
	}
	auto *stages = get(o, "stages");
	if (!stages || ucl_object_type(stages) != UCL_ARRAY || stages->len != 1 ||
		!string_is(ucl_array_find_index(stages, 0), "data")) {
		return tl::make_unexpected("only inbound data is supported");
	}
	auto *props = get(o, "properties");
	if (!props || ucl_object_type(props) == UCL_NULL) {
		return {};
	}
	if (ucl_object_type(props) != UCL_ARRAY || props->len != properties.size()) {
		return tl::make_unexpected("DATA profile requires all eight properties");
	}
	std::array<bool, properties.size()> seen{};
	ucl_object_iter_t it = nullptr;
	while (auto *v = ucl_object_iterate(props, &it, true)) {
		auto p = str(v);
		if (!p) {
			return tl::make_unexpected(p.error());
		}
		auto found = std::find(properties.begin(), properties.end(), *p);
		if (found == properties.end() || seen[found - properties.begin()]) {
			return tl::make_unexpected("unsupported or duplicate property");
		}
		seen[found - properties.begin()] = true;
	}
	return {};
}

result<void> validate_event(const ucl_object_t *o)
{
	if (!string_is(get(o, "stage"), "data")) {
		return tl::make_unexpected("unsupported stage");
	}
	auto action = str(get(o, "action"));
	if (!action || (*action != "accept" && *action != "reject" && *action != "discard" &&
					*action != "quarantine" && *action != "disconnect")) {
		return tl::make_unexpected("invalid action");
	}
	auto timestamp = str(get(o, "timestamp"));
	if (!timestamp || !valid_timestamp(*timestamp)) {
		return tl::make_unexpected("invalid UTC timestamp");
	}
	auto *protocol = get(o, "protocol");
	if (!protocol || ucl_object_type(protocol) != UCL_OBJECT ||
		!string_is(get(protocol, "version"), "1.0")) {
		return tl::make_unexpected("unsupported protocol version");
	}
	return {};
}

result<fstring> decode_body(const ucl_object_t *o, size_t max_message)
{
	auto raw = str(get(o, "rawMessage"));
	if (!raw) {
		return tl::make_unexpected(raw.error());
	}
	if (raw->empty() || raw->size() % 4 != 0 || raw->size() > ((max_message + 2) / 3) * 4) {
		return tl::make_unexpected("invalid base64 size");
	}
	fstring body{rspamd_fstring_sized_new(raw->size() / 4 * 3), rspamd_fstring_free};
	gsize len = body->allocated;
	if (!rspamd_cryptobox_base64_decode(raw->data(), raw->size(),
										reinterpret_cast<unsigned char *>(body->str), &len) ||
		len == 0 || len > max_message) {
		return tl::make_unexpected("invalid base64 message");
	}
	/* The fast decoder is permissive about whitespace and padding bits.
	 * Re-encoding enforces the canonical wire profile, without copying raw. */
	gsize encoded_len;
	std::unique_ptr<char, decltype(&g_free)> encoded{
		rspamd_encode_base64(reinterpret_cast<unsigned char *>(body->str), len, 0, &encoded_len), g_free};
	if (!encoded || *raw != sv{encoded.get(), encoded_len}) {
		return tl::make_unexpected("noncanonical base64 message");
	}
	body->len = len;
	return body;
}

result<sv> envelope_address(const ucl_object_t *o, bool sender)
{
	if (!o || ucl_object_type(o) != UCL_OBJECT) {
		return tl::make_unexpected("invalid envelope address");
	}
	auto *v = get(o, "address");
	if (v && ucl_object_type(v) == UCL_NULL) {
		if (sender) {
			return sv{"<>"};
		}
		return tl::make_unexpected("null recipient");
	}
	auto text = str(v);
	if (!text || text->empty() || !clean(*text, 1024)) {
		return tl::make_unexpected("invalid address");
	}
	auto parsed = std::unique_ptr<rspamd_email_address, decltype(&rspamd_email_address_free)>{
		rspamd_email_address_from_smtp(text->data(), text->size()), rspamd_email_address_free};
	if (!parsed || (parsed->flags & RSPAMD_EMAIL_ADDR_EMPTY)) {
		return tl::make_unexpected("invalid SMTP address; null reverse path must use JSON null");
	}
	return *text;
}

result<void> add_esmtp_parameters(rspamd_http_message *m, const ucl_object_t *o, int index)
{
	auto *params = get(o, "parameters");
	if (!params || ucl_object_type(params) != UCL_OBJECT || params->len > 32) {
		return tl::make_unexpected("invalid ESMTP parameters");
	}
	ucl_object_iter_t it = nullptr;
	while (auto *p = ucl_object_iterate(params, &it, true)) {
		auto key = key_view(p);
		if (key.empty() || key.size() > 64 ||
			!std::all_of(key.begin(), key.end(), [](unsigned char c) { return ascii_alnum(c) || c == '-'; })) {
			return tl::make_unexpected("invalid ESMTP key");
		}
		auto value = str(p);
		if (!value || !clean(*value)) {
			return tl::make_unexpected("invalid ESMTP value");
		}
		/* Combining the recipient index, key and value requires owned storage. */
		std::string field = index < 0 ? "" : std::to_string(index) + ":";
		field.append(key).append("=").append(*value);
		auto added = add_header(m, index < 0 ? "X-Rspamd-Mail-Esmtp-Args" : "X-Rspamd-Rcpt-Esmtp-Args", field);
		if (!added) {
			return added;
		}
	}
	return {};
}

result<void> add_envelope_address(rspamd_http_message *m, const ucl_object_t *o, int index)
{
	return envelope_address(o, index < 0)
		.and_then([&](sv address) { return add_header(m, index < 0 ? "From" : "Rcpt", address); })
		.and_then([&] { return add_esmtp_parameters(m, o, index); });
}

result<void> decode_envelope(rspamd_http_message *m, const ucl_object_t *o)
{
	auto *envelope = get(o, "envelope");
	if (!envelope || ucl_object_type(envelope) != UCL_OBJECT) {
		return tl::make_unexpected("missing envelope");
	}
	auto sender = add_envelope_address(m, get(envelope, "from"), -1);
	if (!sender) {
		return sender;
	}
	auto *to = get(envelope, "to");
	if (!to || ucl_object_type(to) != UCL_ARRAY || to->len == 0 || to->len > 1000) {
		return tl::make_unexpected("invalid recipients");
	}
	ucl_object_iter_t it = nullptr;
	int index = 0;
	while (auto *recipient = ucl_object_iterate(to, &it, true)) {
		auto added = add_envelope_address(m, recipient, index++);
		if (!added) {
			return added;
		}
	}
	return {};
}

result<void> decode_client(rspamd_http_message *m, const ucl_object_t *o)
{
	auto *client = get(o, "client");
	if (!client || ucl_object_type(client) == UCL_NULL) {
		return {};
	}
	if (ucl_object_type(client) != UCL_OBJECT) {
		return tl::make_unexpected("invalid client");
	}
	if (auto *ip = get(client, "ip"); ip && ucl_object_type(ip) != UCL_NULL) {
		auto text = str(ip);
		if (!text) {
			return tl::make_unexpected(text.error());
		}
		rspamd_inet_addr_t *addr = nullptr;
		if (!rspamd_parse_inet_address(&addr, text->data(), text->size(),
									   static_cast<rspamd_inet_address_parse_flags>(
										   RSPAMD_INET_ADDRESS_PARSE_NO_UNIX | RSPAMD_INET_ADDRESS_PARSE_NO_PORT))) {
			return tl::make_unexpected("invalid client IP");
		}
		rspamd_inet_address_free(addr);
		auto added = add_header(m, "IP", *text);
		if (!added) {
			return added;
		}
	}
	return add_optional_header(m, client, "ehlo", "Helo")
		.and_then([&] { return add_optional_header(m, client, "ptr", "Hostname"); });
}

result<void> decode_queue(rspamd_http_message *m, const ucl_object_t *o)
{
	auto *queue = get(o, "queue");
	if (!queue || ucl_object_type(queue) == UCL_NULL) {
		return {};
	}
	if (ucl_object_type(queue) != UCL_OBJECT) {
		return tl::make_unexpected("invalid queue");
	}
	if (auto *id = get(queue, "id")) {
		return str(id).and_then([&](sv s) { return add_header(m, "Queue-ID", s); });
	}
	return {};
}

result<message> decode_request(sv data, size_t max_message)
{
	if (data.size() > max_message * 4 / 3 + 128 * 1024) {
		return tl::make_unexpected("request too large");
	}
	auto root = parse_borrowed(data);
	if (!root) {
		return tl::make_unexpected(root.error());
	}
	const auto *event = root->get();
	auto valid = validate_event(event);
	if (!valid) {
		return tl::make_unexpected(valid.error());
	}
	auto body = decode_body(event, max_message);
	if (!body) {
		return tl::make_unexpected(body.error());
	}

	message m{rspamd_http_new_message(HTTP_REQUEST), rspamd_http_message_unref};
	m->method = HTTP_POST;
	m->url = rspamd_fstring_append(m->url, "/checkv2", 8);
	rspamd_http_message_set_body_from_fstring_steal(m.get(), body->release());
	rspamd_http_message_add_header(m.get(), "Content-Type", "message/rfc822");
	rspamd_http_message_add_header(m.get(), "Flags", "body_block");
	rspamd_http_message_add_header(m.get(), "Milter", "yes");

	auto metadata = decode_envelope(m.get(), event)
						.and_then([&] { return decode_client(m.get(), event); })
						.and_then([&] { return decode_queue(m.get(), event); });
	if (!metadata) {
		return tl::make_unexpected(metadata.error());
	}
	return m;
}

void set_operation(ucl_object_t *sets, const char *path, ucl_object_t *value)
{
	auto op = obj();
	put(op.get(), "path", path);
	put(op.get(), "value", value);
	ucl_array_append(sets, op.release());
}

result<void> add_output_header(ucl_object_t *adds, sv name, const ucl_object_t *value)
{
	int order = -1;
	if (ucl_object_type(value) == UCL_OBJECT) {
		if (auto *o = ucl_object_lookup_any(value, "order", "index", nullptr)) {
			if (ucl_object_type(o) != UCL_INT || ucl_object_toint(o) < -1 || ucl_object_toint(o) > 100000) {
				return tl::make_unexpected("invalid header order");
			}
			order = ucl_object_toint(o);
		}
		if (get(value, "order") && get(value, "index") &&
			(ucl_object_type(get(value, "index")) != UCL_INT || ucl_object_toint(get(value, "index")) != order)) {
			return tl::make_unexpected("conflicting header order");
		}
		value = get(value, "value");
	}
	auto text = str(value);
	if (!text || !clean(*text, 64 * 1024) || !valid_utf8(*text)) {
		return tl::make_unexpected("invalid output header value");
	}
	if (name.empty() || name.size() > 998 ||
		!std::all_of(name.begin(), name.end(), [](unsigned char c) { return c > 32 && c < 127 && c != ':'; })) {
		return tl::make_unexpected("invalid output header name");
	}
	if (adds->len >= 256) {
		return tl::make_unexpected("too many output headers");
	}
	auto op = obj(), h = obj();
	put(h.get(), "name", name);
	put(h.get(), "value", *text);
	put(op.get(), "path", "/message/headers");
	put(op.get(), "value", h.release());
	if (order >= 0) {
		put(op.get(), "index", ucl_object_fromint(order));
	}
	ucl_array_append(adds, op.release());
	return {};
}

result<void> encode_headers(ucl_object_t *adds, const ucl_object_t *milter)
{
	if (!milter) {
		return {};
	}
	if (ucl_object_type(milter) != UCL_OBJECT) {
		return tl::make_unexpected("invalid milter result");
	}
	ucl_object_iter_t it = nullptr;
	while (auto *v = ucl_object_iterate(milter, &it, true)) {
		auto key = key_view(v);
		if (key == "remove_headers" && ucl_object_type(v) == UCL_OBJECT && v->len == 0) {
			continue;
		}
		if (key != "add_headers" || ucl_object_type(v) != UCL_OBJECT) {
			return tl::make_unexpected("unsupported milter modification");
		}
		ucl_object_iter_t headers = nullptr;
		while (auto *h = ucl_object_iterate(v, &headers, true)) {
			auto name = key_view(h);
			if (ucl_object_type(h) == UCL_ARRAY) {
				ucl_object_iter_t values = nullptr;
				while (auto *value = ucl_object_iterate(h, &values, true)) {
					auto added = add_output_header(adds, name, value);
					if (!added) {
						return added;
					}
				}
			}
			else {
				auto added = add_output_header(adds, name, h);
				if (!added) {
					return added;
				}
			}
		}
	}
	return {};
}

result<void> encode_action(ucl_object_t *sets, const ucl_object_t *results)
{
	auto action = str(get(results, "action"));
	if (!action) {
		return tl::make_unexpected(action.error());
	}
	if (*action == "reject" || *action == "soft reject") {
		bool soft = *action == "soft reject";
		sv reason = soft ? "Try again later" : "Message rejected";
		if (auto *v = get(get(results, "messages"), "smtp_message")) {
			auto text = str(v);
			if (!text) {
				return tl::make_unexpected(text.error());
			}
			reason = *text;
		}
		if (!clean(reason, 400)) {
			return tl::make_unexpected("invalid SMTP response");
		}
		auto smtp = obj();
		put(smtp.get(), "code", ucl_object_fromint(soft ? 451 : 550));
		put(smtp.get(), "enhancedCode", soft ? "4.7.1" : "5.7.1");
		put(smtp.get(), "message", reason);
		set_operation(sets, "/action", ucl_object_fromstring("reject"));
		set_operation(sets, "/response", smtp.release());
	}
	else if (*action == "discard" || *action == "quarantine") {
		set_operation(sets, "/action", ucl_object_fromlstring(action->data(), action->size()));
	}
	else if (*action != "no action" && *action != "greylist") {
		return tl::make_unexpected("unsupported delivery action");
	}
	return {};
}

result<message> encode_result(const ucl_object_t *results, bool rewritten)
{
	if (!results || ucl_object_type(results) != UCL_OBJECT || get(results, "error")) {
		return tl::make_unexpected("scan failed");
	}
	if (rewritten || get(results, "dkim-signature")) {
		return tl::make_unexpected("body rewriting and DKIM signing are outside the add-only profile");
	}
	auto root = obj(), sets = obj(UCL_ARRAY), adds = obj(UCL_ARRAY);
	auto encoded = encode_headers(adds.get(), get(results, "milter"))
					   .and_then([&] { return encode_action(sets.get(), results); });
	if (!encoded) {
		return tl::make_unexpected(encoded.error());
	}
	/* No-action preserves the MTA's incoming action (including earlier policy). */
	if (sets->len == 0 && adds->len == 0) {
		return reply(204, {});
	}
	if (sets->len) {
		put(root.get(), "set", sets.release());
	}
	if (adds->len) {
		put(root.get(), "add", adds.release());
	}
	auto m = json_reply(200, root.get());
	gsize len;
	rspamd_http_message_get_body(m.get(), &len);
	if (len > 64 * 1024) {
		return tl::make_unexpected("response too large");
	}
	return m;
}
}// namespace

extern "C" rspamd_http_message *rspamd_mta_hooks_error(int status, const char *code, const char *why)
{
	auto root = obj(), error = obj();
	put(error.get(), "code", code);
	put(error.get(), "message", why);
	put(root.get(), "error", error.release());
	auto m = json_reply(status, root.get());
	if (status == 401) {
		rspamd_http_message_add_header(m.get(), "WWW-Authenticate", "Bearer");
	}
	if (status == 503 || status == 429) {
		rspamd_http_message_add_header(m.get(), "Retry-After", "1");
	}
	return m.release();
}

extern "C" rspamd_http_message *rspamd_mta_hooks_decode(const char *data, gsize len, gsize max_message, GError **err)
{
	auto decoded = decode_request({data, len}, max_message);
	if (!decoded) {
		g_set_error_literal(err, g_quark_from_static_string("mta-hooks"), 400, decoded.error());
		return nullptr;
	}
	return decoded->release();
}

extern "C" rspamd_http_message *rspamd_mta_hooks_encode(const ucl_object_t *results, gboolean rewritten)
{
	auto encoded = encode_result(results, rewritten);
	if (!encoded) {
		return rspamd_mta_hooks_error(503, "SCANNER_UNAVAILABLE", encoded.error());
	}
	return encoded->release();
}

struct rspamd_mta_hooks_config {
	rspamd_config *cfg;
	std::string token, owner, redis_host, redis_password, redis_db, prefix, settings_id;
	int redis_port = 6379;
	bool insecure_loopback = false;
	size_t max_message;
};

struct rspamd_mta_hooks_request {
	rspamd_mta_hooks_config *config;
	message input{nullptr, rspamd_http_message_unref}, output{nullptr, rspamd_http_message_unref};
	/* These values survive the input HTTP message and asynchronous callbacks. */
	std::string id, fingerprint;
	fstring registration{nullptr, rspamd_fstring_free};
	std::string registration_key, invocation_key;
	int method;
	double started = g_get_monotonic_time() / 1e6, budget = 20.0;
	bool owns_invocation = false;
};

namespace {
/* Atomic state transitions shared by all workers. Pending requests are not
 * re-executed during the replay window, even after an uncertain worker failure.
 * Redis never stores the message or bearer credential. */
constexpr auto state_script = R"lua(
local op = ARGV[1]
local now = tonumber(redis.call('TIME')[1])
if op == 'register' then
  redis.call('ZREMRANGEBYSCORE', KEYS[2], '-inf', now)
  if redis.call('ZCARD', KEYS[2]) >= 64 then return {409, ''} end
  if not redis.call('SET', KEYS[1], ARGV[3], 'EX', ARGV[4], 'NX') then return {503, ''} end
  redis.call('ZADD', KEYS[2], now + tonumber(ARGV[4]), KEYS[1])
  redis.call('EXPIRE', KEYS[2], ARGV[4])
  return {201, ''}
end
local reg = redis.call('GET', KEYS[1])
if not reg then return {404, ''} end
reg = cjson.decode(reg)
if reg.owner ~= ARGV[2] then return {403, ''} end
if op == 'delete' then
  reg.response.status = 'deregistered'
  redis.call('SET', KEYS[1], cjson.encode(reg), 'KEEPTTL')
  -- Tombstones count towards the quota until expiry, preventing churn from
  -- growing the registry without bound.
  return {200, cjson.encode(reg)}
end
if op == 'status' then return {200, cjson.encode(reg)} end
if reg.response.status ~= 'active' then return {410, ''} end
if op == 'get' then return {200, cjson.encode(reg)} end
if op == 'invoke' then
  local cached = redis.call('GET', KEYS[2])
  if cached then
    cached = cjson.decode(cached)
    if cached.fingerprint ~= ARGV[3] then return {409, ''} end
    if not cached.body then return {503, ''} end
    return {cached.status, cached.body}
  end
  redis.call('ZREMRANGEBYSCORE', KEYS[3], '-inf', now)
  if redis.call('ZCARD', KEYS[3]) >= 1024 then return {429, ''} end
  redis.call('SET', KEYS[2], cjson.encode({fingerprint=ARGV[3]}), 'EX', ARGV[4])
  redis.call('ZADD', KEYS[3], now + tonumber(ARGV[4]), KEYS[2])
  redis.call('EXPIRE', KEYS[3], ARGV[4])
  return {100, ''}
end
return {503, ''}
)lua";
constexpr auto complete_script = R"lua(
local previous = redis.call('GET', KEYS[1])
if not previous then return 0 end
previous = cjson.decode(previous)
if previous.fingerprint ~= ARGV[1] or previous.body then return 0 end
redis.call('SET', KEYS[1], cjson.encode({fingerprint=ARGV[1], status=tonumber(ARGV[2]), body=ARGV[3]}), 'KEEPTTL')
return 1
)lua";
using redis_cb = std::function<void(const redisReply *)>;
struct redis_operation {
	rspamd_mta_hooks_config *config;
	redis_cb done;
};
void redis_done(redisAsyncContext *ctx, void *reply, void *ud)
{
	auto op = std::unique_ptr<redis_operation>(static_cast<redis_operation *>(ud));
	rspamd_redis_pool_release_connection(op->config->cfg->redis_pool, ctx,
										 reply ? RSPAMD_REDIS_RELEASE_DEFAULT : RSPAMD_REDIS_RELEASE_FATAL);
	op->done(static_cast<redisReply *>(reply));
}
void command(rspamd_mta_hooks_config *c, std::initializer_list<sv> args, redis_cb done)
{
	auto *ctx = rspamd_redis_pool_connect(c->cfg->redis_pool, c->redis_db.c_str(), nullptr,
										  c->redis_password.empty() ? nullptr : c->redis_password.c_str(), c->redis_host.c_str(), c->redis_port);
	if (!ctx) {
		done(nullptr);
		return;
	}
	redisAsyncSetTimeout(ctx, timeval{1, 0});
	std::vector<const char *> argv;
	std::vector<size_t> lengths;
	argv.reserve(args.size());
	lengths.reserve(args.size());
	for (auto &s: args) {
		argv.push_back(s.data());
		lengths.push_back(s.size());
	}
	auto *op = new redis_operation{c, std::move(done)};
	/* Hiredis formats and copies the arguments before returning. Only the
	 * callback, not these borrowed views, survives this call. */
	if (redisAsyncCommandArgv(ctx, redis_done, op, argv.size(), argv.data(), lengths.data()) != REDIS_OK) {
		redis_done(ctx, nullptr, op);
	}
}
void state(rspamd_mta_hooks_request *r, const char *op, sv key2, sv arg3,
		   unsigned ttl, std::function<void(int, sv)> cb)
{
	command(r->config, {"EVAL", state_script, "3", r->registration_key, key2, r->config->prefix + "invocations:" + r->config->owner, op, r->config->owner, arg3, std::to_string(ttl)}, [cb = std::move(cb)](const redisReply *rep) {
		if (!rep || rep->type != REDIS_REPLY_ARRAY || rep->elements != 2 ||
			rep->element[0]->type != REDIS_REPLY_INTEGER || rep->element[1]->type != REDIS_REPLY_STRING) {
			cb(503, {});
			return;
		}
		cb(rep->element[0]->integer, {rep->element[1]->str, rep->element[1]->len});
	});
}
rspamd_http_message *state_error(int code)
{
	const char *name = "SCANNER_UNAVAILABLE";
	if (code == 404) name = "REGISTRATION_NOT_FOUND";
	else if (code == 403)
		name = "REGISTRATION_MISMATCH";
	else if (code == 410)
		name = "REGISTRATION_DEREGISTERED";
	else if (code == 409)
		name = "INVALID_REQUEST";
	else if (code == 429)
		name = "RATE_LIMITED";
	return rspamd_mta_hooks_error(code, name, "Registration or invocation state is unavailable or conflicts");
}
std::string quota_key(rspamd_mta_hooks_request *r)
{
	return r->config->prefix + "quota:" + r->config->owner;
}
void return_output(rspamd_mta_hooks_request *r, rspamd_mta_hooks_callback cb, gpointer ud)
{
	cb(r->output.release(), FALSE, ud);
}
}// namespace

namespace {
result<std::unique_ptr<rspamd_mta_hooks_config>> parse_config(const ucl_object_t *o, rspamd_config *cfg)
{
	if (!o || ucl_object_type(o) != UCL_OBJECT) {
		return tl::make_unexpected("mta_hooks must be an object");
	}
	auto *enabled = get(o, "enabled");
	if (!enabled || ucl_object_type(enabled) != UCL_BOOLEAN) {
		return tl::make_unexpected("mta_hooks requires explicit enabled boolean");
	}
	if (!ucl_object_toboolean(enabled)) {
		return std::unique_ptr<rspamd_mta_hooks_config>{};
	}
	auto token = str(get(o, "token"));
	if (!token || token->size() < 32 || !clean(*token, 1024)) {
		return tl::make_unexpected("token must be 32-1024 printable bytes");
	}
	auto host = str(get(o, "redis_host"));
	if (!host || host->empty() || !clean(*host, 256)) {
		return tl::make_unexpected("redis_host required");
	}
	auto c = std::make_unique<rspamd_mta_hooks_config>();
	c->cfg = cfg;
	c->max_message = std::min<size_t>(cfg->max_message, 25 * 1024 * 1024);
	/* Config owns values across worker startup, reload and async operations. */
	c->token = *token;
	c->owner = digest(*token);
	c->redis_host = *host;
	c->prefix = "mta-hooks:draft01:";
	for (auto pair: {std::pair{"redis_password", &c->redis_password}, std::pair{"redis_db", &c->redis_db},
					 std::pair{"prefix", &c->prefix}, std::pair{"settings_id", &c->settings_id}}) {
		if (auto *v = get(o, pair.first)) {
			auto value = str(v);
			if (!value || !clean(*value, 1024)) {
				return tl::make_unexpected("invalid configuration string");
			}
			*pair.second = *value;
		}
	}
	if (auto *v = get(o, "redis_port")) {
		if (ucl_object_type(v) != UCL_INT || ucl_object_toint(v) <= 0 || ucl_object_toint(v) > 65535) {
			return tl::make_unexpected("invalid redis_port");
		}
		c->redis_port = ucl_object_toint(v);
	}
	if (auto *v = get(o, "insecure_loopback")) {
		if (ucl_object_type(v) != UCL_BOOLEAN) {
			return tl::make_unexpected("insecure_loopback must be boolean");
		}
		c->insecure_loopback = ucl_object_toboolean(v);
	}
	/* Profile changes must not reuse state from another scanning policy. */
	c->prefix += digest(c->settings_id + ":add-only-v1:") + ":";
	return c;
}

message discovery(const rspamd_mta_hooks_config *c)
{
	auto root = obj(), endpoints = obj(), caps = obj(), inbound = obj(), limits = obj();
	put(root.get(), "version", "1.0");
	put(endpoints.get(), "registration", "/v1/hooks/register");
	put(endpoints.get(), "deregistration", "/v1/hooks/register/{registration_id}");
	put(root.get(), "endpoints", endpoints.release());
	auto formats = obj(UCL_ARRAY);
	ucl_array_append(formats.get(), ucl_object_fromstring("json"));
	put(root.get(), "serialization", formats.release());
	auto sub = subscription();
	put(inbound.get(), "stages", ucl_object_ref(get(sub.get(), "stages")));
	put(inbound.get(), "fetchProperties", ucl_object_ref(get(sub.get(), "properties")));
	auto actions = obj(UCL_ARRAY), updates = obj(UCL_ARRAY);
	for (auto a: {"accept", "reject", "discard", "quarantine"}) {
		ucl_array_append(actions.get(), ucl_object_fromstring(a));
	}
	for (auto p: {"/action", "/response", "/message/headers"}) {
		ucl_array_append(updates.get(), ucl_object_fromstring(p));
	}
	put(inbound.get(), "actions", actions.release());
	put(inbound.get(), "updateProperties", updates.release());
	put(caps.get(), "inbound", inbound.release());
	put(root.get(), "capabilities", caps.release());
	put(limits.get(), "maxMessageSize", ucl_object_fromint(c->max_message));
	put(limits.get(), "maxRegistrations", ucl_object_fromint(64));
	put(limits.get(), "timeoutMs", ucl_object_fromint(20000));
	put(root.get(), "limits", limits.release());
	return json_reply(200, root.get());
}

result<void> validate_content_type(rspamd_http_message *msg)
{
	auto type = header(msg, "Content-Type");
	if (!type) {
		return tl::make_unexpected(type.error());
	}
	if (*type != "application/json" && *type != "application/json; charset=utf-8") {
		return tl::make_unexpected("application/json required");
	}
	for (auto name: {"Content-Encoding", "Compression"}) {
		auto encoding = header(msg, name);
		if (!encoding) {
			return tl::make_unexpected(encoding.error());
		}
		if (!encoding->empty()) {
			return tl::make_unexpected("compressed requests unsupported");
		}
	}
	return {};
}

result<void> prepare_registration(rspamd_mta_hooks_request *r, sv data)
{
	if (data.size() > 16384) {
		return tl::make_unexpected("registration too large");
	}
	auto request = parse_borrowed(data);
	if (!request) {
		return tl::make_unexpected(request.error());
	}
	const auto *o = request->get();
	auto name = str(get(o, "name"));
	if (!name || name->empty() || !clean(*name, 255)) {
		return tl::make_unexpected("MTA name required");
	}
	if (!string_is(get(o, "serialization"), "json")) {
		return tl::make_unexpected("only JSON is supported");
	}
	if (auto *out = get(o, "outbound"); out && ucl_object_type(out) != UCL_NULL) {
		return tl::make_unexpected("outbound unsupported");
	}
	if (auto *filter = get(o, "filter"); filter && ucl_object_type(filter) != UCL_NULL) {
		r->output.reset(rspamd_mta_hooks_error(422, "UNSUPPORTED_FILTER", "Filters are not supported"));
		return {};
	}
	auto subscription_valid = validate_subscription(get(o, "inbound"));
	if (!subscription_valid) {
		return subscription_valid;
	}
	int timeout_ms = 20000;
	if (auto *v = get(o, "timeoutMs"); v && ucl_object_type(v) != UCL_NULL) {
		if (ucl_object_type(v) != UCL_INT || ucl_object_toint(v) < 1000 || ucl_object_toint(v) > 3600000) {
			return tl::make_unexpected("invalid timeoutMs");
		}
		timeout_ms = std::min<int64_t>(20000, ucl_object_toint(v));
	}
	char *id = g_uuid_string_random();
	r->id = id;
	g_free(id);
	auto response = obj(), negotiated = obj(), endpoints = obj(), record = obj();
	put(response.get(), "registrationId", r->id);
	put(response.get(), "status", "active");
	auto now = time(nullptr);
	put(response.get(), "createdAt", utc(now));
	put(response.get(), "expiresAt", utc(now + registration_ttl));
	put(response.get(), "hookEndpoint", "/v1/hooks/invoke/" + r->id);
	put(negotiated.get(), "serialization", "json");
	put(negotiated.get(), "inbound", subscription().release());
	put(negotiated.get(), "outbound", ucl_object_typed_new(UCL_NULL));
	put(response.get(), "negotiated", negotiated.release());
	put(endpoints.get(), "status", "/v1/hooks/register/" + r->id + "/status");
	put(endpoints.get(), "deregistration", "/v1/hooks/register/" + r->id);
	put(response.get(), "endpoints", endpoints.release());
	r->output = json_reply(201, response.get());
	rspamd_http_message_add_header(r->output.get(), "Location", ("/v1/hooks/register/" + r->id).c_str());
	put(record.get(), "owner", r->config->owner);
	put(record.get(), "timeoutMs", ucl_object_fromint(timeout_ms));
	put(record.get(), "response", response.release());
	r->registration = emit(record.get());
	return {};
}

result<void> prepare_invocation(rspamd_mta_hooks_request *r, rspamd_http_message *msg, sv id, sv data)
{
	auto registration = header(msg, "X-MTA-Hooks-Registration");
	if (!registration) {
		return tl::make_unexpected(registration.error());
	}
	if (!identifier(id, 255, true) || *registration != id) {
		return tl::make_unexpected("invalid registration header");
	}
	auto request_id = header(msg, "X-MTA-Hooks-Request-Id");
	if (!request_id) {
		return tl::make_unexpected(request_id.error());
	}
	if (!identifier(*request_id, 128)) {
		return tl::make_unexpected("invalid request ID");
	}
	auto input = decode_request(data, r->config->max_message);
	if (!input) {
		return tl::make_unexpected(input.error());
	}
	if (!r->config->settings_id.empty()) {
		auto added = add_header(input->get(), "Settings-ID", r->config->settings_id);
		if (!added) {
			return added;
		}
	}
	r->id = id;
	r->fingerprint = digest(data);
	r->invocation_key = r->config->prefix + "request:" + r->config->owner + ":";
	r->invocation_key.append(*request_id);
	r->input = std::move(*input);
	return {};
}

result<void> prepare_request(rspamd_mta_hooks_request *r, rspamd_http_message *msg, bool tls, bool loopback)
{
	auto *c = r->config;
	if (!tls && !(loopback && c->insecure_loopback)) {
		r->output.reset(rspamd_mta_hooks_error(403, "REGISTRATION_DENIED", "HTTPS required"));
		return {};
	}
	sv path = msg->url ? sv{msg->url->str, msg->url->len} : sv{};
	if (path == "/.well-known/mta-hooks" && msg->method == HTTP_GET) {
		r->output = discovery(c);
		return {};
	}
	auto authorization = header(msg, "Authorization");
	if (!authorization) {
		return tl::make_unexpected(authorization.error());
	}
	constexpr sv bearer = "Bearer ";
	if (authorization->size() != bearer.size() + c->token.size() ||
		!authorization->starts_with(bearer) ||
		rspamd_cryptobox_memcmp(authorization->data() + bearer.size(), c->token.data(), c->token.size()) != 0) {
		r->output.reset(rspamd_mta_hooks_error(401, "INVALID_CREDENTIALS", "Valid bearer credential required"));
		return {};
	}
	gsize len;
	const char *data = rspamd_http_message_get_body(msg, &len);
	if (len > rspamd_mta_hooks_max_request(c)) {
		r->output.reset(rspamd_mta_hooks_error(413, "REQUEST_TOO_LARGE", "Request limit exceeded"));
		return {};
	}
	if (msg->method == HTTP_POST) {
		auto content = validate_content_type(msg);
		if (!content) {
			return content;
		}
	}
	constexpr sv registration_path = "/v1/hooks/register/";
	constexpr sv invocation_path = "/v1/hooks/invoke/";
	if (path == "/v1/hooks/register" && msg->method == HTTP_POST) {
		auto prepared = prepare_registration(r, {data, len});
		if (!prepared) {
			return prepared;
		}
	}
	else if (path.starts_with(invocation_path) && msg->method == HTTP_POST) {
		auto prepared = prepare_invocation(r, msg, path.substr(invocation_path.size()), {data, len});
		if (!prepared) {
			return prepared;
		}
	}
	else if (path.starts_with(registration_path) && (msg->method == HTTP_GET || msg->method == HTTP_DELETE)) {
		auto id = path.substr(registration_path.size());
		if (msg->method == HTTP_GET) {
			if (!id.ends_with("/status")) {
				return tl::make_unexpected("invalid status endpoint");
			}
			id.remove_suffix(7);
		}
		if (!identifier(id, 255, true)) {
			return tl::make_unexpected("invalid registration ID");
		}
		r->id = id;
	}
	else {
		r->output.reset(rspamd_mta_hooks_error(404, "INVALID_REQUEST", "Unknown Hooks endpoint or method"));
		return {};
	}
	r->registration_key = c->prefix + "registration:" + r->id;
	return {};
}
}// namespace

extern "C" rspamd_mta_hooks_config *rspamd_mta_hooks_config_new(const ucl_object_t *o, rspamd_config *cfg, GError **err)
{
	auto parsed = parse_config(o, cfg);
	if (!parsed) {
		g_set_error_literal(err, g_quark_from_static_string("mta-hooks"), EINVAL, parsed.error());
		return nullptr;
	}
	return parsed->release();
}

extern "C" void rspamd_mta_hooks_config_free(rspamd_mta_hooks_config *c)
{
	delete c;
}

extern "C" gsize rspamd_mta_hooks_max_request(rspamd_mta_hooks_config *c)
{
	return c->max_message * 4 / 3 + 128 * 1024;
}

extern "C" void rspamd_mta_hooks_request_free(rspamd_mta_hooks_request *r)
{
	delete r;
}

extern "C" double rspamd_mta_hooks_remaining(rspamd_mta_hooks_request *r)
{
	return std::max(0.001, r->budget - (g_get_monotonic_time() / 1e6 - r->started));
}

extern "C" rspamd_mta_hooks_request *rspamd_mta_hooks_request_new(rspamd_mta_hooks_config *c,
																  rspamd_http_message *msg, gboolean tls, gboolean loopback)
{
	auto r = std::make_unique<rspamd_mta_hooks_request>();
	r->config = c;
	r->method = msg->method;
	auto prepared = prepare_request(r.get(), msg, tls, loopback);
	if (!prepared) {
		r->registration.reset();
		r->output.reset(rspamd_mta_hooks_error(400, "INVALID_REQUEST", prepared.error()));
	}
	return r.release();
}

extern "C" void rspamd_mta_hooks_begin(rspamd_mta_hooks_request *r, rspamd_mta_hooks_callback cb, gpointer ud)
{
	if (r->registration) {
		state(r, "register", quota_key(r), view(r->registration), registration_ttl, [=](int status, sv) {
			if (status != 201) {
				r->output.reset(status == 409 ? rspamd_mta_hooks_error(409, "REGISTRATION_LIMIT_REACHED", "Registration quota exceeded") : state_error(status));
			}
			return_output(r, cb, ud);
		});
		return;
	}
	if (r->output) {
		return_output(r, cb, ud);
		return;
	}
	const char *op = r->method == HTTP_DELETE ? "delete" : r->method == HTTP_GET ? "status"
																				 : "get";
	state(r, op, quota_key(r), "", registration_ttl, [=](int status, sv payload) {
		if (status != 200) {
			cb(state_error(status), FALSE, ud);
			return;
		}
		auto record = parse_borrowed(payload);
		if (!record) {
			cb(state_error(503), FALSE, ud);
			return;
		}
		if (!r->input) {
			auto *response = get(record->get(), "response");
			if (r->method == HTTP_DELETE) {
				auto out = obj();
				put(out.get(), "registrationId", r->id);
				put(out.get(), "status", "deregistered");
				put(out.get(), "deregisteredAt", utc(time(nullptr)));
				cb(json_reply(200, out.get()).release(), FALSE, ud);
			}
			else if (!response || ucl_object_type(response) != UCL_OBJECT) {
				cb(state_error(503), FALSE, ud);
			}
			else {
				cb(json_reply(200, response).release(), FALSE, ud);
			}
			return;
		}
		auto *timeout = get(record->get(), "timeoutMs");
		if (!timeout || ucl_object_type(timeout) != UCL_INT ||
			ucl_object_toint(timeout) < 1000 || ucl_object_toint(timeout) > 20000) {
			cb(state_error(503), FALSE, ud);
			return;
		}
		r->budget = ucl_object_toint(timeout) / 1000.0;
		if (rspamd_mta_hooks_remaining(r) <= 0.001) {
			cb(state_error(503), FALSE, ud);
			return;
		}
		state(r, "invoke", r->invocation_key, r->fingerprint, replay_ttl, [=](int code, sv body) {
			if (code == 100) {
				r->owns_invocation = true;
				if (rspamd_mta_hooks_remaining(r) <= 0.001) {
					cb(state_error(503), FALSE, ud);
				}
				else {
					cb(r->input.release(), TRUE, ud);
				}
			}
			else if (!body.empty() || code == 204) {
				cb(reply(code, body).release(), FALSE, ud);
			}
			else {
				cb(state_error(code), FALSE, ud);
			}
		});
	});
}

extern "C" void rspamd_mta_hooks_finish(rspamd_mta_hooks_request *r, const ucl_object_t *results,
										gboolean rewritten, rspamd_mta_hooks_callback cb, gpointer ud)
{
	r->output.reset(rspamd_mta_hooks_encode(results, rewritten));
	if (rspamd_mta_hooks_remaining(r) <= 0.001) {
		r->output.reset(state_error(503));
	}
	if (!r->owns_invocation) {
		return_output(r, cb, ud);
		return;
	}
	gsize len;
	auto *body = rspamd_http_message_get_body(r->output.get(), &len);
	command(r->config, {"EVAL", complete_script, "1", r->invocation_key, r->fingerprint, std::to_string(r->output->code), sv{body, len}}, [=](const redisReply *rep) {
		if (!rep || rep->type != REDIS_REPLY_INTEGER || rep->integer != 1) {
			r->output.reset(state_error(503));
		}
		return_output(r, cb, ud);
	});
}
