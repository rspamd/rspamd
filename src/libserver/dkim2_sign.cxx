/*
 * Copyright 2026 Vsevolod Stakhov
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * DKIM2 signing of an original message, see dkim2_sign.hxx
 */

#include "config.h"
#include "rspamd.h"
#include "message.h"
#include "dkim.h"
#include "dkim2.h"
#include "dkim2.hxx"
#include "dkim2_sign.hxx"
#include "dkim2_task.hxx"
#include "libmime/email_addr.h"

#include "contrib/fmt/include/fmt/core.h"

#include <openssl/evp.h>

#include <algorithm>

#define DKIM2_SIGN_ERROR dkim2_sign_error_quark()
static GQuark
dkim2_sign_error_quark(void)
{
	return g_quark_from_static_string("dkim2-sign-error-quark");
}

namespace rspamd::dkim2 {

auto tag_list_builder::tag(std::string_view name) -> tag_list_builder &
{
	tokens.emplace_back(token_t{fmt::format("{}=", name), false, true});

	return *this;
}

auto tag_list_builder::text(std::string_view value) -> tag_list_builder &
{
	tokens.emplace_back(token_t{std::string{value}, false, false});

	return *this;
}

auto tag_list_builder::base64(std::string_view encoded) -> tag_list_builder &
{
	tokens.emplace_back(token_t{std::string{encoded}, true, false});

	return *this;
}

auto tag_list_builder::unfolded() const -> std::string
{
	std::string out;

	for (const auto &token: tokens) {
		if (token.starts_tag && !out.empty()) {
			out.append("; ");
		}

		out.append(token.text);
	}

	return out;
}

auto tag_list_builder::folded(std::string_view newline, std::size_t width) const -> std::string
{
	std::string out;
	std::size_t col = 0;

	auto wrap = [&]() {
		out.append(newline);
		out.push_back('\t');
		col = 8;
	};

	for (const auto &token: tokens) {
		if (token.starts_tag && !out.empty()) {
			/* FWS is allowed after the separator of the tags */
			out.push_back(';');
			wrap();
		}

		if (!token.is_base64) {
			out.append(token.text);
			col += token.text.size();
			continue;
		}

		/* ... and anywhere inside a base64string, but not around it */
		std::string_view rest{token.text};

		while (!rest.empty()) {
			if (col >= width && rest.size() < token.text.size()) {
				wrap();
			}

			auto room = col < width ? width - col : std::size_t{1};
			auto chunk = rest.substr(0, std::max<std::size_t>(room, 1));

			out.append(chunk);
			col += chunk.size();
			rest.remove_prefix(chunk.size());
		}
	}

	return out;
}

auto check_originator(std::span<const raw_header_t> headers, const sign_fields_t &fields)
	-> std::optional<std::string>
{
	std::string_view from;
	unsigned int nfrom = 0;

	for (const auto &hdr: headers) {
		if (eq_icase(hdr.name, RSPAMD_DKIM2_MIHEADER) ||
			eq_icase(hdr.name, RSPAMD_DKIM2_SIGNHEADER)) {
			/* Signing on behalf of a Forwarder or a Reviser is another story */
			return "the message has DKIM2 header fields already";
		}

		if (eq_icase(hdr.name, "from")) {
			from = hdr.value;
			nfrom++;
		}
	}

	if (!valid_domain(fields.domain) || !valid_domain(fields.selector)) {
		return "the signing domain or the selector is not a valid domain name";
	}

	if (!smtp_addr_is_null(fields.mf) &&
		!relaxed_domain_match(smtp_addr_domain(fields.mf), fields.domain)) {
		return fmt::format("the signing domain {} is neither the MAIL FROM domain nor its parent",
						   fields.domain);
	}

	if (fields.rt.empty()) {
		return "the message has no recipients";
	}

	auto maybe_domain = nfrom == 1 ? from_mailbox_domain(from) : std::nullopt;

	if (!maybe_domain) {
		return "the message does not have a single From address";
	}

	auto from_domain = *maybe_domain;

	if (!valid_domain(from_domain)) {
		return "the From address does not have a usable domain";
	}

	if (!relaxed_domain_match(from_domain, fields.domain) &&
		!relaxed_domain_match(fields.domain, from_domain)) {
		return fmt::format("the From domain {} is not Authentic for the signing domain {}",
						   from_domain, fields.domain);
	}

	return std::nullopt;
}

auto sign_message(std::span<const raw_header_t> headers, std::string_view body,
				  const sign_fields_t &fields, std::string_view newline,
				  const sign_digest_fn &sign_digest)
	-> tl::expected<signed_fields_t, std::string>
{
	if (fields.rt.size() > DKIM2_MAX_RT_ENTRIES) {
		return tl::make_unexpected(std::string{"too many recipients"});
	}

	auto digests = hash_message(headers, body, EVP_sha256());

	if (!digests) {
		return tl::make_unexpected(std::string{"cannot hash the message"});
	}

	tag_list_builder mi;

	mi.tag("m").text("1");
	mi.tag("h").text("sha256:").base64(b64_encode(digests->hdr)).text(":").base64(b64_encode(digests->body));

	auto make_sig = [&](std::string_view signature) {
		tag_list_builder sig;

		sig.tag("i").text("1");
		sig.tag("m").text("1");
		sig.tag("t").text(fmt::format("{}", fields.t));
		sig.tag("d").text(fields.domain);
		sig.tag("mf").base64(b64_encode(fields.mf));
		sig.tag("rt");

		for (std::size_t k = 0; k < fields.rt.size(); k++) {
			if (k > 0) {
				sig.text(",");
			}

			sig.base64(b64_encode(fields.rt[k]));
		}

		sig.tag("s").text(fmt::format("{}:{}:", fields.selector, fields.alg));

		if (!signature.empty()) {
			sig.base64(b64_encode(signature));
		}

		return sig;
	};

	signed_fields_t res;

	res.mi_value = mi.unfolded();

	/* The input: the instance and this field with a null signature value */
	auto input = canon_sig_line(RSPAMD_DKIM2_MIHEADER, res.mi_value);

	input.append(canon_sig_line(RSPAMD_DKIM2_SIGNHEADER, make_sig({}).unfolded()));

	unsigned char digest[EVP_MAX_MD_SIZE];
	unsigned int dlen = 0;

	if (EVP_Digest(input.data(), input.size(), digest, &dlen, EVP_sha256(), nullptr) != 1 ||
		dlen != 32) {
		return tl::make_unexpected(std::string{"cannot hash the signature input"});
	}

	auto signature = sign_digest(std::string_view{reinterpret_cast<const char *>(digest), dlen});

	if (!signature || signature->empty()) {
		return tl::make_unexpected(std::string{"cannot sign the message"});
	}

	auto sig = make_sig(*signature);

	res.sig_value = sig.unfolded();
	res.mi = mi.folded(newline);
	res.sig = sig.folded(newline);

	return res;
}

}// namespace rspamd::dkim2

using namespace rspamd::dkim2;

/* An envelope address as it is recorded in mf=/rt=: `<local@a-label-domain>` */
static auto
dkim2_sign_path(struct rspamd_task *task, const struct rspamd_email_address *addr)
	-> std::optional<std::string>
{
	if (addr == nullptr || addr->addr == nullptr || addr->addr_len == 0) {
		return "<>";
	}

	std::string_view full{addr->addr, addr->addr_len};
	auto at_pos = full.rfind('@');

	if (at_pos == std::string_view::npos) {
		return std::nullopt;
	}

	auto domain = domain_alabel(task, full.substr(at_pos + 1));

	if (!domain || !valid_domain(*domain)) {
		return std::nullopt;
	}

	return fmt::format("<{}@{}>", full.substr(0, at_pos), *domain);
}

bool rspamd_dkim2_sign(struct rspamd_task *task,
					   rspamd_dkim_sign_key_t *key,
					   const char *domain,
					   const char *selector,
					   const char **mi_out,
					   const char **sig_out,
					   GError **err)
{
	auto fail = [&](const std::string &what) {
		g_set_error(err, DKIM2_SIGN_ERROR, EINVAL, "%s", what.c_str());
		return false;
	};

	if (task == nullptr || task->message == nullptr || key == nullptr ||
		domain == nullptr || selector == nullptr) {
		return fail("invalid arguments");
	}

	sign_fields_t fields;

	fields.domain = domain;
	fields.selector = selector;
	rspamd_str_lc(fields.domain.data(), fields.domain.size());

	switch (rspamd_dkim_sign_key_get_type(key)) {
	case RSPAMD_DKIM_KEY_RSA:
		fields.alg = "rsa-sha256";
		break;
	case RSPAMD_DKIM_KEY_EDDSA:
		fields.alg = "ed25519-sha256";
		break;
	default:
		return fail("the key type is not usable for DKIM2");
	}

	/*
	 * The envelope of the transmission is recorded in the signature, so it
	 * has to be the one that the MTA has told us, not a guess
	 */
	if (rspamd_task_get_request_header(task, "From") == nullptr ||
		rspamd_task_get_request_header(task, "Rcpt") == nullptr) {
		return fail("the SMTP envelope of the message is not known");
	}

	const auto *from = task->from_envelope_orig ? task->from_envelope_orig : task->from_envelope;
	auto mf = from != nullptr ? dkim2_sign_path(task, from) : std::nullopt;

	if (!mf) {
		return fail("the MAIL FROM address cannot be recorded");
	}

	fields.mf = std::move(*mf);

	if (task->rcpt_envelope != nullptr) {
		unsigned int i;
		struct rspamd_email_address *rcpt;
		bool has_original = false;

		PTR_ARRAY_FOREACH(task->rcpt_envelope, i, rcpt)
		{
			has_original = has_original || (rcpt->flags & RSPAMD_EMAIL_ADDR_ORIGINAL);
		}

		PTR_ARRAY_FOREACH(task->rcpt_envelope, i, rcpt)
		{
			if (has_original && !(rcpt->flags & RSPAMD_EMAIL_ADDR_ORIGINAL)) {
				/* Added by an alias expansion, was not on the wire */
				continue;
			}

			auto path = dkim2_sign_path(task, rcpt);

			if (!path || path->size() == 2) {
				return fail("a RCPT TO address cannot be recorded");
			}

			fields.rt.emplace_back(std::move(*path));
		}
	}

	fields.t = static_cast<std::uint64_t>(task->task_timestamp > 0 ? task->task_timestamp : time(nullptr));

	auto headers = message_headers(task);

	if (!headers) {
		return fail(fmt::format("the message header cannot be signed: {}", headers.error()));
	}

	if (auto problem = check_originator(*headers, fields)) {
		return fail(*problem);
	}

	/* What we return goes to the MTA over the milter protocol or to a client */
	std::string_view newline = "\r\n";

	if (task->protocol_flags & RSPAMD_TASK_PROTOCOL_FLAG_MILTER) {
		newline = "\n";
	}
	else if (MESSAGE_FIELD(task, nlines_type) == RSPAMD_TASK_NEWLINES_LF) {
		newline = "\n";
	}

	auto res = sign_message(*headers, message_body(task), fields, newline,
							[&](std::string_view digest) -> std::optional<std::string> {
								char *sig_b64 = nullptr;
								GError *sign_err = nullptr;

								if (!rspamd_dkim_sign_digest(key,
															 reinterpret_cast<const unsigned char *>(digest.data()),
															 digest.size(), &sig_b64, &sign_err)) {
									if (sign_err != nullptr) {
										g_error_free(sign_err);
									}

									return std::nullopt;
								}

								auto raw = b64_decode(sig_b64);

								g_free(sig_b64);

								return raw;
							});

	if (!res) {
		return fail(res.error());
	}

	*mi_out = rspamd_mempool_strdup(task->task_pool, res->mi.c_str());
	*sig_out = rspamd_mempool_strdup(task->task_pool, res->sig.c_str());

	return true;
}
