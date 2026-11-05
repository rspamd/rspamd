#define U_CHARSET_IS_UTF8 1
#include <unicode/utypes.h>
#include <unicode/utf8.h>
#include <unicode/uchar.h>
#include <unicode/normalizer2.h>
#include <unicode/unistr.h>
#include <algorithm>
#include <cstdint>
#include <iterator>
#include <initializer_list>
#include <string_view>
#include <vector>

#include "smtputf8_syntax.h"
#include "smtputf8_data.hxx"

namespace {

using script_code = rspamd::smtputf8::script;
using rspamd::smtputf8::script_ranges;

/*
 * Rule 1. The ACE prefix is case-insensitive, so XN-- is an a-label too.
 * A quoted local part is not made of atoms, so the caller skips it.
 */
auto has_a_label(std::string_view s) -> bool
{
	std::size_t start = 0;

	for (;;) {
		auto end = s.find('.', start);
		auto atom = s.substr(start, end == std::string_view::npos ? end : end - start);

		if (atom.size() >= 4 && (atom[0] | 0x20) == 'x' && (atom[1] | 0x20) == 'n' &&
			atom[2] == '-' && atom[3] == '-') {
			return true;
		}

		if (end == std::string_view::npos) {
			return false;
		}

		start = end + 1;
	}
}

auto decode_utf8(std::string_view s, std::vector<UChar32> &out) -> bool
{
	int32_t i = 0;
	auto len = static_cast<int32_t>(s.size());

	while (i < len) {
		UChar32 cp;
		U8_NEXT(s.data(), i, len, cp);

		if (cp < 0) {
			return false;
		}

		out.push_back(cp);
	}

	return true;
}

static_assert(script_ranges[0] >> 8 == 0 &&
				  std::is_sorted(std::begin(script_ranges), std::end(script_ranges)),
			  "script_of() needs a sorted table that starts at U+0000");

/* Binary search, since the table holds about 1500 ranges */
auto script_of(UChar32 cp) -> script_code
{
	auto key = (static_cast<std::uint32_t>(cp) << 8) | 0xff;
	auto it = std::upper_bound(std::begin(script_ranges), std::end(script_ranges), key);

	return static_cast<script_code>(*(it - 1) & 0xff);
}

/*
 * RFC5892 2.6 and 2.8 enumerate the code points that need a context rule.
 * The table gives them a script like any permitted code point, and
 * gen_smtputf8_data.py fails if Unicode ever adds a join control.
 */
auto is_contextj(UChar32 cp) -> bool
{
	return cp == 0x200C || cp == 0x200D;
}

auto is_contexto(UChar32 cp) -> bool
{
	return cp == 0x00B7 || cp == 0x0375 || cp == 0x05F3 || cp == 0x05F4 ||
		   cp == 0x30FB || (cp >= 0x0660 && cp <= 0x0669) ||
		   (cp >= 0x06F0 && cp <= 0x06F9);
}

auto is_virama(UChar32 cp) -> bool
{
	return u_getCombiningClass(cp) == 9;
}

auto joining_type(UChar32 cp) -> int32_t
{
	return u_getIntPropertyValue(cp, UCHAR_JOINING_TYPE);
}

/* RFC5892 A.1 and A.2 */
auto contextj_ok(const std::vector<UChar32> &cps, std::size_t i) -> bool
{
	if (i > 0 && is_virama(cps[i - 1])) {
		return true;
	}

	if (cps[i] != 0x200C) {
		return false;
	}

	/* (Joining_Type:{L,D})(Joining_Type:T)*‌(Joining_Type:T)*(Joining_Type:{R,D}) */
	auto before = i;

	while (before > 0 && joining_type(cps[before - 1]) == U_JT_TRANSPARENT) {
		before--;
	}

	if (before == 0) {
		return false;
	}

	auto left = joining_type(cps[before - 1]);

	if (left != U_JT_LEFT_JOINING && left != U_JT_DUAL_JOINING) {
		return false;
	}

	auto after = i + 1;

	while (after < cps.size() && joining_type(cps[after]) == U_JT_TRANSPARENT) {
		after++;
	}

	if (after == cps.size()) {
		return false;
	}

	auto right = joining_type(cps[after]);

	return right == U_JT_RIGHT_JOINING || right == U_JT_DUAL_JOINING;
}

struct contexto_properties {
	bool arabic_indic = false;
	bool extended_arabic_indic = false;
	bool japanese = false;
};

/* Compute address-wide context once, rather than rescanning for each character. */
auto get_contexto_properties(const std::vector<UChar32> &cps) -> contexto_properties
{
	contexto_properties context;
	bool middle_dot = false;

	for (auto cp: cps) {
		context.arabic_indic |= cp >= 0x0660 && cp <= 0x0669;
		context.extended_arabic_indic |= cp >= 0x06F0 && cp <= 0x06F9;
		middle_dot |= cp == 0x30FB;
	}

	if (middle_dot) {
		for (auto cp: cps) {
			if (cp < 0x80) {
				continue;
			}

			auto script = script_of(cp);

			if (script == script_code::hiragana || script == script_code::katakana ||
				script == script_code::han) {
				context.japanese = true;
				break;
			}
		}
	}

	return context;
}

/* RFC5892 A.3 to A.9 */
auto contexto_ok(const std::vector<UChar32> &cps, std::size_t i,
				 const contexto_properties &context) -> bool
{
	auto cp = cps[i];

	if (cp == 0x00B7) {
		/*
		 * A.3 specifies U+006C, because in the DNS, the label
		 * has been folded to lower case before that point. However,
		 * email addresses are not folded, so we accept L here.
		 */
		return i > 0 && i + 1 < cps.size() &&
			   (cps[i - 1] | 0x20) == 'l' && (cps[i + 1] | 0x20) == 'l';
	}

	if (cp == 0x0375) {
		return i + 1 < cps.size() && script_of(cps[i + 1]) == script_code::greek;
	}

	if (cp == 0x05F3 || cp == 0x05F4) {
		return i > 0 && script_of(cps[i - 1]) == script_code::hebrew;
	}

	if (cp == 0x30FB) {
		return context.japanese;
	}

	if (cp >= 0x0660 && cp <= 0x0669) {
		return !context.extended_arabic_indic;
	}

	if (cp >= 0x06F0 && cp <= 0x06F9) {
		return !context.arabic_indic;
	}

	return false;
}

auto within(const std::vector<script_code> &used,
			std::initializer_list<script_code> family) -> bool
{
	for (auto script: used) {
		bool found = false;

		for (auto f: family) {
			if (f == script) {
				found = true;
			}
		}

		if (!found) {
			return false;
		}
	}

	return true;
}

/*
 * Rule 3. Japanese uses Han, Hiragana and Katakana together, so those
 * count as one script, as do Han with Hangul and Han with Bopomofo.
 */
auto single_script(const std::vector<UChar32> &cps) -> bool
{
	std::vector<script_code> used;

	for (auto cp: cps) {
		if (cp < 0x80) {
			continue;
		}

		auto script = script_of(cp);

		if (script == script_code::common || script == script_code::inherited) {
			continue;
		}

		bool seen = false;

		for (auto s: used) {
			if (s == script) {
				seen = true;
			}
		}

		if (!seen) {
			used.push_back(script);
		}
	}

	return used.size() <= 1 ||
		   within(used, {script_code::han, script_code::hiragana, script_code::katakana}) ||
		   within(used, {script_code::han, script_code::hangul}) ||
		   within(used, {script_code::han, script_code::bopomofo});
}

auto is_nfc(const std::vector<UChar32> &cps) -> bool
{
	UErrorCode uc_err = U_ZERO_ERROR;
	const auto *nfc = icu::Normalizer2::getNFCInstance(uc_err);

	if (U_FAILURE(uc_err)) {
		return false;
	}

	icu::UnicodeString us;

	for (auto cp: cps) {
		us.append(cp);
	}

	auto normalized = nfc->isNormalized(us, uc_err);

	return U_SUCCESS(uc_err) && normalized;
}

}// namespace

enum rspamd_smtputf8_syntax_result
rspamd_smtputf8_check_address(const char *user, gsize user_len,
							  const char *domain, gsize domain_len,
							  gboolean user_quoted)
{
	std::string_view user_sv{user, user_len}, domain_sv{domain, domain_len};
	const auto is_ascii = [](unsigned char c) { return c < 0x80; };
	const auto ascii_domain = std::all_of(domain_sv.begin(), domain_sv.end(), is_ascii);
	const auto ascii_address = ascii_domain &&
							   std::all_of(user_sv.begin(), user_sv.end(), is_ascii);
	std::vector<UChar32> cps;

	if (!ascii_address) {
		cps.reserve(user_len + domain_len + 1);

		if (!decode_utf8(user_sv, cps)) {
			return RSPAMD_SMTPUTF8_BAD_UTF8;
		}

		cps.push_back('@');

		if (!decode_utf8(domain_sv, cps)) {
			return RSPAMD_SMTPUTF8_BAD_UTF8;
		}
	}

	if (!user_quoted && has_a_label(user_sv)) {
		return RSPAMD_SMTPUTF8_A_LABEL;
	}

	if (!(RSPAMD_SMTPUTF8_ACCEPT_A_LABEL_DOMAINS && ascii_domain) &&
		has_a_label(domain_sv)) {
		return RSPAMD_SMTPUTF8_A_LABEL;
	}

	/* ASCII needs no Unicode allocation, script lookup or normalization. */
	if (ascii_address) {
		const auto is_printable = [](unsigned char c) { return c >= 0x20 && c <= 0x7E; };
		return std::all_of(user_sv.begin(), user_sv.end(), is_printable) &&
					   std::all_of(domain_sv.begin(), domain_sv.end(), is_printable)
				   ? RSPAMD_SMTPUTF8_VALID
				   : RSPAMD_SMTPUTF8_CODE_POINT;
	}

	const auto context = get_contexto_properties(cps);

	/* Rule 2 admits SPACE on top of the IdentifierClass */
	for (std::size_t i = 0; i < cps.size(); i++) {
		auto cp = cps[i];

		if (cp == ' ') {
			continue;
		}

		if (is_contextj(cp)) {
			if (!contextj_ok(cps, i)) {
				return RSPAMD_SMTPUTF8_CODE_POINT;
			}
		}
		else if (is_contexto(cp)) {
			if (!contexto_ok(cps, i, context)) {
				return RSPAMD_SMTPUTF8_CODE_POINT;
			}
		}
		else if (script_of(cp) == script_code::none) {
			return RSPAMD_SMTPUTF8_CODE_POINT;
		}
	}

	if (!single_script(cps)) {
		return RSPAMD_SMTPUTF8_SCRIPTS;
	}

	if (!is_nfc(cps)) {
		return RSPAMD_SMTPUTF8_NOT_NFC;
	}

	return RSPAMD_SMTPUTF8_VALID;
}

const char *
rspamd_smtputf8_result_name(enum rspamd_smtputf8_syntax_result r)
{
	switch (r) {
	case RSPAMD_SMTPUTF8_VALID:
		return "valid";
	case RSPAMD_SMTPUTF8_BAD_UTF8:
		return "invalid UTF-8";
	case RSPAMD_SMTPUTF8_A_LABEL:
		return "a-label";
	case RSPAMD_SMTPUTF8_CODE_POINT:
		return "code point";
	case RSPAMD_SMTPUTF8_SCRIPTS:
		return "mixed scripts";
	case RSPAMD_SMTPUTF8_NOT_NFC:
		return "not NFC";
	}

	return "unknown";
}
