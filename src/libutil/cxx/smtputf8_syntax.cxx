#define U_CHARSET_IS_UTF8 1
#include <unicode/utypes.h>
#include <unicode/utf8.h>
#include <algorithm>
#include <array>
#include <cstdint>
#include <iterator>
#include <limits>
#include <initializer_list>
#include <string_view>
#include <vector>

#include "smtputf8_syntax.h"
#include "smtputf8_data.hxx"
extern "C" {
#include "contrib/librdns/punycode.h"
}

namespace {

using script_code = rspamd::smtputf8::script;
using namespace rspamd::smtputf8;

auto properties_of(char32_t cp) -> const properties &
{
	static_assert(ranges[0].first == 0);
	auto it = std::upper_bound(std::begin(ranges), std::end(ranges), cp,
							   [](char32_t c, const property_range &r) { return c < r.first; });
	return property_values[(it - 1)->index];
}

using codepoints = std::vector<std::uint32_t>;

auto decode_utf8(std::string_view s, codepoints &out) -> bool
{
	/* ICU takes offsets as int32_t; older versions pass them by pointer */
	if (s.size() > static_cast<std::size_t>(std::numeric_limits<std::int32_t>::max())) {
		return false;
	}

	std::int32_t i = 0;
	auto len = static_cast<std::int32_t>(s.size());

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

auto script_of(UChar32 cp) -> script_code
{
	return properties_of(cp).sc;
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

/* RFC5892 A.1 and A.2 */
auto contextj_ok(const codepoints &cps, std::size_t i) -> bool
{
	if (i > 0 && properties_of(cps[i - 1]).ccc == 9) {
		return true;
	}

	if (cps[i] != 0x200C) {
		return false;
	}

	/* (Joining_Type:{L,D})(Joining_Type:T)*‌(Joining_Type:T)*(Joining_Type:{R,D}) */
	auto before = i;

	while (before > 0 && properties_of(cps[before - 1]).jt == joining::transparent) {
		before--;
	}

	if (before == 0) {
		return false;
	}

	auto left = properties_of(cps[before - 1]).jt;

	if (left != joining::left && left != joining::dual) {
		return false;
	}

	auto after = i + 1;

	while (after < cps.size() && properties_of(cps[after]).jt == joining::transparent) {
		after++;
	}

	if (after == cps.size()) {
		return false;
	}

	auto right = properties_of(cps[after]).jt;

	return right == joining::right || right == joining::dual;
}

struct contexto_properties {
	bool arabic_indic = false;
	bool extended_arabic_indic = false;
	bool japanese = false;
};

/* Compute address-wide context once, rather than rescanning for each character. */
auto get_contexto_properties(const codepoints &cps) -> contexto_properties
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
auto contexto_ok(const codepoints &cps, std::size_t i,
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
auto single_script(const codepoints &cps) -> bool
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

/* PRECIS and IDNA both exclude NFC_QC=No and conjoining Hangul jamo.
 * Check canonical order and whether an unblocked character changes the
 * starter. The table includes pairs whose starter is already composed. */
auto is_nfc(const codepoints &cps) -> bool
{
	char32_t starter = 0;
	unsigned last_ccc = 0;
	for (auto cp: cps) {
		const auto &p = properties_of(cp);
		if (p.ccc != 0 && last_ccc > p.ccc) {
			return false;
		}
		if (p.nfc_maybe && (last_ccc == 0 || last_ccc < p.ccc) &&
			std::binary_search(std::begin(non_nfc_pairs), std::end(non_nfc_pairs), pair_key(starter, cp))) {
			return false;
		}
		if (p.ccc == 0) {
			starter = cp;
		}
		last_ccc = p.ccc;
	}
	return true;
}

/* For a single label RFC5893 is triggered by R, AL or AN. */
auto valid_ulabel(const codepoints &cps) -> bool
{
	if (cps.empty() || cps.front() == '-' || cps.back() == '-' ||
		(cps.size() >= 4 && cps[2] == '-' && cps[3] == '-') ||
		properties_of(cps.front()).leading_mark) {
		return false;
	}

	const auto context = get_contexto_properties(cps);
	bool has_rtl = false, european_number = false, arabic_number = false, other = false;
	auto last = bidi::other;
	for (std::size_t i = 0; i < cps.size(); ++i) {
		auto cp = cps[i];
		const auto &p = properties_of(cp);
		if (!p.idna_allowed || (is_contextj(cp) && !contextj_ok(cps, i)) ||
			(is_contexto(cp) && !contexto_ok(cps, i, context))) {
			return false;
		}

		has_rtl |= p.direction == bidi::rtl;
		arabic_number |= p.direction == bidi::arabic_number;
		european_number |= p.direction == bidi::european_number;
		other |= p.direction == bidi::other;
		if (p.direction != bidi::mark) {
			last = p.direction;
		}
	}
	if (has_rtl || arabic_number) {
		if (properties_of(cps.front()).direction != bidi::rtl || other ||
			(arabic_number && european_number) ||
			(last != bidi::rtl && last != bidi::arabic_number && last != bidi::european_number)) {
			return false;
		}
	}
	return is_nfc(cps);
}

auto is_a_label(std::string_view atom) -> bool
{
	if (atom.size() <= 4 || atom.size() > 63 || g_ascii_strncasecmp(atom.data(), "xn--", 4) != 0) {
		return false;
	}
	std::array<char, 64> ascii{};
	for (std::size_t i = 0; i < atom.size(); ++i) {
		auto c = atom[i];
		if (!g_ascii_isalnum(c) && c != '-') {
			return false;
		}
		ascii[i] = g_ascii_tolower(c);
	}

	gchar *decoded = g_hostname_to_unicode(ascii.data());
	if (decoded == nullptr) {
		return false;
	}
	codepoints label;
	bool valid = decode_utf8(decoded, label);
	g_free(decoded);
	if (!valid || std::none_of(label.begin(), label.end(), [](auto cp) { return cp >= 0x80; }) ||
		!valid_ulabel(label)) {
		return false;
	}
	/* RFC5890 requires the decoded U-label to round-trip to the A-label. */
	std::array<char, 64> encoded{};
	auto len = encoded.size();
	return rdns_punycode_label_toascii(label.data(), label.size(), encoded.data(), &len) &&
		   len == atom.size() && std::equal(encoded.begin(), encoded.begin() + len, ascii.begin());
}

auto has_a_label(std::string_view s) -> bool
{
	for (;;) {
		auto end = s.find('.');
		if (is_a_label(s.substr(0, end))) {
			return true;
		}
		if (end == s.npos) {
			return false;
		}
		s.remove_prefix(end + 1);
	}
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
	codepoints cps;

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
