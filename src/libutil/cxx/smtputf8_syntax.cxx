#define U_CHARSET_IS_UTF8 1
#include <unicode/utypes.h>
#include <unicode/utf8.h>
#include <unicode/uchar.h>
#include <unicode/uscript.h>
#include <unicode/normalizer2.h>
#include <unicode/unistr.h>
#include <algorithm>
#include <initializer_list>
#include <string_view>
#include <vector>

#include "smtputf8_syntax.h"

namespace {

enum class precis_class {
	pvalid,
	contextj,
	contexto,
	disallowed,
};

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

/*
 * NFKC changes the code point. A precomposed é decomposes canonically but
 * recomposes, so it is not HasCompat, and the decomposition mapping alone
 * cannot answer this.
 */
auto has_compat(UChar32 cp) -> bool
{
	UErrorCode uc_err = U_ZERO_ERROR;
	const auto *nfkc = icu::Normalizer2::getNFKCInstance(uc_err);

	if (U_FAILURE(uc_err)) {
		return true;
	}

	auto normalized = nfkc->isNormalized(icu::UnicodeString(cp), uc_err);

	return U_FAILURE(uc_err) || !normalized;
}

/*
 * The derived property from RFC8264 8, for the IdentifierClass, in the
 * order RFC8264 gives. The exceptions are from RFC5892 2.6.
 */
auto identifier_class(UChar32 cp) -> precis_class
{
	switch (cp) {
	case 0x00DF:
	case 0x03C2:
	case 0x06FD:
	case 0x06FE:
	case 0x0F0B:
	case 0x3007:
		return precis_class::pvalid;
	case 0x00B7:
	case 0x0375:
	case 0x05F3:
	case 0x05F4:
	case 0x30FB:
		return precis_class::contexto;
	case 0x0640:
	case 0x07FA:
	case 0x302E:
	case 0x302F:
	case 0x3031:
	case 0x3032:
	case 0x3033:
	case 0x3034:
	case 0x3035:
	case 0x303B:
		return precis_class::disallowed;
	default:
		break;
	}

	if ((cp >= 0x0660 && cp <= 0x0669) || (cp >= 0x06F0 && cp <= 0x06F9)) {
		return precis_class::contexto;
	}

	auto gc = u_charType(cp);

	if (gc == U_UNASSIGNED) {
		return precis_class::disallowed;
	}

	if (cp >= 0x21 && cp <= 0x7E) {
		return precis_class::pvalid;
	}

	if (u_hasBinaryProperty(cp, UCHAR_JOIN_CONTROL)) {
		return precis_class::contextj;
	}

	auto hst = u_getIntPropertyValue(cp, UCHAR_HANGUL_SYLLABLE_TYPE);

	if (hst == U_HST_LEADING_JAMO || hst == U_HST_VOWEL_JAMO ||
		hst == U_HST_TRAILING_JAMO) {
		return precis_class::disallowed;
	}

	if (u_hasBinaryProperty(cp, UCHAR_DEFAULT_IGNORABLE_CODE_POINT) ||
		u_hasBinaryProperty(cp, UCHAR_NONCHARACTER_CODE_POINT) ||
		gc == U_CONTROL_CHAR || has_compat(cp)) {
		return precis_class::disallowed;
	}

	switch (gc) {
	case U_LOWERCASE_LETTER:
	case U_UPPERCASE_LETTER:
	case U_OTHER_LETTER:
	case U_DECIMAL_DIGIT_NUMBER:
	case U_MODIFIER_LETTER:
	case U_NON_SPACING_MARK:
	case U_COMBINING_SPACING_MARK:
		return precis_class::pvalid;
	default:
		/* Spaces, symbols, punctuation and other letter-digits */
		return precis_class::disallowed;
	}
}

auto script_of(UChar32 cp) -> UScriptCode
{
	UErrorCode uc_err = U_ZERO_ERROR;
	auto script = uscript_getScript(cp, &uc_err);

	return U_FAILURE(uc_err) ? USCRIPT_INVALID_CODE : script;
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

			if (script == USCRIPT_HIRAGANA || script == USCRIPT_KATAKANA ||
				script == USCRIPT_HAN) {
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
		/* A.3 requires U+006C on both sides, without case folding. */
		return i > 0 && i + 1 < cps.size() &&
			   cps[i - 1] == 'l' && cps[i + 1] == 'l';
	}

	if (cp == 0x0375) {
		return i + 1 < cps.size() && script_of(cps[i + 1]) == USCRIPT_GREEK;
	}

	if (cp == 0x05F3 || cp == 0x05F4) {
		return i > 0 && script_of(cps[i - 1]) == USCRIPT_HEBREW;
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

auto within(const std::vector<UScriptCode> &used,
			std::initializer_list<UScriptCode> family) -> bool
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
	std::vector<UScriptCode> used;

	for (auto cp: cps) {
		if (cp < 0x80) {
			continue;
		}

		auto script = script_of(cp);

		if (script == USCRIPT_COMMON || script == USCRIPT_INHERITED) {
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
		   within(used, {USCRIPT_HAN, USCRIPT_HIRAGANA, USCRIPT_KATAKANA}) ||
		   within(used, {USCRIPT_HAN, USCRIPT_HANGUL}) ||
		   within(used, {USCRIPT_HAN, USCRIPT_BOPOMOFO});
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
		if (cps[i] == ' ') {
			continue;
		}

		switch (identifier_class(cps[i])) {
		case precis_class::pvalid:
			break;
		case precis_class::contextj:
			if (!contextj_ok(cps, i)) {
				return RSPAMD_SMTPUTF8_CODE_POINT;
			}
			break;
		case precis_class::contexto:
			if (!contexto_ok(cps, i, context)) {
				return RSPAMD_SMTPUTF8_CODE_POINT;
			}
			break;
		case precis_class::disallowed:
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
