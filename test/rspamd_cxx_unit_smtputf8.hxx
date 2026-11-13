#ifndef RSPAMD_RSPAMD_CXX_UNIT_SMTPUTF8_HXX
#define RSPAMD_RSPAMD_CXX_UNIT_SMTPUTF8_HXX

#define DOCTEST_CONFIG_IMPLEMENTATION_IN_DLL
#include "doctest/doctest.h"

#include <algorithm>
#include <ctime>
#include <string>
#include "libutil/cxx/smtputf8_syntax.h"

namespace {

// Splits at the last @ and strips the quotes from a quoted local part,
// which is the shape rspamd's address parser hands over.
rspamd_smtputf8_syntax_result
check_smtputf8(const std::string &address)
{
	auto at = address.rfind('@');
	REQUIRE(at != std::string::npos);
	auto user = address.substr(0, at);
	auto domain = address.substr(at + 1);
	bool quoted = user.size() >= 2 && user.front() == '"' && user.back() == '"';

	if (quoted) {
		user = user.substr(1, user.size() - 2);
	}

	return rspamd_smtputf8_check_address(user.data(), user.size(),
										 domain.data(), domain.size(),
										 quoted);
}

struct smtputf8_case {
	const char *address;
	rspamd_smtputf8_syntax_result expected;
};

constexpr auto a_label_domain = RSPAMD_SMTPUTF8_ACCEPT_A_LABEL_DOMAINS
									? RSPAMD_SMTPUTF8_VALID
									: RSPAMD_SMTPUTF8_A_LABEL;

}// namespace

TEST_SUITE("smtputf8 syntax")
{
	TEST_CASE("draft test vectors")
	{
		// tests.json from the draft's repository. The a-label domain
		// depends on RSPAMD_SMTPUTF8_ACCEPT_A_LABEL_DOMAINS.
		const smtputf8_case cases[] = {
			{"example@example.com", RSPAMD_SMTPUTF8_VALID},
			{"Example@example.com", RSPAMD_SMTPUTF8_VALID},
			{"dømi@dømi.fo", RSPAMD_SMTPUTF8_VALID},
			{"example@xn--gr-zia.example.com", a_label_domain},
			{"xn--gr-zia@example.com", RSPAMD_SMTPUTF8_A_LABEL},
			{"com.xn--gr-zia@example.com", RSPAMD_SMTPUTF8_A_LABEL},
			{"XN--GR-ZIA@example.com", RSPAMD_SMTPUTF8_A_LABEL},
			{"xn-gr@example.com", RSPAMD_SMTPUTF8_VALID},
			{"‎4@example.com", RSPAMD_SMTPUTF8_CODE_POINT},
			{"؜@example.com", RSPAMD_SMTPUTF8_CODE_POINT},
			{"‎@‏.‎", RSPAMD_SMTPUTF8_CODE_POINT},
			{"ali‮moc.elpmaxe@kravdraa.ec", RSPAMD_SMTPUTF8_CODE_POINT},
			{"🐪@example.com", RSPAMD_SMTPUTF8_CODE_POINT},
			{"adminㅤ@example.com", RSPAMD_SMTPUTF8_CODE_POINT},
			{"ＡＤＭＩＮ@example.com", RSPAMD_SMTPUTF8_CODE_POINT},
			{"名字️@example.com", RSPAMD_SMTPUTF8_CODE_POINT},
			{"مـحمد@example.com", RSPAMD_SMTPUTF8_CODE_POINT},
			{"각@example.com", RSPAMD_SMTPUTF8_CODE_POINT},
			{"각@example.com", RSPAMD_SMTPUTF8_VALID},
			{"IВM@dømi.fo", RSPAMD_SMTPUTF8_SCRIPTS},
			{"阿Q正传@dømi.fo", RSPAMD_SMTPUTF8_SCRIPTS},
			{"Толстой@example.com", RSPAMD_SMTPUTF8_VALID},
			{"名字@example.com", RSPAMD_SMTPUTF8_VALID},
			{"阿Q正传@阿Q正传.example", RSPAMD_SMTPUTF8_VALID},
			{"名字@例子.中国", RSPAMD_SMTPUTF8_VALID},
			{"info@例子.中国", RSPAMD_SMTPUTF8_VALID},
			{"उदाहरण@उदाहरण.भारत", RSPAMD_SMTPUTF8_VALID},
			{"gøril@example.com", RSPAMD_SMTPUTF8_VALID},
			{"ا@2ا.ا", RSPAMD_SMTPUTF8_VALID},
			{"ا@example.com", RSPAMD_SMTPUTF8_VALID},
			{"café@example.com", RSPAMD_SMTPUTF8_VALID},
			{"\"john.doe\"@example.com", RSPAMD_SMTPUTF8_VALID},
			{"\"john doe\"@example.com", RSPAMD_SMTPUTF8_VALID},
			{"grå\u0009​﻿­  　@grå.org",
			 RSPAMD_SMTPUTF8_CODE_POINT},
			{"cel·la@example.com", RSPAMD_SMTPUTF8_VALID},
			{"cex·xa@example.com", RSPAMD_SMTPUTF8_CODE_POINT},
			{"٠۰@example.com", RSPAMD_SMTPUTF8_CODE_POINT},
			{"まり子@まり子.日本", RSPAMD_SMTPUTF8_VALID},
			{"지훈@まり子.日本", RSPAMD_SMTPUTF8_SCRIPTS},
			{"中国互联网络信息中心域名注册服务部门联系人员@"
			 "北京市海淀区中关村南四街四号中国互联网络信息中心.中国",
			 RSPAMD_SMTPUTF8_VALID},
			{"example@[ipv6:2001:db8::8bd:1002]", RSPAMD_SMTPUTF8_VALID},
		};

		for (const auto &c: cases) {
			CAPTURE(c.address);
			CHECK(check_smtputf8(c.address) == c.expected);
		}
	}

	TEST_CASE("further cases")
	{
		const smtputf8_case cases[] = {
			// An 8-bit address with an a-label in its domain, as Exchange
			// writes it
			{"grå@xn--gr-zia.org", a_label_domain},
			{"grå@XN--GR-ZIA.org", a_label_domain},
			// A domain that mixes u-labels and a-labels is invalid either
			// way, and so are the local part's a-labels
			{"grå@grå.xn--fiqs8s", RSPAMD_SMTPUTF8_A_LABEL},
			{"xn--gr-zia@grå.org", RSPAMD_SMTPUTF8_A_LABEL},
			// An ACE prefix only counts when the whole atom is an IDNA2008 A-label.
			{"xn--café@example.com", RSPAMD_SMTPUTF8_VALID},
			{"xn--team+sales@example.com", RSPAMD_SMTPUTF8_VALID},
			{"xn--@example.com", RSPAMD_SMTPUTF8_VALID},
			{"xn--abc-@example.com", RSPAMD_SMTPUTF8_VALID},
			{"xn--a@example.com", RSPAMD_SMTPUTF8_VALID},
			{"xn--e28h@example.com", RSPAMD_SMTPUTF8_VALID},    // emoji
			{"xn--a-0hc@example.com", RSPAMD_SMTPUTF8_VALID},   // Latin and Hebrew, violates Bidi
			{"xn--9ca58h@example.com", RSPAMD_SMTPUTF8_VALID},  // leading combining mark
			{"xn--ab-m1t@example.com", RSPAMD_SMTPUTF8_VALID},  // joiner without context
			{"xn--ngbn6f@example.com", RSPAMD_SMTPUTF8_A_LABEL},// دبي
			{"xn--7q1dqd@example.com", RSPAMD_SMTPUTF8_A_LABEL},// Tulu-Tigalari
			// A quoted string is not an atom, so rule 1 does not reach it
			{"\"xn--gr-zia\"@example.com", RSPAMD_SMTPUTF8_VALID},
			// Latin-1, an overlong slash and a surrogate are not UTF-8
			{"gr\xe5@example.com", RSPAMD_SMTPUTF8_BAD_UTF8},
			{"a\xc0\xaf"
			 "b@example.com",
			 RSPAMD_SMTPUTF8_BAD_UTF8},
			{"a\xed\xa0\x80"
			 "b@example.com",
			 RSPAMD_SMTPUTF8_BAD_UTF8},
			// DEL and controls are outside rule 2
			{"a\x7f"
			 "b@example.com",
			 RSPAMD_SMTPUTF8_CODE_POINT},
			// The IdentifierClass does not fold case, so the ela
			// geminada may be upper case, but it still needs an l or L
			// on each side
			{"CEL·LA@example.com", RSPAMD_SMTPUTF8_VALID},
			{"cel·La@example.com", RSPAMD_SMTPUTF8_VALID},
			{"ceL·la@example.com", RSPAMD_SMTPUTF8_VALID},
			{"CE·LA@example.com", RSPAMD_SMTPUTF8_CODE_POINT},
			{"·la@example.com", RSPAMD_SMTPUTF8_CODE_POINT},
			// RFC5892 A.4: the keraia must precede a Greek letter
			{"͵α@example.com", RSPAMD_SMTPUTF8_VALID},
			{"͵a@example.com", RSPAMD_SMTPUTF8_CODE_POINT},
			// RFC5892 A.5: the geresh must follow a Hebrew letter
			{"א׳@example.com", RSPAMD_SMTPUTF8_VALID},
			{"a׳@example.com", RSPAMD_SMTPUTF8_CODE_POINT},
			// RFC5892 A.7: the katakana middle dot needs Japanese
			{"カ・ナ@example.com", RSPAMD_SMTPUTF8_VALID},
			{"・・カ@example.com", RSPAMD_SMTPUTF8_VALID},
			{"a・b@example.com", RSPAMD_SMTPUTF8_CODE_POINT},
			// RFC5892 A.8 and A.9: either set of digits, but not both, even
			// far apart
			{"٠١٢@example.com", RSPAMD_SMTPUTF8_VALID},
			{"۰۱۲@example.com", RSPAMD_SMTPUTF8_VALID},
			{"٠ب@ب۰.example", RSPAMD_SMTPUTF8_CODE_POINT},
			// RFC5892 A.1 and A.2: the joiners are fine after a virama
			{"क्‌ष@example.com", RSPAMD_SMTPUTF8_VALID},
			{"क्‍ष@example.com", RSPAMD_SMTPUTF8_VALID},
			{"\U00011392\U000113ce\u200d\U00011392@example.com", RSPAMD_SMTPUTF8_VALID},
			{"\U00011392\U000113c2\U000113b8@example.com", RSPAMD_SMTPUTF8_NOT_NFC},
			{"\U00011392\U000113c7@example.com", RSPAMD_SMTPUTF8_VALID},
			{"Ḋ\u0323@example.com", RSPAMD_SMTPUTF8_NOT_NFC},     /* reorder inside a composed starter */
			{"a\u0305\u0301@example.com", RSPAMD_SMTPUTF8_VALID}, /* equal classes block composition */
			{"a‍b@example.com", RSPAMD_SMTPUTF8_CODE_POINT},
			// RFC5892 A.1: ZWNJ is also fine between joining letters
			{"ب‌ب@example.com", RSPAMD_SMTPUTF8_VALID},
			// Han may be mixed with Bopomofo, but not Hangul with kana
			{"中ㄅ@example.com", RSPAMD_SMTPUTF8_VALID},
			{"각カ@example.com", RSPAMD_SMTPUTF8_SCRIPTS},
			// Combining marks belong to whatever script they follow
			{"उदाहरण@example.com", RSPAMD_SMTPUTF8_VALID},
		};

		for (const auto &c: cases) {
			CAPTURE(c.address);
			CHECK(check_smtputf8(c.address) == c.expected);
		}
	}

	TEST_CASE("long contextual addresses")
	{
		const auto repeat = [](const std::string &cp) {
			std::string result;
			result.reserve(32768 * cp.size());
			for (int i = 0; i < 32768; i++) {
				result.append(cp);
			}
			return result;
		};

		const auto arabic = repeat("٠");
		const auto extended_arabic = repeat("۰");
		const auto middle_dots = repeat("・");

		CHECK(check_smtputf8(arabic + "@example.com") == RSPAMD_SMTPUTF8_VALID);
		CHECK(check_smtputf8(extended_arabic + "@example.com") == RSPAMD_SMTPUTF8_VALID);
		CHECK(check_smtputf8(arabic + "@۰.example") == RSPAMD_SMTPUTF8_CODE_POINT);
		CHECK(check_smtputf8(extended_arabic + "@٠.example") == RSPAMD_SMTPUTF8_CODE_POINT);
		CHECK(check_smtputf8(middle_dots + "@日.example") == RSPAMD_SMTPUTF8_VALID);
		CHECK(check_smtputf8(middle_dots + "@example.com") == RSPAMD_SMTPUTF8_CODE_POINT);
	}

	// Tripling the input should roughly triple the time. Test
	// that by testing a few long strings, short-long-short-long,
	// and checking that the time difference stays below a factor
	// of seven. Random scheduler variation makes this difficult
	// to test, but using the fastest of a few runs, interspersing
	// the short and long runs, and using a limit more than twice
	// the expected behaviour makes the test reliable. Quadratic
	// code implies a factor of nine, so if this test is flaky,
	// the most likely cause is a combination of quadratic code
	// and a great optimiser.
	//
	// Very loosely based on
	// https://github.com/arnt/uts58/blob/main/javascript/test/timing.test.js
	TEST_CASE("runtime scales roughly linearly, not quadratically")
	{
		const auto repeat = [](const std::string &s, int n) {
			std::string result;
			result.reserve(n * s.size());
			for (int i = 0; i < n; i++) {
				result.append(s);
			}
			return result;
		};
		const auto cpu_ms = [](const std::string &address) {
			timespec start, end;
			clock_gettime(CLOCK_THREAD_CPUTIME_ID, &start);
			check_smtputf8(address);
			clock_gettime(CLOCK_THREAD_CPUTIME_ID, &end);
			return (end.tv_sec - start.tv_sec) * 1e3 +
				   (end.tv_nsec - start.tv_nsec) / 1e6;
		};
		const struct {
			std::string rule;
			std::string unit;
			std::string tail;
		} inputs[] = {
			// Each dot needs Japanese, which comes last
			{"RFC5892 A.7", "・", "@日.example"},
			// Each digit needs the absence of the other set
			{"RFC5892 A.8", "٠", "@example.com"},
			// Each ZWNJ looks at its neighbours' joining types
			{"RFC5892 A.1", "ب‌", "ب@example.com"},
			// Script lookups and NFC
			{"rules 2 to 4", "中", "@例子.中国"},
		};

		for (const auto &input: inputs) {
			const auto build = [&](int n) {
				return repeat(input.unit, n) + input.tail;
			};
			REQUIRE(check_smtputf8(build(10)) == RSPAMD_SMTPUTF8_VALID);
			cpu_ms(build(1000));// warm the CPU cache(s)

			const auto small = build(2000), large = build(6000);
			double t1 = 1e9, t2 = 1e9;
			for (int i = 0; i < 7; i++) {
				t1 = std::min(t1, cpu_ms(small));
				t2 = std::min(t2, cpu_ms(large));
			}
			CAPTURE(input.rule);
			CAPTURE(t1);
			CAPTURE(t2);
			CHECK(t2 / t1 < 7);
		}
	}

	TEST_CASE("result names")
	{
		CHECK(std::string(rspamd_smtputf8_result_name(RSPAMD_SMTPUTF8_VALID)) == "valid");
		CHECK(std::string(rspamd_smtputf8_result_name(RSPAMD_SMTPUTF8_A_LABEL)) == "a-label");
		CHECK(std::string(rspamd_smtputf8_result_name(RSPAMD_SMTPUTF8_NOT_NFC)) == "not NFC");
	}
}

#endif
