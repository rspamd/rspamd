#ifndef RSPAMD_RSPAMD_CXX_UNIT_SMTPUTF8_HXX
#define RSPAMD_RSPAMD_CXX_UNIT_SMTPUTF8_HXX

#define DOCTEST_CONFIG_IMPLEMENTATION_IN_DLL
#include "doctest/doctest.h"

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
			// geminada may be upper case
			{"CEL·LA@example.com", RSPAMD_SMTPUTF8_VALID},
			{"·la@example.com", RSPAMD_SMTPUTF8_CODE_POINT},
			// RFC5892 A.4: the keraia must precede a Greek letter
			{"͵α@example.com", RSPAMD_SMTPUTF8_VALID},
			{"͵a@example.com", RSPAMD_SMTPUTF8_CODE_POINT},
			// RFC5892 A.5: the geresh must follow a Hebrew letter
			{"א׳@example.com", RSPAMD_SMTPUTF8_VALID},
			{"a׳@example.com", RSPAMD_SMTPUTF8_CODE_POINT},
			// RFC5892 A.7: the katakana middle dot needs Japanese
			{"カ・ナ@example.com", RSPAMD_SMTPUTF8_VALID},
			{"a・b@example.com", RSPAMD_SMTPUTF8_CODE_POINT},
			// RFC5892 A.1 and A.2: the joiners are fine after a virama
			{"क्‌ष@example.com", RSPAMD_SMTPUTF8_VALID},
			{"क्‍ष@example.com", RSPAMD_SMTPUTF8_VALID},
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

	TEST_CASE("result names")
	{
		CHECK(std::string(rspamd_smtputf8_result_name(RSPAMD_SMTPUTF8_VALID)) == "valid");
		CHECK(std::string(rspamd_smtputf8_result_name(RSPAMD_SMTPUTF8_A_LABEL)) == "a-label");
		CHECK(std::string(rspamd_smtputf8_result_name(RSPAMD_SMTPUTF8_NOT_NFC)) == "not NFC");
	}
}

#endif
