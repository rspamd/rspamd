/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy at https://www.apache.org/licenses/LICENSE-2.0
 */

/* An SMTP address is valid only if the whole input is the address */

#ifndef RSPAMD_CXX_UNIT_EMAIL_ADDR_HXX
#define RSPAMD_CXX_UNIT_EMAIL_ADDR_HXX

#define DOCTEST_CONFIG_IMPLEMENTATION_IN_DLL
#include "doctest/doctest.h"

#include "config.h"
#include "libmime/email_addr.h"

#include <cstring>
#include <string>

namespace rspamd_email_addr_test {

/* The address part of a parsed SMTP address, or "<invalid>" if it is rejected */
static std::string smtp_addr(const char *in)
{
	auto *addr = rspamd_email_address_from_smtp(in, strlen(in));

	if (addr == nullptr) {
		return "<invalid>";
	}

	std::string res(addr->addr, addr->addr_len);
	rspamd_email_address_free(addr);

	return res;
}

}// namespace rspamd_email_addr_test

TEST_SUITE("smtp address parser")
{
	TEST_CASE("whole input is the address")
	{
		using rspamd_email_addr_test::smtp_addr;

		CHECK(smtp_addr("<a@b.c>") == "a@b.c");
		CHECK(smtp_addr("a@b.c") == "a@b.c");
		CHECK(smtp_addr(" <a@b.c>  ") == "a@b.c");
		CHECK(smtp_addr("\t<a@b.c>\r\n") == "a@b.c");
	}

	TEST_CASE("empty address")
	{
		auto *addr = rspamd_email_address_from_smtp("<>", 2);

		REQUIRE(addr != nullptr);
		CHECK((addr->flags & RSPAMD_EMAIL_ADDR_VALID) != 0);
		CHECK((addr->flags & RSPAMD_EMAIL_ADDR_EMPTY) != 0);
		CHECK(addr->addr_len == 0);
		rspamd_email_address_free(addr);
	}

	TEST_CASE("trailing text makes the address invalid")
	{
		using rspamd_email_addr_test::smtp_addr;

		CHECK(smtp_addr("<a@b.c> junk") == "<invalid>");
		CHECK(smtp_addr("<a@b.c> SIZE=123") == "<invalid>");
		CHECK(smtp_addr("a@b.c x@y.z") == "<invalid>");
		CHECK(smtp_addr("<a@b.c>x") == "<invalid>");
		CHECK(smtp_addr("<> junk") == "<invalid>");
	}
}

#endif// RSPAMD_CXX_UNIT_EMAIL_ADDR_HXX
