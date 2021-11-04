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

/* Detached unit tests for the dkim utils */

#ifndef RSPAMD_RSPAMD_CXX_UNIT_DKIM_HXX
#define RSPAMD_RSPAMD_CXX_UNIT_DKIM_HXX

#define DOCTEST_CONFIG_IMPLEMENTATION_IN_DLL
#include "doctest/doctest.h"

#include "libserver/dkim.h"

#include <vector>
#include <utility>
#include <string>
#include <tuple>

TEST_SUITE("rspamd_dkim") {

TEST_CASE("rspamd_dkim_parse_key")
{
	struct test_case {
		std::string input;
		bool is_valid;
		std::string expected_id;
	};
	std::vector<test_case> cases{
			{"p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCA"
			 "QEA5CeQZpoPbsS8lG41UI1rxTtOSqPrfgZzhrZsk0t9dIbFTvaoql/FLuYcbdUARc"
			 "5zuyXsDj1eSprOgcPT9PY9RoSUsY8i/jnD49DHXtMfXoBk0J6epNzbZqqWU+"
			 "TG02HwWNy/kf1h+OlAGQKJLgakivZ3nMMnUIPHkUjwvhbkaMXCI046XoqsEQ7KW"
			 "VKRoF3cK1cFXLo+bgO3sEJgGtvwzPodG0CqVu+gjehrjwdLnPhqyEspfI1IbL"
			 "lnNaq5pWei/B8pG6teV+y3t4yay5ZGktALJjlylKHVo2USkVYQTFQ9Ji25m2jupdCd"
			 "kn1FTuYNqh0Nzg3KPQHNVp7mlE7lfwIDAQAB",
			 true, "e40cc5c40ee29cb4f21d95c7f0dc9989"},
			 // Spaces before p
			{"   p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCA"
			 "QEA5CeQZpoPbsS8lG41UI1rxTtOSqPrfgZzhrZsk0t9dIbFTvaoql/FLuYcbdUARc"
			 "5zuyXsDj1eSprOgcPT9PY9RoSUsY8i/jnD49DHXtMfXoBk0J6epNzbZqqWU+"
			 "TG02HwWNy/kf1h+OlAGQKJLgakivZ3nMMnUIPHkUjwvhbkaMXCI046XoqsEQ7KW"
			 "VKRoF3cK1cFXLo+bgO3sEJgGtvwzPodG0CqVu+gjehrjwdLnPhqyEspfI1IbL"
			 "lnNaq5pWei/B8pG6teV+y3t4yay5ZGktALJjlylKHVo2USkVYQTFQ9Ji25m2jupdCd"
			 "kn1FTuYNqh0Nzg3KPQHNVp7mlE7lfwIDAQAB",
			 true, "e40cc5c40ee29cb4f21d95c7f0dc9989"},
			// Spaces and bogus semicolon before p
			{";  p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCA"
			 "QEA5CeQZpoPbsS8lG41UI1rxTtOSqPrfgZzhrZsk0t9dIbFTvaoql/FLuYcbdUARc"
			 "5zuyXsDj1eSprOgcPT9PY9RoSUsY8i/jnD49DHXtMfXoBk0J6epNzbZqqWU+"
			 "TG02HwWNy/kf1h+OlAGQKJLgakivZ3nMMnUIPHkUjwvhbkaMXCI046XoqsEQ7KW"
			 "VKRoF3cK1cFXLo+bgO3sEJgGtvwzPodG0CqVu+gjehrjwdLnPhqyEspfI1IbL"
			 "lnNaq5pWei/B8pG6teV+y3t4yay5ZGktALJjlylKHVo2USkVYQTFQ9Ji25m2jupdCd"
			 "kn1FTuYNqh0Nzg3KPQHNVp7mlE7lfwIDAQAB",
					true, "e40cc5c40ee29cb4f21d95c7f0dc9989"},
			 // Spaces after p
			{"k=rsa; t=s; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCA"
			 "QEA5CeQZpoPbsS8lG41UI1rxTtOSqPrfgZzhrZsk0t9dIbFTvaoql/FLuYcbdUARc"
			 "5zuyXsDj1eSprOgcPT9PY9RoSUsY8i/jnD49DHXtMfXoBk0J6epNzbZqqWU+"
			 "TG02HwWNy/kf1h+OlAGQKJLgakivZ3nMMnUIPHkUjwvhbkaMXCI046XoqsEQ7KW"
			 "VKRoF3cK1cFXLo+bgO3sEJgGtvwzPodG0CqVu+gjehrjwdLnPhqyEspfI1IbL"
			 "lnNaq5pWei/B8pG6teV+y3t4yay5ZGktALJjlylKHVo2USkVYQTFQ9Ji25m2jupdCd"
			 "kn1FTuYNqh0Nzg3KPQHNVp7mlE7lfwIDAQAB      ",
			 true, "e40cc5c40ee29cb4f21d95c7f0dc9989"},
			// ; and spaces
			{"k=rsa; t=s; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCA"
			 "QEA5CeQZpoPbsS8lG41UI1rxTtOSqPrfgZzhrZsk0t9dIbFTvaoql/FLuYcbdUARc"
			 "5zuyXsDj1eSprOgcPT9PY9RoSUsY8i/jnD49DHXtMfXoBk0J6epNzbZqqWU+"
			 "TG02HwWNy/kf1h+OlAGQKJLgakivZ3nMMnUIPHkUjwvhbkaMXCI046XoqsEQ7KW"
			 "VKRoF3cK1cFXLo+bgO3sEJgGtvwzPodG0CqVu+gjehrjwdLnPhqyEspfI1IbL"
			 "lnNaq5pWei/B8pG6teV+y3t4yay5ZGktALJjlylKHVo2USkVYQTFQ9Ji25m2jupdCd"
			 "kn1FTuYNqh0Nzg3KPQHNVp7mlE7lfwIDAQAB  ;    ",
			 true, "e40cc5c40ee29cb4f21d95c7f0dc9989"},
			// ; and spaces around '=' sign
			{"k=rsa; t=s; p =   MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCA"
			 "QEA5CeQZpoPbsS8lG41UI1rxTtOSqPrfgZzhrZsk0t9dIbFTvaoql/FLuYcbdUARc"
			 "5zuyXsDj1eSprOgcPT9PY9RoSUsY8i/jnD49DHXtMfXoBk0J6epNzbZqqWU+"
			 "TG02HwWNy/kf1h+OlAGQKJLgakivZ3nMMnUIPHkUjwvhbkaMXCI046XoqsEQ7KW"
			 "VKRoF3cK1cFXLo+bgO3sEJgGtvwzPodG0CqVu+gjehrjwdLnPhqyEspfI1IbL"
			 "lnNaq5pWei/B8pG6teV+y3t4yay5ZGktALJjlylKHVo2USkVYQTFQ9Ji25m2jupdCd"
			 "kn1FTuYNqh0Nzg3KPQHNVp7mlE7lfwIDAQAB;",
			 true, "e40cc5c40ee29cb4f21d95c7f0dc9989"},
			// ; and spaces around '=' sign + bad stuff
			{"ololo k=rsa; t=s; p =   MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCA"
			 "QEA5CeQZpoPbsS8lG41UI1rxTtOSqPrfgZzhrZsk0t9dIbFTvaoql/FLuYcbdUARc"
			 "5zuyXsDj1eSprOgcPT9PY9RoSUsY8i/jnD49DHXtMfXoBk0J6epNzbZqqWU+"
			 "TG02HwWNy/kf1h+OlAGQKJLgakivZ3nMMnUIPHkUjwvhbkaMXCI046XoqsEQ7KW"
			 "VKRoF3cK1cFXLo+bgO3sEJgGtvwzPodG0CqVu+gjehrjwdLnPhqyEspfI1IbL"
			 "lnNaq5pWei/B8pG6teV+y3t4yay5ZGktALJjlylKHVo2USkVYQTFQ9Ji25m2jupdCd"
			 "kn1FTuYNqh0Nzg3KPQHNVp7mlE7lfwIDAQAB;",
			 true, "e40cc5c40ee29cb4f21d95c7f0dc9989"},
			// ; and spaces around '=' sign + bad stuff
			{"ololo=trololo; k=rsa; t=s; "
			 "p =   MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCA"
			 "QEA5CeQZpoPbsS8lG41UI1rxTtOSqPrfgZzhrZsk0t9dIbFTvaoql/FLuYcbdUARc"
			 "5zuyXsDj1eSprOgcPT9PY9RoSUsY8i/jnD49DHXtMfXoBk0J6epNzbZqqWU+"
			 "TG02HwWNy/kf1h+OlAGQKJLgakivZ3nMMnUIPHkUjwvhbkaMXCI046XoqsEQ7KW"
			 "VKRoF3cK1cFXLo+bgO3sEJgGtvwzPodG0CqVu+gjehrjwdLnPhqyEspfI1IbL"
			 "lnNaq5pWei/B8pG6teV+y3t4yay5ZGktALJjlylKHVo2USkVYQTFQ9Ji25m2jupdCd"
			 "kn1FTuYNqh0Nzg3KPQHNVp7mlE7lfwIDAQAB ",
			 true, "e40cc5c40ee29cb4f21d95c7f0dc9989"},
			 // Invalid RSA
			{"ololo=trololo; k=rsa; t=s; "
			 "p =   BADMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCA"
			 "QEA5CeQZpoPbsS8lG41UI1rxTtOSqPrfgZzhrZsk0t9dIbFTvaoql/FLuYcbdUARc"
			 "5zuyXsDj1eSprOgcPT9PY9RoSUsY8i/jnD49DHXtMfXoBk0J6epNzbZqqWU+"
			 "TG02HwWNy/kf1h+OlAGQKJLgakivZ3nMMnUIPHkUjwvhbkaMXCI046XoqsEQ7KW"
			 "VKRoF3cK1cFXLo+bgO3sEJgGtvwzPodG0CqVu+gjehrjwdLnPhqyEspfI1IbL"
			 "lnNaq5pWei/B8pG6teV+y3t4yay5ZGktALJjlylKHVo2USkVYQTFQ9Ji25m2jupdCd"
			 "kn1FTuYNqh0Nzg3KPQHNVp7mlE7lfwIDAQAB ",
			 false, ""},
			// Invalid RSA for eddsa
			{"ololo=trololo; k=ed25519; t=s; "
			 "p =   MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCA"
			 "QEA5CeQZpoPbsS8lG41UI1rxTtOSqPrfgZzhrZsk0t9dIbFTvaoql/FLuYcbdUARc"
			 "5zuyXsDj1eSprOgcPT9PY9RoSUsY8i/jnD49DHXtMfXoBk0J6epNzbZqqWU+"
			 "TG02HwWNy/kf1h+OlAGQKJLgakivZ3nMMnUIPHkUjwvhbkaMXCI046XoqsEQ7KW"
			 "VKRoF3cK1cFXLo+bgO3sEJgGtvwzPodG0CqVu+gjehrjwdLnPhqyEspfI1IbL"
			 "lnNaq5pWei/B8pG6teV+y3t4yay5ZGktALJjlylKHVo2USkVYQTFQ9Ji25m2jupdCd"
			 "kn1FTuYNqh0Nzg3KPQHNVp7mlE7lfwIDAQAB ",
			 false, ""},
	};

	for (auto &&c : cases) {
		SUBCASE (("process DKIM record " + c.input).c_str()) {
			gsize klen = c.input.size();
			auto *key = rspamd_dkim_parse_key(c.input.c_str(), &klen, nullptr);
			if (c.is_valid) {
				CHECK(key != nullptr);
				char hexbuf[RSPAMD_DKIM_KEY_ID_LEN * 2 + 1];
				auto *id = rspamd_dkim_key_id(key);
				auto hexlen = rspamd_encode_hex_buf(id, RSPAMD_DKIM_KEY_ID_LEN, hexbuf,
						sizeof(hexbuf));
				CHECK(hexlen > 0);
				CHECK(std::string{hexbuf, (std::size_t) hexlen} == c.expected_id);
				rspamd_dkim_key_free(key);
			}
			else {
				CHECK(key == nullptr);
			}
		}
	}
}

}

#endif
