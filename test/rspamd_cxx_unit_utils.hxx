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

/* Detached unit tests for the utils */

#ifndef RSPAMD_RSPAMD_CXX_UNIT_UTILS_HXX
#define RSPAMD_RSPAMD_CXX_UNIT_UTILS_HXX

#define DOCTEST_CONFIG_IMPLEMENTATION_IN_DLL
#include "doctest/doctest.h"

#include "libmime/mime_headers.h"
#include "libutil/cxx/local_shared_ptr.hxx"
#include <vector>
#include <utility>
#include <string>

TEST_SUITE("rspamd utils") {

TEST_CASE("rspamd_strip_smtp_comments_inplace")
{
	std::vector<std::pair<std::string, std::string>> cases{
			{"abc",                    "abc"},
			{"abc(foo)",               "abc"},
			{"abc(foo()",              "abc"},
			{"abc(foo))",              "abc)"},
			{"abc(foo(bar))",          "abc"},
			{"(bar)abc(foo)",          "abc"},
			{"ab(ololo)c(foo)",        "abc"},
			{"ab(olo\\)lo)c(foo)",     "abc"},
			{"ab(trol\\\1lo)c(foo)",   "abc"},
			{"\\ab(trol\\\1lo)c(foo)", "abc"},
			{"",                       ""},
	};

	for (const auto &c : cases) {
		SUBCASE (("strip comments in " + c.first).c_str()) {
			auto *cpy = new char[c.first.size()];
			memcpy(cpy, c.first.data(), c.first.size());
			auto nlen = rspamd_strip_smtp_comments_inplace(cpy, c.first.size());
			CHECK(std::string{cpy, nlen} == c.second);
			delete[] cpy;
		}
	}
}


TEST_CASE("shared_ptr from nullptr")
{
	rspamd::local_shared_ptr<int const> pi(static_cast<int *>(nullptr));
	CHECK((!!pi ? false : true));
	CHECK(!pi);
	CHECK(pi.get() == nullptr);
	CHECK(pi.use_count() == 1);
	CHECK(pi.unique());


}
TEST_CASE("shared_ptr from ptr")
{
	int *p = new int(7);
	rspamd::local_shared_ptr<int> pi(p);
	CHECK((pi? true: false));
	CHECK(!!pi);
	CHECK(pi.get() == p);
	CHECK(pi.use_count() == 1);
	CHECK(pi.unique());
	CHECK(*pi == 7);
}

TEST_CASE("shared_ptr copy")
{
	rspamd::local_shared_ptr<int> pi;

	rspamd::local_shared_ptr<int> pi2(pi);
	CHECK(pi2 == pi);
	CHECK((pi2? false: true));
	CHECK(!pi2);
	CHECK(pi2.get() == nullptr);
	CHECK(pi2.use_count() == pi.use_count());

	rspamd::local_shared_ptr<int> pi3(pi);
	CHECK(pi3 == pi);
	CHECK((pi3? false: true));
	CHECK(!pi3);
	CHECK(pi3.get() == nullptr);
	CHECK(pi3.use_count() == pi.use_count());

	rspamd::local_shared_ptr<int> pi4(pi3);
	CHECK(pi4 == pi3);
	CHECK((pi4? false: true));
	CHECK(!pi4);
	CHECK(pi4.get() == nullptr);
	CHECK(pi4.use_count() == pi3.use_count());

	int * p = new int(7);
	rspamd::local_shared_ptr<int> pi5(p);

	rspamd::local_shared_ptr<int> pi6(pi5);
	CHECK(pi5 == pi6);
	CHECK((pi6? true: false));
	CHECK(!!pi6);
	CHECK(pi6.get() == p);
	CHECK(pi6.use_count() == 2);
	CHECK(!pi6.unique());
	CHECK(*pi6 == 7);
	CHECK(pi6.use_count() == pi6.use_count());
	CHECK(!(pi5 < pi6 || pi5 < pi6)); // shared ownership test

	auto pi7 = pi6;
	CHECK(pi5 == pi7);
	CHECK((pi7? true: false));
	CHECK(!!pi7);
	CHECK(pi7.get() == p);
	CHECK(pi7.use_count() == 3);
	CHECK(!pi7.unique());
	CHECK(*pi7 == 7);
	CHECK(pi7.use_count() == pi7.use_count());
	CHECK(!(pi5 < pi7 || pi5 < pi7)); // shared ownership test
}

TEST_CASE("shared_ptr move")
{
	rspamd::local_shared_ptr<int> pi(new int);

	rspamd::local_shared_ptr<int> pi2(std::move(pi));
	CHECK(!(pi2 == pi));
	CHECK((!pi2? false: true));
	CHECK(!pi);
	CHECK(pi.get() == nullptr);
	CHECK(pi2.get() != nullptr);
	CHECK(pi.use_count() != pi2.use_count());

	std::swap(pi, pi2);
	CHECK(!(pi2 == pi));
	CHECK((!pi? false: true));
	CHECK(!pi2);
	CHECK(pi.get() != nullptr);
	CHECK(pi2.get() == nullptr);
	CHECK(pi.use_count() != pi2.use_count());
}

struct deleter_test {
	bool *pv;
	deleter_test(bool &v) {
		v = false;
		pv = &v;
	}
	~deleter_test() {
		*pv = true;
	}
};
TEST_CASE("shared_ptr dtor") {
	bool t;

	{
		rspamd::local_shared_ptr<deleter_test> pi(new deleter_test{t});

		CHECK((!pi ? false : true));
		CHECK(!!pi);
		CHECK(pi.get() != nullptr);
		CHECK(pi.use_count() == 1);
		CHECK(pi.unique());
		CHECK(t == false);
	}

	CHECK(t == true);

	{
		rspamd::local_shared_ptr<deleter_test> pi(new deleter_test{t});

		CHECK((!pi ? false : true));
		CHECK(!!pi);
		CHECK(pi.get() != nullptr);
		CHECK(pi.use_count() == 1);
		CHECK(pi.unique());
		CHECK(t == false);

		rspamd::local_shared_ptr<deleter_test> pi2(pi);
		CHECK(pi2 == pi);
		CHECK(pi.use_count() == 2);
		pi.reset();
		CHECK(!(pi2 == pi));
		CHECK(pi2.use_count() == 1);
		CHECK(t == false);

		pi = pi2;
		CHECK(pi2 == pi);
		CHECK(pi.use_count() == 2);
		CHECK(t == false);
	}

	CHECK(t == true);
}

}

#endif
