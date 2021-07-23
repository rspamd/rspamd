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

#ifndef RSPAMD_RSPAMD_CXX_LOCAL_PTR_HXX
#define RSPAMD_RSPAMD_CXX_LOCAL_PTR_HXX

#define DOCTEST_CONFIG_IMPLEMENTATION_IN_DLL
#include "doctest/doctest.h"

#include "libutil/cxx/local_shared_ptr.hxx"

namespace test_internal {
struct deleter_test {
	bool *pv;

	deleter_test(bool &v)
	{
		v = false;
		pv = &v;
	}

	~deleter_test()
	{
		*pv = true;
	}
};
}

namespace std {
template<>
struct hash<test_internal::deleter_test> {
	inline auto operator()(const test_internal::deleter_test &) const noexcept -> auto
	{
		return 42;
	}
};
}

TEST_SUITE("local_ptr") {
using namespace test_internal;

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

TEST_CASE("make_shared dtor") {
	bool t;

	{
		auto pi = rspamd::local_make_shared<deleter_test>(t);

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

TEST_CASE("weak_ptr") {
	bool t;

	{
		rspamd::local_shared_ptr<deleter_test> pi(new deleter_test{t});

		CHECK((!pi ? false : true));
		CHECK(!!pi);
		CHECK(pi.get() != nullptr);
		CHECK(pi.use_count() == 1);
		CHECK(pi.unique());
		CHECK(t == false);

		rspamd::local_weak_ptr<deleter_test> wp(pi);
		CHECK(wp.lock().get() != nullptr);
		CHECK(pi.use_count() == 1);
		CHECK(wp.use_count() == 1);
		pi.reset();
		CHECK(pi.use_count() == 0);
		CHECK(wp.use_count() == 0);
	}

	CHECK(t == true);

	rspamd::local_weak_ptr<deleter_test> wp;
	{
		rspamd::local_shared_ptr<deleter_test> pi(new deleter_test{t});
		wp = pi;
		CHECK(!wp.expired());
		CHECK(wp.lock().get() != nullptr);
	}

	CHECK(t == true);
	CHECK(wp.expired());
}

TEST_CASE("std::swap") {
	bool t;

	{
		rspamd::local_shared_ptr<deleter_test> pi(new deleter_test{t});
		CHECK(pi.use_count() == 1);
		CHECK(pi.unique());
		CHECK(t == false);

		rspamd::local_shared_ptr<deleter_test> pi1;
		CHECK(pi1.get() == nullptr);
		CHECK(pi1.use_count() == 0);
		std::swap(pi1, pi);
		CHECK(pi.use_count() == 0);
		CHECK(pi.get() == nullptr);
		CHECK(pi1.get() != nullptr);
		std::swap(pi, pi1);
		CHECK(pi.use_count() != 0);
		CHECK(pi.get() != nullptr);
		CHECK(pi1.get() == nullptr);
	}

	CHECK(t == true);
}

TEST_CASE("std::hash") {
	bool v;
	deleter_test dt(v);
	CHECK(std::hash<deleter_test>()(dt) == 42);
	auto pi = rspamd::local_make_shared<deleter_test>(v);
	rspamd::local_shared_ptr<deleter_test> pi1;
	CHECK(std::hash<decltype(pi)>()(pi) == 42);
	// No hash for nullptr, different from std::smart_pointers!
	CHECK_THROWS(std::hash<decltype(pi)>()(pi1));
}

}

#endif //RSPAMD_RSPAMD_CXX_LOCAL_PTR_HXX
