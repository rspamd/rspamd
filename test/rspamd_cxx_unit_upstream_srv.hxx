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
 * Unit tests for the SRV-as-multiple-upstreams refactor: each SRV target
 * expands into its own struct upstream with first-class participation in
 * every selection algorithm.
 */

#ifndef RSPAMD_CXX_UNIT_UPSTREAM_SRV_HXX
#define RSPAMD_CXX_UNIT_UPSTREAM_SRV_HXX

#define DOCTEST_CONFIG_IMPLEMENTATION_IN_DLL
#include "doctest/doctest.h"

#include "libutil/upstream.h"
#include "libutil/upstream_internal.h"

#include <map>
#include <set>
#include <string>
#include <vector>

namespace upstream_srv_test {

struct ctx_holder {
	struct upstream_ctx *ctx;
	struct upstream_list *ups;
	struct upstream *parent;

	ctx_holder()
	{
		ctx = rspamd_upstreams_library_init();
		ups = rspamd_upstreams_create(ctx);
		rspamd_upstreams_set_rotation(ups, RSPAMD_UPSTREAM_ROUND_ROBIN);

		auto ok = rspamd_upstreams_add_upstream(ups,
												"service=fuzzy+example.com",
												11335,
												RSPAMD_UPSTREAM_PARSE_DEFAULT,
												nullptr);
		REQUIRE(ok);
		parent = rspamd_upstream_srv_test_get_parent(ups);
		REQUIRE(parent != nullptr);
	}

	~ctx_holder()
	{
		rspamd_upstreams_destroy(ups);
		rspamd_upstreams_library_unref(ctx);
	}

	ctx_holder(const ctx_holder &) = delete;
	ctx_holder &operator=(const ctx_holder &) = delete;

	/* Snapshot the current member set as name → upstream*. */
	std::map<std::string, struct upstream *> members()
	{
		std::map<std::string, struct upstream *> out;
		rspamd_upstreams_foreach(ups, [](struct upstream *up, unsigned int, void *ud) {
			auto *m = static_cast<std::map<std::string, struct upstream *> *>(ud);
			(*m)[rspamd_upstream_name(up)] = up; }, &out);
		return out;
	}

	/* Apply an SRV snapshot. New members come back with PENDING_RESOLVE
	 * set; activate() puts each one into the alive list with a synthetic
	 * loopback IP so it's selectable. */
	void apply(std::initializer_list<rspamd_upstream_srv_entry> entries)
	{
		std::vector<rspamd_upstream_srv_entry> v(entries);
		rspamd_upstream_srv_apply(parent, v.data(), v.size());
	}

	void activate(const std::string &target, const std::string &ip)
	{
		auto m = members();
		auto it = m.find(target);
		REQUIRE(it != m.end());
		rspamd_upstream_member_force_alive_for_test(it->second, ip.c_str());
	}
};

}// namespace upstream_srv_test

TEST_SUITE("upstream_srv")
{
	using upstream_srv_test::ctx_holder;

	TEST_CASE("single-target SRV expansion creates one selectable member")
	{
		ctx_holder t;
		t.apply({{"a.example.com", 11335, 100, 10}});
		t.activate("a.example.com", "127.0.0.1");

		CHECK(rspamd_upstreams_alive(t.ups) == 1);
		CHECK(rspamd_upstreams_count(t.ups) == 1);

		auto *up = rspamd_upstream_get(t.ups, RSPAMD_UPSTREAM_ROUND_ROBIN,
									   nullptr, 0);
		REQUIRE(up != nullptr);
		CHECK(std::string(rspamd_upstream_name(up)) == "a.example.com");
	}

	TEST_CASE("3 equal-weight targets distribute uniformly under RR")
	{
		ctx_holder t;
		t.apply({
			{"a.example.com", 11335, 1, 10},
			{"b.example.com", 11335, 1, 10},
			{"c.example.com", 11335, 1, 10},
		});
		t.activate("a.example.com", "127.0.0.1");
		t.activate("b.example.com", "127.0.0.2");
		t.activate("c.example.com", "127.0.0.3");

		REQUIRE(rspamd_upstreams_alive(t.ups) == 3);

		std::map<std::string, int> counts;
		for (int i = 0; i < 3000; i++) {
			auto *up = rspamd_upstream_get(t.ups, RSPAMD_UPSTREAM_ROUND_ROBIN,
										   nullptr, 0);
			REQUIRE(up != nullptr);
			counts[rspamd_upstream_name(up)]++;
		}

		CHECK(counts.size() == 3);
		for (const auto &[name, c]: counts) {
			CHECK(c >= 900);
			CHECK(c <= 1100);
		}
	}

	TEST_CASE("SRV weight is honoured by weighted round-robin")
	{
		ctx_holder t;
		t.apply({
			{"heavy-a.example.com", 11335, 100, 10},
			{"heavy-b.example.com", 11335, 100, 10},
			{"light.example.com", 11335, 1, 10},
		});
		t.activate("heavy-a.example.com", "127.0.0.1");
		t.activate("heavy-b.example.com", "127.0.0.2");
		t.activate("light.example.com", "127.0.0.3");

		REQUIRE(rspamd_upstreams_alive(t.ups) == 3);

		std::map<std::string, int> counts;
		const int total = 2010; /* 10 cycles of 201 = 100 + 100 + 1 */
		for (int i = 0; i < total; i++) {
			auto *up = rspamd_upstream_get(t.ups, RSPAMD_UPSTREAM_ROUND_ROBIN,
										   nullptr, 0);
			REQUIRE(up != nullptr);
			counts[rspamd_upstream_name(up)]++;
		}

		CHECK(counts["heavy-a.example.com"] >= 900);
		CHECK(counts["heavy-a.example.com"] <= 1100);
		CHECK(counts["heavy-b.example.com"] >= 900);
		CHECK(counts["heavy-b.example.com"] <= 1100);
		CHECK(counts["light.example.com"] >= 5);
		CHECK(counts["light.example.com"] <= 25);
	}

	TEST_CASE("re-resolve add: new target appears, identity preserved")
	{
		ctx_holder t;
		t.apply({
			{"a.example.com", 11335, 1, 10},
			{"b.example.com", 11335, 1, 10},
		});
		t.activate("a.example.com", "127.0.0.1");
		t.activate("b.example.com", "127.0.0.2");

		auto before = t.members();
		REQUIRE(before.size() == 2);
		struct upstream *m_a = before["a.example.com"];
		struct upstream *m_b = before["b.example.com"];

		t.apply({
			{"a.example.com", 11335, 1, 10},
			{"b.example.com", 11335, 1, 10},
			{"c.example.com", 11335, 1, 10},
		});
		t.activate("c.example.com", "127.0.0.3");

		auto after = t.members();
		CHECK(after.size() == 3);
		CHECK(after["a.example.com"] == m_a);
		CHECK(after["b.example.com"] == m_b);
	}

	TEST_CASE("re-resolve remove: dropped target is drained from selection")
	{
		ctx_holder t;
		t.apply({
			{"a.example.com", 11335, 1, 10},
			{"b.example.com", 11335, 1, 10},
			{"c.example.com", 11335, 1, 10},
		});
		t.activate("a.example.com", "127.0.0.1");
		t.activate("b.example.com", "127.0.0.2");
		t.activate("c.example.com", "127.0.0.3");

		REQUIRE(rspamd_upstreams_alive(t.ups) == 3);

		t.apply({
			{"a.example.com", 11335, 1, 10},
			{"c.example.com", 11335, 1, 10},
		});

		CHECK(rspamd_upstreams_alive(t.ups) == 2);

		auto m = t.members();
		CHECK(m.count("a.example.com") == 1);
		CHECK(m.count("c.example.com") == 1);
		CHECK(m.count("b.example.com") == 0);

		/* Subsequent selection only returns the survivors. */
		std::set<std::string> seen;
		for (int i = 0; i < 100; i++) {
			auto *up = rspamd_upstream_get(t.ups,
										   RSPAMD_UPSTREAM_ROUND_ROBIN,
										   nullptr, 0);
			REQUIRE(up != nullptr);
			seen.insert(rspamd_upstream_name(up));
		}
		CHECK(seen.count("a.example.com") == 1);
		CHECK(seen.count("c.example.com") == 1);
		CHECK(seen.count("b.example.com") == 0);
	}

	TEST_CASE("re-resolve weight change shifts the distribution")
	{
		ctx_holder t;
		t.apply({
			{"a.example.com", 11335, 1, 10},
			{"b.example.com", 11335, 1, 10},
			{"c.example.com", 11335, 1, 10},
		});
		t.activate("a.example.com", "127.0.0.1");
		t.activate("b.example.com", "127.0.0.2");
		t.activate("c.example.com", "127.0.0.3");

		t.apply({
			{"a.example.com", 11335, 1, 10},
			{"b.example.com", 11335, 1, 10},
			{"c.example.com", 11335, 100, 10},
		});

		std::map<std::string, int> counts;
		const int total = 5100; /* 50 cycles of 102 */
		for (int i = 0; i < total; i++) {
			auto *up = rspamd_upstream_get(t.ups,
										   RSPAMD_UPSTREAM_ROUND_ROBIN,
										   nullptr, 0);
			REQUIRE(up != nullptr);
			counts[rspamd_upstream_name(up)]++;
		}

		CHECK(counts["c.example.com"] >= 4500);
		CHECK(counts["c.example.com"] <= 5500);
		CHECK(counts["a.example.com"] >= 30);
		CHECK(counts["a.example.com"] <= 80);
		CHECK(counts["b.example.com"] >= 30);
		CHECK(counts["b.example.com"] <= 80);
	}

	TEST_CASE("error budget is per member, not shared across SRV cluster")
	{
		ctx_holder t;
		/*
		 * Squeeze the error window so a few fails over a few tens of
		 * ms cross the rate threshold. Defaults (4 errors / 10s) would
		 * require multi-second sleeps to trigger in unit tests.
		 */
		/*
		 * Rate-based inactive transition fires when:
		 *   (sec_cur - last_fail) >= error_time  AND
		 *   errors / elapsed > max_errors / error_time
		 *
		 * Pick aggressive limits so we comfortably exceed the threshold
		 * even with macOS scheduler jitter on g_usleep.
		 */
		rspamd_upstreams_set_limits(t.ups,
									/* revive_time */ 60.0,
									/* revive_jitter */ 0.4,
									/* error_time */ 0.002,
									/* dns_timeout */ 1.0,
									/* max_errors */ 1,
									/* dns_retransmits */ 2);

		t.apply({
			{"a.example.com", 11335, 1, 10},
			{"b.example.com", 11335, 1, 10},
			{"c.example.com", 11335, 1, 10},
		});
		t.activate("a.example.com", "127.0.0.1");
		t.activate("b.example.com", "127.0.0.2");
		t.activate("c.example.com", "127.0.0.3");

		auto before = t.members();
		REQUIRE(before.size() == 3);
		struct upstream *bad = before["a.example.com"];

		/*
		 * Pre-refactor, the three SRV targets shared one error budget;
		 * a burst here would have killed every target. With per-member
		 * budgets, only `bad` crosses the rate threshold and exits the
		 * alive list.
		 */
		for (int i = 0; i < 12; i++) {
			rspamd_upstream_fail(bad, TRUE, "test");
			g_usleep(1000); /* 1 ms — gives ample margin over error_time=2ms */
		}

		/*
		 * `bad` is now out of the alive list but still in ls->ups (the
		 * revive timer holds a ref + position). The other two members
		 * must still be selectable; verify by sampling.
		 */
		CHECK(rspamd_upstreams_alive(t.ups) == 2);

		std::set<std::string> seen_names;
		for (int i = 0; i < 100; i++) {
			auto *up = rspamd_upstream_get(t.ups,
										   RSPAMD_UPSTREAM_ROUND_ROBIN,
										   nullptr, 0);
			REQUIRE(up != nullptr);
			seen_names.insert(rspamd_upstream_name(up));
		}
		CHECK(seen_names.count("a.example.com") == 0);
		CHECK(seen_names.count("b.example.com") == 1);
		CHECK(seen_names.count("c.example.com") == 1);
	}

	TEST_CASE("per-member latency EWMA records distinct values")
	{
		ctx_holder t;
		t.apply({
			{"a.example.com", 11335, 1, 10},
			{"b.example.com", 11335, 1, 10},
		});
		t.activate("a.example.com", "127.0.0.1");
		t.activate("b.example.com", "127.0.0.2");

		auto m = t.members();
		REQUIRE(m.size() == 2);

		rspamd_upstream_record_latency(m["a.example.com"], 0.005);
		rspamd_upstream_record_latency(m["b.example.com"], 0.250);

		double la = rspamd_upstream_get_latency(m["a.example.com"]);
		double lb = rspamd_upstream_get_latency(m["b.example.com"]);

		CHECK(la > 0.0);
		CHECK(lb > 0.0);
		CHECK(lb > la * 5.0);
	}

	TEST_CASE("parent is invisible to public iteration / count APIs")
	{
		ctx_holder t;
		/* Even before any apply, a parent exists in ls->ups but neither
		 * count nor foreach exposes it. */
		CHECK(rspamd_upstreams_count(t.ups) == 0);
		CHECK(t.members().empty());

		t.apply({{"a.example.com", 11335, 1, 10}});
		t.activate("a.example.com", "127.0.0.1");

		CHECK(rspamd_upstreams_count(t.ups) == 1);
		CHECK(t.members().size() == 1);
	}
}

#endif /* RSPAMD_CXX_UNIT_UPSTREAM_SRV_HXX */
