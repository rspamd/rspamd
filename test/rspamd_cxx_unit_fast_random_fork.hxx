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

/* The fast PRNG must be reseedable in a forked child */

#ifndef RSPAMD_CXX_UNIT_FAST_RANDOM_FORK_HXX
#define RSPAMD_CXX_UNIT_FAST_RANDOM_FORK_HXX

#define DOCTEST_CONFIG_IMPLEMENTATION_IN_DLL
#include "doctest/doctest.h"

#include "config.h"
#include <cstdint>
#include <unistd.h>
#include <sys/wait.h>
#include "libutil/util.h"
#include "ottery.h"

namespace {

/*
 * Forks a child that optionally reseeds the fast PRNG the way a worker does
 * after fork, draws one value and returns it through a pipe.
 * The child only calls ottery, the PRNG, write and _exit.
 */
bool fast_random_child_draw(bool reseed, uint64_t *out)
{
	int fds[2];

	if (pipe(fds) != 0) {
		return false;
	}

	pid_t pid = fork();

	if (pid == -1) {
		close(fds[0]);
		close(fds[1]);
		return false;
	}

	if (pid == 0) {
		close(fds[0]);
		if (reseed) {
			ottery_init(nullptr);
			rspamd_random_seed_fast();
		}
		uint64_t v = rspamd_random_uint64_fast();
		ssize_t w = write(fds[1], &v, sizeof(v));
		_exit(w == (ssize_t) sizeof(v) ? 0 : 1);
	}

	close(fds[1]);
	bool ok = read(fds[0], out, sizeof(*out)) == (ssize_t) sizeof(*out);
	close(fds[0]);

	int status = 0;
	waitpid(pid, &status, 0);

	return ok && WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

}// namespace

TEST_SUITE("fast_random_fork")
{
	TEST_CASE("children share the inherited state unless reseeded")
	{
		/* Make sure the state is already seeded in the parent */
		(void) rspamd_random_uint64_fast();

		/* The state at the fork point is what the children continue from */
		uint64_t a = 0, b = 0;
		REQUIRE(fast_random_child_draw(false, &a));
		REQUIRE(fast_random_child_draw(false, &b));
		const uint64_t parent = rspamd_random_uint64_fast();

		/* This is the behaviour the explicit reseed has to break */
		CHECK(a == b);
		CHECK(a == parent);
	}

	TEST_CASE("rspamd_random_seed_fast reseeds a seeded state")
	{
		(void) rspamd_random_uint64_fast();

		uint64_t a = 0, b = 0;
		REQUIRE(fast_random_child_draw(true, &a));
		REQUIRE(fast_random_child_draw(true, &b));
		const uint64_t parent = rspamd_random_uint64_fast();

		CHECK(a != b);
		CHECK(a != parent);
		CHECK(b != parent);
	}
}

#endif
