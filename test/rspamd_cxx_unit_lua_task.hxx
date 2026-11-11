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

/* Unit tests for task:store_in_file() */

#ifndef RSPAMD_CXX_UNIT_LUA_TASK_HXX
#define RSPAMD_CXX_UNIT_LUA_TASK_HXX

#define DOCTEST_CONFIG_IMPLEMENTATION_IN_DLL
#include "doctest/doctest.h"

#include "config.h"
#include "libserver/task.h"
#include "lua/lua_common.h"

#include <csignal>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <sys/resource.h>
#include <sys/stat.h>

namespace rspamd_lua_task_test {

using namespace std::literals;

/* Binary safe: the message contains an embedded NUL */
constexpr auto message = "Subject: store_in_file\r\n\r\nTest\0message\r\n"sv;

/* A fresh Lua state, a task holding `message` and a private temporary dir */
class store_in_file_fixture {
public:
	store_in_file_fixture()
	{
		dir = std::string{g_get_tmp_dir()} + "/rspamd-store-in-file-XXXXXX";
		REQUIRE(g_mkdtemp(dir.data()) != nullptr);
		L = rspamd_lua_init(false);
		task = rspamd_task_new(nullptr, nullptr, nullptr, nullptr, nullptr, FALSE);
		task->msg.begin = message.data();
		task->msg.len = message.size();
	}

	store_in_file_fixture(const store_in_file_fixture &) = delete;
	store_in_file_fixture &operator=(const store_in_file_fixture &) = delete;

	~store_in_file_fixture()
	{
		destroy_task();
		lua_close(L);
		std::error_code ec;
		std::filesystem::remove_all(dir, ec);
	}

	std::string path(const char *name) const
	{
		return dir + "/" + name;
	}

	/*
	 * Evaluates `task:store_in_file(<args>)`, where `args` may refer to the
	 * `path` local. Asserts nothing, so it is safe to call under a file size
	 * limit; check `error` afterwards.
	 */
	std::optional<std::string> store(const char *args, const std::string &arg_path)
	{
		auto chunk = "local task, path = ...\nreturn task:store_in_file("s + args + ")";
		std::optional<std::string> res;

		error.clear();

		if (luaL_loadstring(L, chunk.c_str()) != 0) {
			error = lua_tostring(L, -1);
			lua_pop(L, 1);

			return res;
		}

		rspamd_lua_task_push(L, task);
		lua_pushstring(L, arg_path.c_str());

		if (lua_pcall(L, 2, 1, 0) != 0) {
			error = lua_tostring(L, -1);
		}
		else if (lua_type(L, -1) == LUA_TSTRING) {
			res = lua_tostring(L, -1);
		}

		lua_pop(L, 1);

		return res;
	}

	/* Runs the task pool destructors, as at the end of a scan */
	void destroy_task()
	{
		if (task) {
			rspamd_task_free(task);
			task = nullptr;
		}
	}

	std::string error;

private:
	std::string dir;
	lua_State *L;
	struct rspamd_task *task;
};

static std::string
read_file(const std::string &fname)
{
	std::ifstream in{fname, std::ios::binary};
	std::ostringstream out;

	out << in.rdbuf();

	return out.str();
}

static bool
file_exists(const std::string &fname)
{
	std::error_code ec;

	return std::filesystem::exists(fname, ec);
}

static unsigned int
file_mode(const std::string &fname)
{
	struct stat st;

	REQUIRE(stat(fname.c_str(), &st) == 0);

	return st.st_mode & 0777;
}

/* Sets a temporary umask, so modes passed to open(2) are predictable */
class umask_guard {
public:
	explicit umask_guard(mode_t mask)
		: old(umask(mask))
	{
	}

	~umask_guard()
	{
		umask(old);
	}

private:
	mode_t old;
};

#if defined(RLIMIT_FSIZE) && defined(SIGXFSZ)
/*
 * Limits the size of files this process may write, so writes past the limit
 * are cut short and then fail with EFBIG. Nothing may be asserted while the
 * guard is alive: test output can go to a regular file as well.
 */
class fsize_limit_guard {
public:
	explicit fsize_limit_guard(rlim_t limit)
	{
		struct rlimit lim;
		struct sigaction action;

		memset(&action, 0, sizeof(action));
		action.sa_handler = SIG_IGN;
		sigemptyset(&action.sa_mask);
		sigaction(SIGXFSZ, &action, &old_action);
		getrlimit(RLIMIT_FSIZE, &old_limit);
		lim = old_limit;
		lim.rlim_cur = limit;
		active = setrlimit(RLIMIT_FSIZE, &lim) == 0;
	}

	~fsize_limit_guard()
	{
		setrlimit(RLIMIT_FSIZE, &old_limit);
		sigaction(SIGXFSZ, &old_action, nullptr);
	}

	bool active = false;

private:
	struct rlimit old_limit;
	struct sigaction old_action;
};
#endif

TEST_SUITE("lua_task")
{
	TEST_CASE("store_in_file writes the whole message")
	{
		for (auto keep: {false, true}) {
			SUBCASE(keep ? "keep = true" : "keep = false")
			{
				store_in_file_fixture f;
				auto fname = f.path("message");
				auto stored = f.store(keep ? "{filename = path, keep = true}" : "{filename = path, keep = false}",
									  fname);

				CHECK(f.error == "");
				REQUIRE(stored.has_value());
				CHECK(*stored == fname);
				CHECK(read_file(fname) == message);

				f.destroy_task();
				CHECK(file_exists(fname) == keep);
			}
		}
	}

#if defined(RLIMIT_FSIZE) && defined(SIGXFSZ)
	TEST_CASE("store_in_file removes an incomplete file")
	{
		for (auto keep: {false, true}) {
			SUBCASE(keep ? "keep = true" : "keep = false")
			{
				store_in_file_fixture f;
				auto fname = f.path("message");
				std::optional<std::string> stored;
				bool limited;

				{
					/* The first write stores 1 byte, the next one fails */
					fsize_limit_guard guard{1};
					limited = guard.active;
					stored = f.store(keep ? "{filename = path, keep = true}" : "{filename = path, keep = false}",
									 fname);
				}

				REQUIRE(limited);
				CHECK(f.error == "");
				CHECK_FALSE(stored.has_value());
				/* Incomplete files must be removed at once, even with keep = true */
				CHECK_FALSE(file_exists(fname));
			}
		}
	}
#endif

	TEST_CASE("store_in_file uses 0600 when mode is omitted")
	{
		SUBCASE("filename")
		{
			store_in_file_fixture f;
			umask_guard mask{022};
			auto stored = f.store("{filename = path}", f.path("message"));

			CHECK(f.error == "");
			REQUIRE(stored.has_value());
			CHECK(file_mode(*stored) == 0600);
		}

		SUBCASE("tmpmask")
		{
			store_in_file_fixture f;
			auto stored = f.store("{tmpmask = path}", f.path("message-XXXXXX"));

			CHECK(f.error == "");
			REQUIRE(stored.has_value());
			CHECK(file_mode(*stored) == 0600);
		}
	}

	TEST_CASE("store_in_file honours an explicit mode")
	{
		store_in_file_fixture f;
		umask_guard mask{022};
		auto stored = f.store("{filename = path, mode = tonumber('0640', 8)}", f.path("message"));

		CHECK(f.error == "");
		REQUIRE(stored.has_value());
		CHECK(file_mode(*stored) == 0640);
	}
}

}// namespace rspamd_lua_task_test

#endif
