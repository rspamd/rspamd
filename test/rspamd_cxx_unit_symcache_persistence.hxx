/*
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

#ifndef RSPAMD_CXX_UNIT_SYMCACHE_PERSISTENCE_HXX
#define RSPAMD_CXX_UNIT_SYMCACHE_PERSISTENCE_HXX

#define DOCTEST_CONFIG_IMPLEMENTATION_IN_DLL
#include "doctest/doctest.h"

#include "libserver/symcache/symcache_internal.hxx"
#include "libserver/symcache/symcache_item.hxx"
#include "libutil/cxx/file_util.hxx"

#include <cerrno>
#include <csignal>
#include <cstring>
#include <fcntl.h>
#include <string>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

namespace {

static void persistence_dummy_callback(struct rspamd_task *,
									   struct rspamd_symcache_dynamic_item *, gpointer)
{
}

static std::string persistence_read_file(const std::string &path)
{
	gchar *data = nullptr;
	gsize len = 0;
	REQUIRE(g_file_get_contents(path.c_str(), &data, &len, nullptr));
	std::string result(data, len);
	g_free(data);
	return result;
}

template<typename F>
static void persistence_child_succeeds(F child)
{
	auto pid = fork();
	REQUIRE(pid != -1);
	if (pid == 0) {
		/* Keep resource limits and signal changes local to this child. */
		_exit(child() ? 0 : 1);
	}

	int status = 0;
	pid_t ret;
	do {
		ret = waitpid(pid, &status, 0);
	} while (ret == -1 && errno == EINTR);
	REQUIRE(ret == pid);
	REQUIRE(WIFEXITED(status));
	CHECK(WEXITSTATUS(status) == 0);
}

struct symcache_persistence_fixture {
	std::string directory;
	std::string path;
	struct rspamd_config *cfg;
	rspamd::symcache::symcache *cache;
	rspamd::symcache::cache_item *item;

	symcache_persistence_fixture()
	{
		auto *tmp = g_dir_make_tmp("rspamd-symcache-XXXXXX", nullptr);
		REQUIRE(tmp != nullptr);
		directory = tmp;
		g_free(tmp);
		path = directory + "/symbols.cache";
		cfg = rspamd_config_new(RSPAMD_CONFIG_INIT_DEFAULT);
		REQUIRE(cfg != nullptr);
		cfg->cache_filename = rspamd_mempool_strdup(cfg->cfg_pool, path.c_str());
		cache = reinterpret_cast<rspamd::symcache::symcache *>(cfg->cache);
		REQUIRE(cache->add_symbol_with_callback("PERSISTENCE_TEST", 0,
											  persistence_dummy_callback, nullptr,
											  SYMBOL_TYPE_NORMAL) >= 0);
		item = cache->get_item_by_name_mut("PERSISTENCE_TEST", false);
		REQUIRE(item != nullptr);
	}

	~symcache_persistence_fixture()
	{
		/* cfg owns its symcache; do not destroy it a second time. */
		rspamd_config_free(cfg);
		unlink((path + ".new").c_str());
		unlink(path.c_str());
		rmdir(path.c_str());
		rmdir(directory.c_str());
	}
};

} // namespace

TEST_SUITE("symcache_persistence")
{
	TEST_CASE("create a cache and reload its statistics")
	{
		symcache_persistence_fixture source;
		source.item->st->total_hits = 23;
		source.item->st->time_counter.mean = 1.25;
		source.item->st->frequency_counter.mean = 2.5;
		source.item->st->frequency_counter.stddev = 0.75;
		REQUIRE(source.cache->save_items());
		CHECK(access((source.path + ".new").c_str(), F_OK) == -1);

		auto bytes = persistence_read_file(source.path);
		REQUIRE(bytes.size() > sizeof(rspamd::symcache::symcache_header));
		CHECK(memcmp(bytes.data(), rspamd::symcache::symcache_magic,
					 sizeof(rspamd::symcache::symcache_magic)) == 0);

		symcache_persistence_fixture restored;
		restored.cfg->cache_filename = rspamd_mempool_strdup(restored.cfg->cfg_pool,
															 source.path.c_str());
		REQUIRE(restored.cache->init());
		CHECK(restored.item->st->total_hits == 23);
		CHECK(restored.item->st->avg_time == doctest::Approx(1.25));
		CHECK(restored.item->st->avg_frequency == doctest::Approx(2.5));
		CHECK(restored.item->st->stddev_frequency == doctest::Approx(0.75));
	}

	TEST_CASE("replace an existing cache while old readers keep their inode")
	{
		symcache_persistence_fixture fx;
		fx.item->st->total_hits = 123456789;
		REQUIRE(fx.cache->save_items());
		auto original = persistence_read_file(fx.path);
		auto reader = rspamd::util::raii_file::open(fx.path.c_str(), O_RDONLY);
		REQUIRE(reader.has_value());

		fx.item->st->total_hits = 1;
		REQUIRE(fx.cache->save_items());
		auto replacement = persistence_read_file(fx.path);
		CHECK(replacement.size() < original.size());
		CHECK(replacement != original);
		std::string old_bytes(original.size(), '\0');
		REQUIRE(read(reader->get_fd(), old_bytes.data(), old_bytes.size()) ==
				static_cast<ssize_t>(old_bytes.size()));
		CHECK(old_bytes == original);
		CHECK(access((fx.path + ".new").c_str(), F_OK) == -1);
	}

	TEST_CASE("rename failure is reported and the temporary file is removed")
	{
		symcache_persistence_fixture fx;
		REQUIRE(mkdir(fx.path.c_str(), 0700) == 0);
		CHECK_FALSE(fx.cache->save_items());
		CHECK(g_file_test(fx.path.c_str(), G_FILE_TEST_IS_DIR));
		CHECK(access((fx.path + ".new").c_str(), F_OK) == -1);
	}

	TEST_CASE("a partial write followed by EFBIG preserves the previous cache")
	{
		symcache_persistence_fixture fx;
		REQUIRE(fx.cache->save_items());
		auto original = persistence_read_file(fx.path);

		persistence_child_succeeds([&]() {
			struct rlimit limit;
			if (getrlimit(RLIMIT_FSIZE, &limit) != 0) {
				return false;
			}
			/* Header fits; the JSON write reaches the limit partway through. */
			limit.rlim_cur = sizeof(rspamd::symcache::symcache_header) + 1;
			if (signal(SIGXFSZ, SIG_IGN) == SIG_ERR ||
				setrlimit(RLIMIT_FSIZE, &limit) != 0) {
				return false;
			}
			return !fx.cache->save_items();
		});

		CHECK(persistence_read_file(fx.path) == original);
		CHECK(access((fx.path + ".new").c_str(), F_OK) == -1);
	}

	TEST_CASE("a competing writer cannot truncate or remove a locked temporary file")
	{
		symcache_persistence_fixture fx;
		auto temporary = fx.path + ".new";
		auto lock = rspamd::util::raii_locked_file::create(temporary.c_str(), O_WRONLY, 0600);
		REQUIRE(lock.has_value());
		const std::string marker = "another writer's pending cache";
		REQUIRE(write(lock->get_fd(), marker.data(), marker.size()) ==
				static_cast<ssize_t>(marker.size()));

		persistence_child_succeeds([&]() { return !fx.cache->save_items(); });
		CHECK(persistence_read_file(temporary) == marker);
	}
}

#endif
