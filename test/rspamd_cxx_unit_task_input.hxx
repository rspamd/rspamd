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
 * Regression tests for the privileged message source path: the windowed
 * segment reader `rspamd_shmem_segment_map` and the two task helpers that
 * gate it.
 *
 * The properties that are pinned down here are the ones that are easy to
 * regress silently:
 *
 *   - only the requested window is ever mapped, so a 64 byte payload inside
 *     a multi megabyte object never maps that object;
 *   - the page alignment arithmetic returns exactly the requested slice,
 *     including at offsets that are deliberately not page aligned;
 *   - offset and length are validated *together*, so neither a wrapping sum
 *     nor an out of range offset can produce a range outside the object;
 *   - the payload handed to the caller is a private snapshot, therefore the
 *     client can resize the backing object afterwards without the parser
 *     ever seeing memory that can fault;
 *   - and, the sharp edge of that one, the snapshot is never *copied out of a
 *     mapping*: a client that truncates the object in the window between the
 *     validating fstat and the copy would otherwise raise SIGBUS inside the
 *     worker;
 *   - the name is sanitised before any syscall touches it and an overlong
 *     name is refused rather than silently truncated;
 *   - `Filename` is *not* a privileged control, whereas `File`, `Path`,
 *     `Shm`, `Shm-Offset` and `Shm-Length` are, case insensitively.
 *
 * Whether the backing object is a POSIX shared memory object or an ordinary
 * file is a build time property (HAVE_SANE_SHMEM), and the implementation
 * picks the matching syscall, so the fixture below creates whichever kind
 * this build actually opens. Both kinds are unlinked from a destructor, so
 * a failing assertion cannot leave anything behind.
 */

#ifndef RSPAMD_CXX_UNIT_TASK_INPUT_HXX
#define RSPAMD_CXX_UNIT_TASK_INPUT_HXX

#define DOCTEST_CONFIG_IMPLEMENTATION_IN_DLL
#include "doctest/doctest.h"

#include "config.h"
#include "libserver/task.h"
#include "libutil/mem_pool.h"

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <climits>
#include <cstdlib>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

namespace rspamd_task_input_test {

/*
 * The overlong name test below pads a path up to PATH_MAX - 1 bytes, and the
 * kernel applies that limit to the *resolved* path, so a symlinked temporary
 * directory (as on macOS, where TMPDIR lives under /var -> private/var) has to
 * be resolved upfront or the padded name would not be openable at all.
 */
static const std::string &
test_tmp_dir(void)
{
	static const std::string dir = []() -> std::string {
		char resolved[PATH_MAX];
		const char *tmp = g_get_tmp_dir();

		if (tmp != nullptr && realpath(tmp, resolved) != nullptr) {
			return std::string(resolved);
		}

		return tmp != nullptr ? std::string(tmp) : std::string("/tmp");
	}();

	return dir;
}

static gsize
test_page_size(void)
{
	long ps = sysconf(_SC_PAGESIZE);

	if (ps <= 0) {
		return 4096;
	}

	return (gsize) ps;
}

/*
 * A deterministic, benign filler: byte at absolute offset `off` is
 * 'A' + off % 26. The period is coprime with any sane page size, so an
 * off-by-one in the alignment arithmetic always changes the slice.
 */
static std::string
pattern_slice(gsize off, gsize len)
{
	std::string res;

	res.reserve(len);

	for (gsize i = 0; i < len; i++) {
		res.push_back((char) ('A' + (int) ((off + i) % 26)));
	}

	return res;
}

static rspamd_ftok_t
ftok_of(const std::string &s)
{
	rspamd_ftok_t tok;

	tok.begin = s.data();
	tok.len = s.size();

	return tok;
}

/*
 * Owns one backing object for the duration of a test case and removes it
 * from the destructor, so an assertion that throws still cleans up.
 */
class backing_object {
public:
	backing_object(const std::string &tag, gsize size)
	{
		obj_name = make_name(tag);

#ifdef HAVE_SANE_SHMEM
		fd = shm_open(obj_name.c_str(), O_RDWR | O_CREAT | O_EXCL, 0600);
#else
		fd = open(obj_name.c_str(), O_RDWR | O_CREAT | O_EXCL, 0600);
#endif

		if (fd == -1) {
			return;
		}

		if (!resize(size)) {
			return;
		}

		ok = fill_pattern();
	}

	backing_object(const backing_object &) = delete;
	backing_object &operator=(const backing_object &) = delete;

	~backing_object()
	{
		if (fd != -1) {
			close(fd);
		}

#ifdef HAVE_SANE_SHMEM
		shm_unlink(obj_name.c_str());
#else
		unlink(obj_name.c_str());
#endif
	}

	bool valid() const
	{
		return ok;
	}

	const std::string &name() const
	{
		return obj_name;
	}

	gsize size() const
	{
		return cur_size;
	}

	bool resize(gsize new_size)
	{
		if (ftruncate(fd, (off_t) new_size) == -1) {
			return false;
		}

		cur_size = new_size;

		return true;
	}

	/*
	 * A second, writable descriptor for the very same object. A concurrent
	 * resizer needs one of its own, so that it never touches this fixture's
	 * bookkeeping from another thread.
	 */
	int open_writable() const
	{
#ifdef HAVE_SANE_SHMEM
		return shm_open(obj_name.c_str(), O_RDWR, 0);
#else
		return open(obj_name.c_str(), O_RDWR);
#endif
	}

	/* Rewrites the whole object with the canonical pattern */
	bool fill_pattern()
	{
		auto data = pattern_slice(0, cur_size);

		return write_all(data);
	}

	/* Rewrites the whole object with a single repeated byte */
	bool fill_with(char c)
	{
		std::string data(cur_size, c);

		return write_all(data);
	}

private:
	static std::string make_name(const std::string &tag)
	{
		auto uniq = tag + "_" + std::to_string((long) getpid());

#ifdef HAVE_SANE_SHMEM
		return "/rspamd_test_input_" + uniq;
#else
		return test_tmp_dir() + "/rspamd_test_input_" + uniq;
#endif
	}

	bool write_all(const std::string &data)
	{
		gsize total = 0;

		if (lseek(fd, 0, SEEK_SET) != 0) {
			return false;
		}

		while (total < data.size()) {
			ssize_t r = write(fd, data.data() + total, data.size() - total);

			if (r > 0) {
				total += (gsize) r;
			}
			else if (r == -1 && errno == EINTR) {
				continue;
			}
			else {
				return false;
			}
		}

		return true;
	}

	std::string obj_name;
	gsize cur_size = 0;
	int fd = -1;
	bool ok = false;
};

/*
 * Resizes a backing object from a second thread for as long as it is alive,
 * which is how a client that owns the object behaves while the worker is
 * reading it.
 *
 * The thread is bounded twice over -- by the stop flag and by a wall clock
 * deadline -- and it is always joined from the destructor, so a failing
 * assertion in the test body can neither leave it running nor hang the suite.
 */
class background_truncator {
public:
	background_truncator(const backing_object &obj, gsize big, gsize small)
	{
		fd = obj.open_writable();

		if (fd == -1) {
			return;
		}

		thr = std::thread([this, big, small]() {
			auto deadline = std::chrono::steady_clock::now() +
							std::chrono::seconds(10);

			while (!stop.load(std::memory_order_relaxed) &&
				   std::chrono::steady_clock::now() < deadline) {
				if (ftruncate(fd, (off_t) small) == -1 ||
					ftruncate(fd, (off_t) big) == -1) {
					break;
				}

				toggles.fetch_add(1, std::memory_order_relaxed);
			}
		});
	}

	background_truncator(const background_truncator &) = delete;
	background_truncator &operator=(const background_truncator &) = delete;

	~background_truncator()
	{
		stop.store(true, std::memory_order_relaxed);

		if (thr.joinable()) {
			thr.join();
		}

		if (fd != -1) {
			close(fd);
		}
	}

	bool valid() const
	{
		return fd != -1;
	}

	unsigned long toggle_count() const
	{
		return toggles.load(std::memory_order_relaxed);
	}

private:
	std::thread thr;
	std::atomic<bool> stop{false};
	std::atomic<unsigned long> toggles{0};
	int fd = -1;
};

/*
 * Owns the pool that the snapshots are allocated from plus the last GError,
 * so that neither leaks when an assertion fails.
 */
class segment_mapper {
public:
	segment_mapper()
	{
		pool = rspamd_mempool_new(rspamd_mempool_suggest_size(), "task_input", 0);
	}

	segment_mapper(const segment_mapper &) = delete;
	segment_mapper &operator=(const segment_mapper &) = delete;

	~segment_mapper()
	{
		clear_error();
		rspamd_mempool_delete(pool);
	}

	struct rspamd_shmem_segment *map_tok(const rspamd_ftok_t *name_tok,
										 const char *offset,
										 const char *length,
										 gsize max_size = 0)
	{
		std::string off_str, len_str;
		rspamd_ftok_t off_tok, len_tok;

		if (offset != nullptr) {
			off_str.assign(offset);
			off_tok = ftok_of(off_str);
		}

		if (length != nullptr) {
			len_str.assign(length);
			len_tok = ftok_of(len_str);
		}

		clear_error();

		return rspamd_shmem_segment_map(pool, name_tok,
										offset != nullptr ? &off_tok : nullptr,
										length != nullptr ? &len_tok : nullptr,
										max_size, &err);
	}

	struct rspamd_shmem_segment *map(const std::string &name,
									 const char *offset,
									 const char *length,
									 gsize max_size = 0)
	{
		auto name_tok = ftok_of(name);

		return map_tok(&name_tok, offset, length, max_size);
	}

	GError *error() const
	{
		return err;
	}

	std::string error_message() const
	{
		return err != nullptr && err->message != nullptr ? std::string(err->message)
														 : std::string();
	}

private:
	void clear_error()
	{
		if (err != nullptr) {
			g_error_free(err);
			err = nullptr;
		}
	}

	rspamd_mempool_t *pool;
	GError *err = nullptr;
};

/* Every successful call must leave neither a mapping nor a descriptor behind */
static void
check_no_mapping_retained(const struct rspamd_shmem_segment *seg)
{
	CHECK(seg->map == nullptr);
	CHECK(seg->map_len == 0);
	CHECK(seg->fd == -1);
}

static std::string
segment_payload(const struct rspamd_shmem_segment *seg)
{
	return std::string(seg->data, seg->data_len);
}

/*
 * Offset, length and payload folded into one comparable string, so that a
 * failure inside a loop names the offending window instead of just printing
 * two numbers
 */
static std::string
describe_window(gsize off, gsize len, const std::string &payload)
{
	return std::to_string(off) + "+" + std::to_string(len) + ":" + payload;
}

static std::string
describe_segment(const struct rspamd_shmem_segment *seg)
{
	return describe_window(seg->offset, seg->data_len, segment_payload(seg));
}

/* Likewise for the privileged header classification loops */
static std::string
classify_header(const char *hdr, struct rspamd_task *task)
{
	return std::string(hdr) + " -> " +
		   (rspamd_task_has_file_shm_input(task) ? "privileged" : "benign");
}

class task_holder {
public:
	task_holder()
	{
		pool = rspamd_mempool_new(rspamd_mempool_suggest_size(), "task_input_task", 0);
		task = rspamd_task_new(nullptr, nullptr, pool, nullptr, nullptr, FALSE);
	}

	task_holder(const task_holder &) = delete;
	task_holder &operator=(const task_holder &) = delete;

	~task_holder()
	{
		rspamd_task_free(task);
		rspamd_mempool_delete(pool);
	}

	struct rspamd_task *get() const
	{
		return task;
	}

	void add_request_header(const char *name, const char *value)
	{
		auto *n = (rspamd_ftok_t *) rspamd_mempool_alloc(task->task_pool,
														 sizeof(rspamd_ftok_t));
		auto *v = (rspamd_ftok_t *) rspamd_mempool_alloc(task->task_pool,
														 sizeof(rspamd_ftok_t));

		n->begin = rspamd_mempool_strdup(task->task_pool, name);
		n->len = strlen(name);
		v->begin = rspamd_mempool_strdup(task->task_pool, value);
		v->len = strlen(value);

		rspamd_task_add_request_header(task, n, v);
	}

private:
	rspamd_mempool_t *pool;
	struct rspamd_task *task;
};

}// namespace rspamd_task_input_test

TEST_SUITE("task privileged input")
{
	using namespace rspamd_task_input_test;

	TEST_CASE("small window of a huge object retains no mapping")
	{
		/* Substantially larger than any page size */
		constexpr gsize obj_size = 4 * 1024 * 1024;
		constexpr gsize win_off = 1000;
		constexpr gsize win_len = 64;

		backing_object obj("small_window", obj_size);
		REQUIRE(obj.valid());

		segment_mapper mapper;
		auto *seg = mapper.map(obj.name(), "1000", "64");

		REQUIRE(seg != nullptr);
		CHECK(mapper.error() == nullptr);
		CHECK(seg->data_len == win_len);
		CHECK(seg->offset == win_off);
		CHECK(segment_payload(seg) == pattern_slice(win_off, win_len));

		/*
		 * The whole point of the windowed reader: no mapping of the 4 MiB
		 * object (nor any other mapping) may outlive the call
		 */
		check_no_mapping_retained(seg);
	}

	TEST_CASE("page aligned window returns the exact requested slice")
	{
		const gsize page = test_page_size();
		const gsize obj_size = 8 * page;
		constexpr gsize win_len = 137;

		backing_object obj("awkward_offsets", obj_size);
		REQUIRE(obj.valid());

		segment_mapper mapper;

		const std::vector<gsize> offsets = {
			0,
			1,
			page - 1,
			page,
			page + 1,
			3 * page + 17,
			obj_size - win_len,
		};

		for (auto off: offsets) {
			auto *seg = mapper.map(obj.name(), std::to_string(off).c_str(),
								   std::to_string(win_len).c_str());

			REQUIRE(seg != nullptr);
			CHECK(mapper.error() == nullptr);
			/* One assertion so that a failure names the offending offset */
			CHECK(describe_segment(seg) ==
				  describe_window(off, win_len, pattern_slice(off, win_len)));
			check_no_mapping_retained(seg);
		}
	}

	TEST_CASE("zero length window maps nothing")
	{
		const gsize page = test_page_size();

		backing_object obj("zero_length", 4 * page);
		REQUIRE(obj.valid());

		segment_mapper mapper;

		SUBCASE("explicit zero length")
		{
			auto *seg = mapper.map(obj.name(), "0", "0");

			REQUIRE(seg != nullptr);
			CHECK(mapper.error() == nullptr);
			CHECK(seg->data_len == 0);
			REQUIRE(seg->data != nullptr);
			CHECK(seg->data[0] == '\0');
			check_no_mapping_retained(seg);
		}

		SUBCASE("explicit zero length at a non zero offset")
		{
			auto *seg = mapper.map(obj.name(), "1234", "0");

			REQUIRE(seg != nullptr);
			CHECK(mapper.error() == nullptr);
			CHECK(seg->data_len == 0);
			CHECK(seg->offset == 1234);
			check_no_mapping_retained(seg);
		}

		SUBCASE("offset at the very end without a length header")
		{
			/* Defaults to st_size - offset, i.e. zero, and maps nothing */
			auto *seg = mapper.map(obj.name(),
								   std::to_string(obj.size()).c_str(), nullptr);

			REQUIRE(seg != nullptr);
			CHECK(mapper.error() == nullptr);
			CHECK(seg->data_len == 0);
			check_no_mapping_retained(seg);
		}
	}

	TEST_CASE("max_size is enforced on the selected length")
	{
		const gsize page = test_page_size();
		const gsize obj_size = 4 * page;
		constexpr gsize max_size = 128;

		backing_object obj("max_size", obj_size);
		REQUIRE(obj.valid());

		segment_mapper mapper;

		SUBCASE("the whole object is refused when it exceeds max_size")
		{
			/*
			 * Without a length header the selected length is the whole object,
			 * which is what max_size is compared against
			 */
			auto *seg = mapper.map(obj.name(), nullptr, nullptr, max_size);

			CHECK(seg == nullptr);
			CHECK(mapper.error() != nullptr);
		}

		SUBCASE("an explicit length above max_size is refused")
		{
			auto *seg = mapper.map(obj.name(), "0",
								   std::to_string(max_size + 1).c_str(), max_size);

			CHECK(seg == nullptr);
			CHECK(mapper.error() != nullptr);
		}

		SUBCASE("a small window of a large object still succeeds")
		{
			/*
			 * max_size bounds the payload, not the backing object: this is the
			 * whole reason for mapping a window instead of the object
			 */
			auto *seg = mapper.map(obj.name(), "4096", "64", max_size);

			REQUIRE(seg != nullptr);
			CHECK(mapper.error() == nullptr);
			CHECK(seg->data_len == 64);
			CHECK(segment_payload(seg) == pattern_slice(4096, 64));
			check_no_mapping_retained(seg);
		}

		SUBCASE("a length of exactly max_size is accepted")
		{
			auto *seg = mapper.map(obj.name(), "0",
								   std::to_string(max_size).c_str(), max_size);

			REQUIRE(seg != nullptr);
			CHECK(mapper.error() == nullptr);
			CHECK(seg->data_len == max_size);
			CHECK(segment_payload(seg) == pattern_slice(0, max_size));
		}

		SUBCASE("max_size of zero means unlimited")
		{
			auto *seg = mapper.map(obj.name(), nullptr, nullptr, 0);

			REQUIRE(seg != nullptr);
			CHECK(mapper.error() == nullptr);
			CHECK(seg->data_len == obj_size);
			check_no_mapping_retained(seg);
		}
	}

	TEST_CASE("offset and length are validated together")
	{
		const gsize obj_size = 4096;

		backing_object obj("offset_length", obj_size);
		REQUIRE(obj.valid());

		segment_mapper mapper;

		SUBCASE("offset beyond the end of the object")
		{
			auto *seg = mapper.map(obj.name(),
								   std::to_string(obj_size + 1).c_str(), nullptr);

			CHECK(seg == nullptr);
			CHECK(mapper.error() != nullptr);
		}

		SUBCASE("length running past the end of the object")
		{
			/* Both fit on their own, their sum does not */
			auto *seg = mapper.map(obj.name(), "4000", "1000");

			CHECK(seg == nullptr);
			CHECK(mapper.error() != nullptr);
		}

		SUBCASE("length one byte past the end of the object")
		{
			auto *seg = mapper.map(obj.name(), "4000",
								   std::to_string(obj_size - 4000 + 1).c_str());

			CHECK(seg == nullptr);
			CHECK(mapper.error() != nullptr);
		}

		SUBCASE("length exactly up to the end of the object is accepted")
		{
			auto *seg = mapper.map(obj.name(), "4000",
								   std::to_string(obj_size - 4000).c_str());

			REQUIRE(seg != nullptr);
			CHECK(mapper.error() == nullptr);
			CHECK(seg->data_len == obj_size - 4000);
			CHECK(segment_payload(seg) == pattern_slice(4000, obj_size - 4000));
		}

		SUBCASE("offset near SIZE_MAX")
		{
			auto *seg = mapper.map(obj.name(), "18446744073709551615", "16");

			CHECK(seg == nullptr);
			CHECK(mapper.error() != nullptr);
		}

		SUBCASE("offset plus length wrapping around SIZE_MAX")
		{
			/*
			 * A naive `offset + length > st_size` would wrap here and let the
			 * request through; the combined check must not
			 */
			auto *seg = mapper.map(obj.name(), "4000", "18446744073709551615");

			CHECK(seg == nullptr);
			CHECK(mapper.error() != nullptr);
		}

		SUBCASE("non numeric offset and length")
		{
			auto *seg = mapper.map(obj.name(), "not-a-number", "16");

			CHECK(seg == nullptr);
			CHECK(mapper.error() != nullptr);

			seg = mapper.map(obj.name(), "0", "not-a-number");

			CHECK(seg == nullptr);
			CHECK(mapper.error() != nullptr);
		}

		SUBCASE("empty object is refused")
		{
			backing_object empty_obj("empty", 0);
			REQUIRE(empty_obj.valid());

			auto *seg = mapper.map(empty_obj.name(), nullptr, nullptr);

			CHECK(seg == nullptr);
			CHECK(mapper.error() != nullptr);
		}
	}

	TEST_CASE("malformed segment names are rejected before any syscall")
	{
		segment_mapper mapper;

		SUBCASE("null name token")
		{
			auto *seg = mapper.map_tok(nullptr, nullptr, nullptr);

			CHECK(seg == nullptr);
			CHECK(mapper.error() != nullptr);
		}

		SUBCASE("empty name")
		{
			std::string empty;
			auto tok = ftok_of(empty);
			auto *seg = mapper.map_tok(&tok, nullptr, nullptr);

			CHECK(seg == nullptr);
			CHECK(mapper.error() != nullptr);
		}

		SUBCASE("name with a newline")
		{
			auto *seg = mapper.map("/rspamd_test_input\nname", nullptr, nullptr);

			CHECK(seg == nullptr);
			CHECK(mapper.error() != nullptr);
		}

		SUBCASE("name with a low control byte")
		{
			auto *seg = mapper.map(std::string("/rspamd_test_input\x01name"),
								   nullptr, nullptr);

			CHECK(seg == nullptr);
			CHECK(mapper.error() != nullptr);
		}

		SUBCASE("name with DEL")
		{
			auto *seg = mapper.map(std::string("/rspamd_test_input\x7fname"),
								   nullptr, nullptr);

			CHECK(seg == nullptr);
			CHECK(mapper.error() != nullptr);
		}

		SUBCASE("name with an embedded NUL")
		{
			std::string name("/rspamd_test_input\0name", 23);
			auto tok = ftok_of(name);
			auto *seg = mapper.map_tok(&tok, nullptr, nullptr);

			CHECK(seg == nullptr);
			CHECK(mapper.error() != nullptr);
		}

		SUBCASE("name with a url encoded NUL")
		{
			/* The NUL only appears after decoding, it must still be caught */
			auto *seg = mapper.map("/rspamd_test_input%00name", nullptr, nullptr);

			CHECK(seg == nullptr);
			CHECK(mapper.error() != nullptr);
		}
	}

	TEST_CASE("overlong segment name is rejected rather than truncated")
	{
		segment_mapper mapper;

#ifndef HAVE_SANE_SHMEM
		/*
		 * On the file flavour a path can be padded with redundant slashes,
		 * which lets us build a name whose first PATH_MAX - 1 bytes are a real,
		 * openable path to an object that exists. If the implementation ever
		 * went back to copying with silent truncation, the truncated name would
		 * therefore *succeed*, and this test would go red.
		 */
		backing_object obj("overlong", 256);
		REQUIRE(obj.valid());

		const auto &path = obj.name();
		auto slash = path.rfind('/');
		REQUIRE(slash != std::string::npos);
		REQUIRE(path.size() < (gsize) PATH_MAX - 1);

		auto pad = (gsize) PATH_MAX - 1 - path.size();
		auto max_len_name = path.substr(0, slash + 1) + std::string(pad, '/') +
							path.substr(slash + 1);
		REQUIRE(max_len_name.size() == (gsize) PATH_MAX - 1);

		/*
		 * The premise of the second subcase: those PATH_MAX - 1 bytes really do
		 * name the object that has just been created, so acting on a truncated
		 * copy of a longer name would succeed
		 */
		int probe_fd = open(max_len_name.c_str(), O_RDONLY);
		REQUIRE(probe_fd != -1);
		close(probe_fd);

		SUBCASE("a name of exactly PATH_MAX - 1 bytes is still accepted")
		{
			auto *seg = mapper.map(max_len_name, "0", "16");

			REQUIRE(seg != nullptr);
			CHECK(mapper.error() == nullptr);
			CHECK(seg->data_len == 16);
			CHECK(segment_payload(seg) == pattern_slice(0, 16));
		}

		SUBCASE("a longer name is refused although its prefix is valid")
		{
			auto overlong = max_len_name + "AAAA";
			auto *seg = mapper.map(overlong, "0", "16");

			CHECK(seg == nullptr);
			REQUIRE(mapper.error() != nullptr);
			/* Refused by the sanitiser, not by a failing open of a shorter name */
			CHECK(mapper.error_message().find("too long") != std::string::npos);
		}
#else
		/*
		 * POSIX shared memory names may not contain a slash and are limited to
		 * NAME_MAX, so a PATH_MAX sized prefix cannot name a real object here.
		 * What can still be asserted is that the refusal comes from the length
		 * check itself, before any syscall sees the name.
		 */
		SUBCASE("a name longer than PATH_MAX is refused")
		{
			auto overlong = "/rspamd_test_input_" + std::string(PATH_MAX, 'A');
			auto *seg = mapper.map(overlong, "0", "16");

			CHECK(seg == nullptr);
			REQUIRE(mapper.error() != nullptr);
			CHECK(mapper.error_message().find("too long") != std::string::npos);
		}
#endif
	}

	TEST_CASE("snapshot is stable when the backing object is resized")
	{
		const gsize page = test_page_size();
		const gsize obj_size = 3 * page;
		const gsize win_off = page + 10;
		constexpr gsize win_len = 200;

		backing_object obj("resize", obj_size);
		REQUIRE(obj.valid());

		segment_mapper mapper;
		auto *seg = mapper.map(obj.name(), std::to_string(win_off).c_str(),
							   std::to_string(win_len).c_str());

		REQUIRE(seg != nullptr);
		CHECK(seg->data_len == win_len);

		const auto expected = pattern_slice(win_off, win_len);
		CHECK(segment_payload(seg) == expected);
		check_no_mapping_retained(seg);

		/* Shrink the object below the window that was just read */
		REQUIRE(obj.resize(100));
		CHECK(segment_payload(seg) == expected);

		/* And below the offset of the window, i.e. to nothing at all */
		REQUIRE(obj.resize(1));
		CHECK(segment_payload(seg) == expected);

		/* A fresh request for the same window must now be refused */
		auto *stale = mapper.map(obj.name(), std::to_string(win_off).c_str(),
								 std::to_string(win_len).c_str());
		CHECK(stale == nullptr);
		CHECK(mapper.error() != nullptr);

		/* Grow it again and overwrite everything with different bytes */
		REQUIRE(obj.resize(8 * page));
		REQUIRE(obj.fill_with('Z'));
		CHECK(segment_payload(seg) == expected);

		/* The new content is visible only to a new request */
		auto *fresh = mapper.map(obj.name(), std::to_string(win_off).c_str(),
								 std::to_string(win_len).c_str());
		REQUIRE(fresh != nullptr);
		CHECK(segment_payload(fresh) == std::string(win_len, 'Z'));
		CHECK(segment_payload(seg) == expected);
	}

	TEST_CASE("a concurrently truncated object is survived rather than faulted on")
	{
		/*
		 * The test above resizes the object only *after* the call has returned,
		 * so it never touches the interval that actually hurts: the one between
		 * the fstat that validates the request and the copy that fulfils it.
		 * A client owns the object and may truncate it exactly there, and a
		 * copy out of a mapping then reads pages that no longer exist, which is
		 * SIGBUS and a dead worker rather than a failed request. Reading the
		 * window instead cannot fault; it merely returns fewer bytes.
		 *
		 * Which of the two permitted outcomes a given iteration gets is up to
		 * the scheduler, so only the outcomes themselves are asserted: either a
		 * snapshot no longer than the window that was asked for, or a refusal
		 * that says why. Completing the loop at all is the regression test.
		 */
		constexpr gsize big_size = 2 * 1024 * 1024;
		constexpr gsize small_size = 4096;
		constexpr gsize win_len = 512 * 1024;
		/* At the very end, so that shrinking really does remove its pages */
		constexpr gsize win_off = big_size - win_len;
		constexpr int iterations = 600;

		backing_object obj("truncate_race", big_size);
		REQUIRE(obj.valid());

		/*
		 * Zero filled on purpose: ftruncate only ever zero fills, so whatever
		 * the two threads do, every byte that is really read back is a zero.
		 * A data_len that reported the requested length rather than the number
		 * of bytes that were actually read would therefore hand out
		 * uninitialised pool memory, and that is visible right here.
		 */
		REQUIRE(obj.fill_with('\0'));

		background_truncator truncator(obj, big_size, small_size);
		REQUIRE(truncator.valid());

		const std::string zeros(win_len, '\0');
		const auto off_str = std::to_string(win_off);
		const auto len_str = std::to_string(win_len);

		int completed = 0, snapshots = 0, refusals = 0;
		int short_reads = 0, partial_reads = 0;
		int oversized = 0, unexplained = 0, retained = 0, dirty = 0;
		int null_data = 0;

		for (int i = 0; i < iterations; i++) {
			/* One pool per iteration, so that the snapshots cannot pile up */
			segment_mapper mapper;
			auto *seg = mapper.map(obj.name(), off_str.c_str(), len_str.c_str());

			completed++;

			if (seg == nullptr) {
				/* Losing the race is fine as long as the refusal says why */
				refusals++;

				if (mapper.error() == nullptr) {
					unexplained++;
				}

				continue;
			}

			snapshots++;

			if (seg->data == nullptr) {
				/* Even an empty snapshot is copied from by the callers */
				null_data++;
				continue;
			}

			if (seg->data_len > win_len) {
				oversized++;
				continue;
			}

			if (seg->data_len < win_len) {
				short_reads++;

				if (seg->data_len > 0) {
					/* The object shrank in the middle of the read itself */
					partial_reads++;
				}
			}

			if (seg->map != nullptr || seg->map_len != 0 || seg->fd != -1) {
				retained++;
			}

			/*
			 * Reads every byte that was reported as present, so that a
			 * data_len covering bytes that were never read shows up as the
			 * fill pattern of a fresh allocation, and one running past the
			 * allocation altogether is caught by the sanitiser
			 */
			if (memcmp(seg->data, zeros.data(), seg->data_len) != 0) {
				dirty++;
			}
		}

		INFO("snapshots: " << snapshots << ", refusals: " << refusals
						   << ", short reads: " << short_reads
						   << " (" << partial_reads << " partial)"
						   << ", toggles: " << truncator.toggle_count());

		/* Getting this far at all is the point: the old reader took SIGBUS */
		CHECK(completed == iterations);
		CHECK(snapshots + refusals == iterations);
		/* Otherwise nothing was ever raced and the loop proves nothing */
		CHECK(snapshots > 0);
		CHECK(null_data == 0);
		/* Never more than was asked for, whatever the object did meanwhile */
		CHECK(oversized == 0);
		CHECK(unexplained == 0);
		/* The read path keeps neither a mapping nor a descriptor */
		CHECK(retained == 0);
		/* data_len bounds real content, not the tail of a fresh allocation */
		CHECK(dirty == 0);
	}

	TEST_CASE("rspamd_task_allow_file_shm_input")
	{
		CHECK(rspamd_task_allow_file_shm_input(nullptr) == FALSE);

		task_holder th;

		/* Local, non network tasks are trusted by default */
		CHECK(rspamd_task_allow_file_shm_input(th.get()) == TRUE);

		th.get()->protocol_flags &= ~RSPAMD_TASK_PROTOCOL_FLAG_ALLOW_FILE_SHM_INPUT;
		CHECK(rspamd_task_allow_file_shm_input(th.get()) == FALSE);

		th.get()->protocol_flags |= RSPAMD_TASK_PROTOCOL_FLAG_ALLOW_FILE_SHM_INPUT;
		CHECK(rspamd_task_allow_file_shm_input(th.get()) == TRUE);

		/* The answer must not depend on the presence of the headers themselves */
		th.add_request_header("Shm", "/whatever");
		th.get()->protocol_flags &= ~RSPAMD_TASK_PROTOCOL_FLAG_ALLOW_FILE_SHM_INPUT;
		CHECK(rspamd_task_allow_file_shm_input(th.get()) == FALSE);
	}

	TEST_CASE("rspamd_task_has_file_shm_input")
	{
		CHECK(rspamd_task_has_file_shm_input(nullptr) == FALSE);

		SUBCASE("a task without request headers carries no privileged control")
		{
			task_holder th;

			CHECK(rspamd_task_has_file_shm_input(th.get()) == FALSE);
		}

		SUBCASE("privileged controls are detected case insensitively")
		{
			const std::vector<const char *> privileged = {
				"file",
				"File",
				"FILE",
				"path",
				"Path",
				"PATH",
				"shm",
				"Shm",
				"SHM",
				"shm-offset",
				"Shm-Offset",
				"SHM-Offset",
				"shm-length",
				"Shm-Length",
				"SHM-LENGTH",
			};

			for (const auto *hdr: privileged) {
				task_holder th;
				th.add_request_header(hdr, "1");

				CHECK(classify_header(hdr, th.get()) ==
					  std::string(hdr) + " -> privileged");
			}
		}

		SUBCASE("unrelated headers are not privileged controls")
		{
			/*
			 * `Filename` is merely a label for the message and must never be
			 * mistaken for the `File` control, no matter how it is spelled
			 */
			const std::vector<const char *> benign = {
				"Filename",
				"filename",
				"FILENAME",
				"File-Name",
				"Pathname",
				"Shmem",
				"Shm-Offsets",
				"X-Shm",
				"Queue-Id",
				"From",
				"Rcpt",
				"Settings-Id",
			};

			for (const auto *hdr: benign) {
				task_holder th;
				th.add_request_header(hdr, "1");

				CHECK(classify_header(hdr, th.get()) ==
					  std::string(hdr) + " -> benign");
			}
		}

		SUBCASE("a privileged control among benign headers is still detected")
		{
			task_holder th;

			th.add_request_header("Filename", "message.eml");
			th.add_request_header("Queue-Id", "deadbeef");
			th.add_request_header("SHM-Offset", "0");

			CHECK(rspamd_task_has_file_shm_input(th.get()) == TRUE);
		}

		SUBCASE("detection performs no IO, the object need not exist")
		{
			task_holder th;

			th.add_request_header("Shm", "/rspamd_test_input_does_not_exist");

			CHECK(rspamd_task_has_file_shm_input(th.get()) == TRUE);
		}
	}
}

#endif /* RSPAMD_CXX_UNIT_TASK_INPUT_HXX */
