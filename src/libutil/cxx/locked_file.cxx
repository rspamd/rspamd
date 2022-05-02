/*-
 * Copyright 2022 Vsevolod Stakhov
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
#include "locked_file.hxx"
#include <fmt/core.h>
#include "libutil/util.h"
#include "libutil/unix-std.h"

#define DOCTEST_CONFIG_IMPLEMENTATION_IN_DLL

#include "doctest/doctest.h"

namespace rspamd::util {

auto raii_locked_file::open(const char *fname, int flags) -> tl::expected<raii_locked_file, std::string>
{
	int oflags = flags;
#ifdef O_CLOEXEC
	oflags |= O_CLOEXEC;
#endif

	if (fname == nullptr) {
		return tl::make_unexpected("cannot open file; filename is nullptr");
	}

	auto fd = ::open(fname, oflags);

	if (fd == -1) {
		return tl::make_unexpected(fmt::format("cannot open file {}: {}", fname, ::strerror(errno)));
	}

	if (!rspamd_file_lock(fd, TRUE)) {
		close(fd);
		return tl::make_unexpected(fmt::format("cannot lock file {}: {}", fname, ::strerror(errno)));
	}

	auto ret = raii_locked_file{fname, fd, false};

	if (fstat(ret.fd, &ret.st) == -1) {
		return tl::make_unexpected(fmt::format("cannot stat file {}: {}", fname, ::strerror(errno)));
	}

	return ret;
}

raii_locked_file::~raii_locked_file()
{
	if (fd != -1) {
		if (temp) {
			(void)unlink(fname.c_str());
		}
		(void) rspamd_file_unlock(fd, FALSE);
		close(fd);
	}
}

auto raii_locked_file::create(const char *fname, int flags, int perms) -> tl::expected<raii_locked_file, std::string>
{
	int oflags = flags;
#ifdef O_CLOEXEC
	oflags |= O_CLOEXEC | O_CREAT | O_EXCL;
#endif

	if (fname == nullptr) {
		return tl::make_unexpected("cannot open file; filename is nullptr");
	}

	auto fd = ::open(fname, oflags, perms);

	if (fd == -1) {
		return tl::make_unexpected(fmt::format("cannot create file {}: {}", fname, ::strerror(errno)));
	}

	if (!rspamd_file_lock(fd, TRUE)) {
		close(fd);
		return tl::make_unexpected(fmt::format("cannot lock file {}: {}", fname, ::strerror(errno)));
	}

	auto ret = raii_locked_file{fname, fd, false};

	if (fstat(ret.fd, &ret.st) == -1) {
		return tl::make_unexpected(fmt::format("cannot stat file {}: {}", fname, ::strerror(errno)));
	}

	return ret;
}

auto raii_locked_file::create_temp(const char *fname, int flags, int perms) -> tl::expected<raii_locked_file, std::string>
{
	int oflags = flags;
#ifdef O_CLOEXEC
	oflags |= O_CLOEXEC | O_CREAT | O_EXCL;
#endif
	if (fname == nullptr) {
		return tl::make_unexpected("cannot open file; filename is nullptr");
	}

	auto fd = ::open(fname, oflags, perms);

	if (fd == -1) {
		return tl::make_unexpected(fmt::format("cannot create file {}: {}", fname, ::strerror(errno)));
	}

	if (!rspamd_file_lock(fd, TRUE)) {
		close(fd);
		return tl::make_unexpected(fmt::format("cannot lock file {}: {}", fname, ::strerror(errno)));
	}

	auto ret = raii_locked_file{fname, fd, true};

	if (fstat(ret.fd, &ret.st) == -1) {
		return tl::make_unexpected(fmt::format("cannot stat file {}: {}", fname, ::strerror(errno)));
	}

	return ret;
}

raii_mmaped_locked_file::raii_mmaped_locked_file(raii_locked_file &&_file, void *_map)
		: file(std::move(_file)), map(_map)
{
}

auto raii_mmaped_locked_file::mmap_shared(raii_locked_file &&file,
										  int flags) -> tl::expected<raii_mmaped_locked_file, std::string>
{
	void *map;

	map = mmap(NULL, file.get_stat().st_size, flags, MAP_SHARED, file.get_fd(), 0);

	if (map == MAP_FAILED) {
		return tl::make_unexpected(fmt::format("cannot mmap file at fd: {}: {}",
				file.get_fd(), ::strerror(errno)));

	}

	return raii_mmaped_locked_file{std::move(file), map};
}

auto raii_mmaped_locked_file::mmap_shared(const char *fname, int open_flags,
										  int mmap_flags) -> tl::expected<raii_mmaped_locked_file, std::string>
{
	auto file = raii_locked_file::open(fname, open_flags);

	if (!file.has_value()) {
		return tl::make_unexpected(file.error());
	}

	return raii_mmaped_locked_file::mmap_shared(std::move(file.value()), mmap_flags);
}

raii_mmaped_locked_file::~raii_mmaped_locked_file()
{
	if (map != nullptr) {
		munmap(map, file.get_stat().st_size);
	}
}

raii_mmaped_locked_file::raii_mmaped_locked_file(raii_mmaped_locked_file &&other) noexcept
		: file(std::move(other.file))
{
	std::swap(map, other.map);
}

auto raii_file_sink::create(const char *fname, int flags, int perms,
							const char *suffix) -> tl::expected<raii_file_sink, std::string>
{
	auto tmp_fname = fmt::format("{}.{}", fname, suffix);
	auto file = raii_locked_file::create(tmp_fname.c_str(), flags, perms);

	if (!file.has_value()) {
		return tl::make_unexpected(file.error());
	}

	return raii_file_sink{std::move(file.value()), fname, std::move(tmp_fname)};
}

auto raii_file_sink::write_output() -> bool
{
	if (success) {
		/* We cannot write output twice */
		return false;
	}

	if (rename(tmp_fname.c_str(), output_fname.c_str()) == -1) {
		return false;
	}

	success = true;

	return true;
}

raii_file_sink::~raii_file_sink()
{
	if (!success) {
		/* Unlink sink */
		unlink(tmp_fname.c_str());
	}
}

raii_file_sink::raii_file_sink(raii_locked_file &&_file, const char *_output, std::string &&_tmp_fname)
		: file(std::move(_file)), output_fname(_output), tmp_fname(std::move(_tmp_fname)), success(false)
{
}

raii_file_sink::raii_file_sink(raii_file_sink &&other) noexcept
		: file(std::move(other.file)),
		  output_fname(std::move(other.output_fname)),
		  tmp_fname(std::move(other.tmp_fname)),
		  success(other.success)
{
}

namespace tests {
template<class T>
static auto test_read_file(const T& f) {
	auto fd = f.get_fd();
	(void)::lseek(fd, 0, SEEK_SET);
	std::string buf('\0', (std::size_t)f.get_size());
	::read(fd, buf.data(), buf.size());
	return buf;
}
template<class T>
static auto test_write_file(const T& f, const std::string_view &buf) {
	auto fd = f.get_fd();
	(void)::lseek(fd, 0, SEEK_SET);
	return ::write(fd, buf.data(), buf.size());
}
auto random_fname() {
	const auto *tmpdir = getenv("TMPDIR");
	if (tmpdir == nullptr) {
		tmpdir = G_DIR_SEPARATOR_S "tmp";
	}

	std::string out_fname{tmpdir};
	out_fname += G_DIR_SEPARATOR_S;

	unsigned char hexbuf[32];
	rspamd_random_hex(hexbuf, sizeof(hexbuf));
	out_fname.append((const char *)hexbuf, sizeof(hexbuf));

	return out_fname;
}
TEST_SUITE("loked files utils") {

TEST_CASE("create and delete file") {
	auto fname = random_fname();
	{
		auto raii_locked_file = raii_locked_file::create_temp(fname.c_str(), O_RDONLY, 00600);
		CHECK(raii_locked_file.has_value());
		CHECK(::access(fname.c_str(), R_OK) == 0);
	}
	// File must be deleted after this call
	auto ret = ::access(fname.c_str(), R_OK);
	auto serrno = errno;
	CHECK(ret == -1);
	CHECK(serrno == ENOENT);
	// Create one more time
	{
		auto raii_locked_file = raii_locked_file::create_temp(fname.c_str(), O_RDONLY, 00600);
		CHECK(raii_locked_file.has_value());
		CHECK(::access(fname.c_str(), R_OK) == 0);
	}
	ret = ::access(fname.c_str(), R_OK);
	serrno = errno;
	CHECK(ret == -1);
	CHECK(serrno == ENOENT);
}

TEST_CASE("check lock") {
	auto fname = random_fname();
	{
		auto raii_locked_file = raii_locked_file::create_temp(fname.c_str(), O_RDONLY, 00600);
		CHECK(raii_locked_file.has_value());
		CHECK(::access(fname.c_str(), R_OK) == 0);
		auto raii_locked_file2 = raii_locked_file::open(fname.c_str(), O_RDONLY);
		CHECK(!raii_locked_file2.has_value());
		CHECK(::access(fname.c_str(), R_OK) == 0);
	}
	// File must be deleted after this call
	auto ret = ::access(fname.c_str(), R_OK);
	auto serrno = errno;
	CHECK(ret == -1);
	CHECK(serrno == ENOENT);
}

} // TEST_SUITE

} // namespace tests

} // namespace rspamd::util
