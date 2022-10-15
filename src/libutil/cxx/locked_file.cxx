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

auto raii_file::open(const char *fname, int flags) -> tl::expected<raii_file, std::string>
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

	auto ret = raii_file{fname, fd, false};

	if (fstat(ret.fd, &ret.st) == -1) {
		return tl::make_unexpected(fmt::format("cannot stat file {}: {}", fname, ::strerror(errno)));
	}

	return ret;
}

auto raii_file::create(const char *fname, int flags, int perms) -> tl::expected<raii_file, std::string>
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

	auto ret = raii_file{fname, fd, false};

	if (fstat(ret.fd, &ret.st) == -1) {
		return tl::make_unexpected(fmt::format("cannot stat file {}: {}", fname, ::strerror(errno)));
	}

	return ret;
}

auto raii_file::create_temp(const char *fname, int flags, int perms) -> tl::expected<raii_file, std::string>
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
		unlink(fname);
		close(fd);
		return tl::make_unexpected(fmt::format("cannot lock file {}: {}", fname, ::strerror(errno)));
	}

	auto ret = raii_file{fname, fd, true};

	if (fstat(ret.fd, &ret.st) == -1) {
		return tl::make_unexpected(fmt::format("cannot stat file {}: {}", fname, ::strerror(errno)));
	}

	return ret;
}

auto raii_file::mkstemp(const char *pattern, int flags, int perms) -> tl::expected<raii_file, std::string>
{
	int oflags = flags;
#ifdef O_CLOEXEC
	oflags |= O_CLOEXEC | O_CREAT | O_EXCL;
#endif
	if (pattern == nullptr) {
		return tl::make_unexpected("cannot open file; pattern is nullptr");
	}

	std::string mutable_pattern = pattern;

	auto fd = g_mkstemp_full(mutable_pattern.data(), oflags, perms);

	if (fd == -1) {
		return tl::make_unexpected(fmt::format("cannot create file {}: {}", pattern, ::strerror(errno)));
	}

	if (!rspamd_file_lock(fd, TRUE)) {
		close(fd);
		(void)unlink(mutable_pattern.c_str());
		return tl::make_unexpected(fmt::format("cannot lock file {}: {}", pattern, ::strerror(errno)));
	}

	auto ret = raii_file{mutable_pattern.c_str(), fd, true};

	if (fstat(ret.fd, &ret.st) == -1) {
		return tl::make_unexpected(fmt::format("cannot stat file {}: {}",
				mutable_pattern.c_str(), ::strerror(errno)));
	}

	return ret;
}

raii_file::~raii_file() noexcept
{
	if (fd != -1) {
		if (temp) {
			(void)unlink(fname.c_str());
		}
		(void) rspamd_file_unlock(fd, FALSE);
		close(fd);
	}
}


raii_locked_file::~raii_locked_file() noexcept
{
	if (fd != -1) {
		(void) rspamd_file_unlock(fd, FALSE);
	}
}

auto raii_locked_file::lock_raii_file(raii_file &&unlocked) -> tl::expected<raii_locked_file, std::string>
{
	if (!rspamd_file_lock(unlocked.get_fd(), TRUE)) {
		return tl::make_unexpected(fmt::format("cannot lock file {}: {}", unlocked.get_name(), ::strerror(errno)));
	}

	return raii_locked_file{std::move(unlocked)};
}

raii_mmaped_file::raii_mmaped_file(raii_file &&_file, void *_map)
		: file(std::move(_file)), map(_map)
{
}

auto raii_mmaped_file::mmap_shared(raii_file &&file,
								   int flags) -> tl::expected<raii_mmaped_file, std::string>
{
	void *map;

	map = mmap(NULL, file.get_stat().st_size, flags, MAP_SHARED, file.get_fd(), 0);

	if (map == MAP_FAILED) {
		return tl::make_unexpected(fmt::format("cannot mmap file at fd: {}: {}",
				file.get_fd(), ::strerror(errno)));

	}

	return raii_mmaped_file{std::move(file), map};
}

auto raii_mmaped_file::mmap_shared(const char *fname, int open_flags,
								   int mmap_flags) -> tl::expected<raii_mmaped_file, std::string>
{
	auto file = raii_file::open(fname, open_flags);

	if (!file.has_value()) {
		return tl::make_unexpected(file.error());
	}

	return raii_mmaped_file::mmap_shared(std::move(file.value()), mmap_flags);
}

raii_mmaped_file::~raii_mmaped_file()
{
	if (map != nullptr) {
		munmap(map, file.get_stat().st_size);
	}
}

raii_mmaped_file::raii_mmaped_file(raii_mmaped_file &&other) noexcept
		: file(std::move(other.file))
{
	std::swap(map, other.map);
}

auto raii_file_sink::create(const char *fname, int flags, int perms,
							const char *suffix) -> tl::expected<raii_file_sink, std::string>
{
	if (!fname || !suffix) {
		return tl::make_unexpected("cannot create file sink: bad input arguments");
	}

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
auto random_fname(std::string_view extension) {
	const auto *tmpdir = getenv("TMPDIR");
	if (tmpdir == nullptr) {
		tmpdir = G_DIR_SEPARATOR_S "tmp";
	}

	std::string out_fname{tmpdir};
	out_fname += G_DIR_SEPARATOR_S;

	unsigned char hexbuf[32];
	rspamd_random_hex(hexbuf, sizeof(hexbuf));
	out_fname.append((const char *)hexbuf, sizeof(hexbuf));
	if (!extension.empty()) {
		out_fname.append(".");
		out_fname.append(extension);
	}

	return out_fname;
}
TEST_SUITE("loked files utils") {

TEST_CASE("create and delete file") {
	auto fname = random_fname("tmp");
	{
		auto raii_locked_file = raii_locked_file::create_temp(fname.c_str(), O_RDONLY, 00600);
		CHECK(raii_locked_file.has_value());
		CHECK(raii_locked_file.value().get_extension() == "tmp");
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
	auto fname = random_fname("");
	{
		auto raii_locked_file = raii_locked_file::create_temp(fname.c_str(), O_RDONLY, 00600);
		CHECK(raii_locked_file.has_value());
		CHECK(raii_locked_file.value().get_extension() == "");
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

TEST_CASE("tempfile") {
	std::string tmpname;
	{
		auto raii_locked_file = raii_locked_file::mkstemp("/tmp//doctest-XXXXXXXX",
				O_RDONLY, 00600);
		CHECK(raii_locked_file.has_value());
		CHECK(raii_locked_file.value().get_dir() == "/tmp");
		CHECK(access(raii_locked_file.value().get_name().data(), R_OK) == 0);
		auto raii_locked_file2 = raii_locked_file::open(raii_locked_file.value().get_name().data(), O_RDONLY);
		CHECK(!raii_locked_file2.has_value());
		CHECK(access(raii_locked_file.value().get_name().data(), R_OK) == 0);
		tmpname = raii_locked_file.value().get_name();
	}
	// File must be deleted after this call
	auto ret = ::access(tmpname.c_str(), R_OK);
	auto serrno = errno;
	CHECK(ret == -1);
	CHECK(serrno == ENOENT);
}

} // TEST_SUITE

} // namespace tests

} // namespace rspamd::util
