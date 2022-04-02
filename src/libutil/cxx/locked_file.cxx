//
// Created by Vsevolod Stakhov on 02/04/2022.
//

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
	auto fd = ::open(fname, oflags);

	if (fd == -1) {
		return tl::make_unexpected(fmt::format("cannot open file {}: {}", fname, ::strerror(errno)));
	}

	if (!rspamd_file_lock(fd, FALSE)) {
		close(fd);
		return tl::make_unexpected(fmt::format("cannot lock file {}: {}", fname, ::strerror(errno)));
	}

	auto ret = raii_locked_file{fd};

	if (fstat(ret.fd, &ret.st) == -1) {
		return tl::make_unexpected(fmt::format("cannot stat file {}: {}", fname, ::strerror(errno)));
	}

	return ret;
}

raii_locked_file::~raii_locked_file()
{
	if (fd != -1) {
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
	auto fd = ::open(fname, oflags, perms);

	if (fd == -1) {
		return tl::make_unexpected(fmt::format("cannot create file {}: {}", fname, ::strerror(errno)));
	}

	if (!rspamd_file_lock(fd, FALSE)) {
		close(fd);
		return tl::make_unexpected(fmt::format("cannot lock file {}: {}", fname, ::strerror(errno)));
	}

	auto ret = raii_locked_file{fd};

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
	munmap(map, file.get_stat().st_size);
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

}
