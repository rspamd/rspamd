//
// Created by Vsevolod Stakhov on 02/04/2022.
//

#include "locked_file.hxx"
#include <fmt/core.h>
#include "libutil/util.h"
#include "libutil/unix-std.h"

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

raii_mmaped_locked_file::raii_mmaped_locked_file(raii_locked_file &&_file, void *_map)
	: file(std::move(_file)), map(_map) {}

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

raii_mmaped_locked_file::raii_mmaped_locked_file(raii_mmaped_locked_file &&other)  noexcept
	: file(std::move(other.file))
{
	std::swap(map, other.map);
}

}
