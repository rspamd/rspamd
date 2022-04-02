//
// Created by Vsevolod Stakhov on 02/04/2022.
//

#include "locked_file.hxx"
#include <fmt/core.h>
#include "libutil/util.h"
#include "libutil/unix-std.h"

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

	return raii_locked_file{fd};
}

raii_locked_file::~raii_locked_file()
{
	if (fd != -1) {
		(void) rspamd_file_unlock(fd, FALSE);
		close(fd);
	}
}
