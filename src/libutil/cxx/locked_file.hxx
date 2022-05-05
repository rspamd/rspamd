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
#ifndef RSPAMD_LOCKED_FILE_HXX
#define RSPAMD_LOCKED_FILE_HXX
#pragma once

#include "contrib/expected/expected.hpp"
#include <string>
#include <sys/stat.h>

namespace rspamd::util {
/**
 * A simple RAII object to contain a file descriptor with an flock wrap
 * A file is unlocked and closed when not needed
 */
struct raii_locked_file final {
	~raii_locked_file();

	static auto open(const char *fname, int flags) -> tl::expected<raii_locked_file, std::string>;
	static auto create(const char *fname, int flags, int perms) -> tl::expected<raii_locked_file, std::string>;
	static auto create_temp(const char *fname, int flags, int perms) -> tl::expected<raii_locked_file, std::string>;

	auto get_fd() const -> int {
		return fd;
	}

	auto get_stat() const -> const struct stat& {
		return st;
	};

	raii_locked_file& operator=(raii_locked_file &&other) noexcept {
		std::swap(fd, other.fd);
		std::swap(temp, other.temp);
		std::swap(fname, other.fname);
		std::swap(st, other.st);

		return *this;
	}

	raii_locked_file(raii_locked_file &&other) noexcept {
		*this = std::move(other);
	}

	/* Do not allow copy/default ctor */
	const raii_locked_file& operator=(const raii_locked_file &other) = delete;
	raii_locked_file() = delete;
	raii_locked_file(const raii_locked_file &other) = delete;
private:
	int fd = -1;
	bool temp;
	std::string fname;
	struct stat st;

	explicit raii_locked_file(const char *_fname, int _fd, bool _temp) : fd(_fd), temp(_temp), fname(_fname) {}
};

/**
 * A mmap wrapper on top of a locked file
 */
struct raii_mmaped_locked_file final {
	~raii_mmaped_locked_file();
	static auto mmap_shared(raii_locked_file &&file, int flags) -> tl::expected<raii_mmaped_locked_file, std::string>;
	static auto mmap_shared(const char *fname, int open_flags, int mmap_flags) -> tl::expected<raii_mmaped_locked_file, std::string>;
	auto get_map() const -> void* {return map;}
	auto get_size() const -> std::size_t { return file.get_stat().st_size; }

	raii_mmaped_locked_file& operator=(raii_mmaped_locked_file &&other) noexcept {
		std::swap(map, other.map);
		file = std::move(other.file);

		return *this;
	}

	raii_mmaped_locked_file(raii_mmaped_locked_file &&other) noexcept;

	/* Do not allow copy/default ctor */
	const raii_mmaped_locked_file& operator=(const raii_mmaped_locked_file &other) = delete;
	raii_mmaped_locked_file() = delete;
	raii_mmaped_locked_file(const raii_mmaped_locked_file &other) = delete;
private:
	/* Is intended to be used with map_shared */
	explicit raii_mmaped_locked_file(raii_locked_file &&_file, void *_map);
	raii_locked_file file;
	void *map = nullptr;
};

/**
 * A helper to have a file to write that will be renamed to the
 * target file if successful or deleted in the case of failure
 */
struct raii_file_sink final {
	static auto create(const char *fname, int flags, int perms, const char *suffix = "new")
		-> tl::expected<raii_file_sink, std::string>;
	auto write_output() -> bool;
	~raii_file_sink();
	auto get_fd() const -> int
	{
		return file.get_fd();
	}

	raii_file_sink(raii_file_sink &&other) noexcept;
	/* Do not allow copy/default ctor */
	const raii_file_sink& operator=(const raii_file_sink &other) = delete;
	raii_file_sink() = delete;
	raii_file_sink(const raii_file_sink &other) = delete;
private:
	explicit raii_file_sink(raii_locked_file &&_file, const char *_output, std::string &&_tmp_fname);
	raii_locked_file file;
	std::string output_fname;
	std::string tmp_fname;
	bool success;
};

}

#endif //RSPAMD_LOCKED_FILE_HXX
