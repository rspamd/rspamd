/*
 * Copyright 2024 Vsevolod Stakhov
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
#ifndef RSPAMD_FILE_UTIL_HXX
#define RSPAMD_FILE_UTIL_HXX
#pragma once

#include "config.h"
#include "contrib/expected/expected.hpp"
#include "libutil/cxx/error.hxx"
#include "libutil/cxx/string.hxx"
#include <sys/stat.h>

namespace rspamd::util {
/**
 * A simple RAII object to contain a move only file descriptor
 * A file is unlocked and closed when not needed
 */
struct raii_file {
public:
	virtual ~raii_file() noexcept;

	static auto open(const char *fname, int flags) -> tl::expected<raii_file, error>;
	static auto open(const sz::string &fname, int flags) -> tl::expected<raii_file, error>
	{
		return open(fname.c_str(), flags);
	};
	static auto create(const char *fname, int flags, int perms) -> tl::expected<raii_file, error>;
	static auto create(const sz::string &fname, int flags, int perms) -> tl::expected<raii_file, error>
	{
		return create(fname.c_str(), flags, perms);
	};

	static auto create_temp(const char *fname, int flags, int perms) -> tl::expected<raii_file, error>;
	static auto mkstemp(const char *pattern, int flags, int perms) -> tl::expected<raii_file, error>;

	auto get_fd() const -> int
	{
		return fd;
	}

	auto get_stat() const -> const struct stat &
	{
		return st;
	};

	auto get_size() const -> std::size_t
	{
		return st.st_size;
	};

	auto get_name() const -> std::string_view
	{
		return std::string_view{fname};
	}

	auto get_dir() const -> std::string_view
	{
		auto sep_pos = fname.rfind(G_DIR_SEPARATOR);

		if (sep_pos == std::string::npos) {
			return std::string_view{fname};
		}

		while (sep_pos >= 1 && fname[sep_pos - 1] == G_DIR_SEPARATOR) {
			sep_pos--;
		}

		return std::string_view{fname.c_str(), sep_pos + 1};
	}

	auto get_extension() const -> std::string_view
	{
		auto sep_pos = fname.rfind(G_DIR_SEPARATOR);

		if (sep_pos == std::string::npos) {
			sep_pos = 0;
		}

		auto filename = std::string_view{fname.c_str() + sep_pos};
		auto dot_pos = filename.find('.');

		if (dot_pos == std::string::npos) {
			return std::string_view{};
		}
		else {
			return std::string_view{filename.data() + dot_pos + 1, filename.size() - dot_pos - 1};
		}
	}

	raii_file &operator=(raii_file &&other) noexcept
	{
		std::swap(fd, other.fd);
		std::swap(temp, other.temp);
		std::swap(fname, other.fname);
		std::swap(st, other.st);

		return *this;
	}

	raii_file(raii_file &&other) noexcept
	{
		*this = std::move(other);
	}

	/**
	 * Prevent file from being deleted
	 * @return
	 */
	auto make_immortal() noexcept
	{
		temp = false;
	}

	/**
	 * Performs fstat on an opened file to refresh internal stat
	 * @return
	 */
	auto update_stat() noexcept -> bool;

	auto is_valid() noexcept -> bool
	{
		return fd != -1;
	}

	/* Do not allow copy/default ctor */
	const raii_file &operator=(const raii_file &other) = delete;
	raii_file() = delete;
	raii_file(const raii_file &other) = delete;

protected:
	int fd = -1;
	bool temp;
	std::string fname;
	struct stat st;

	explicit raii_file(const char *fname, int fd, bool temp);
};
/**
 * A simple RAII object to contain a file descriptor with an flock wrap
 * A file is unlocked and closed when not needed
 */
struct raii_locked_file final : public raii_file {
public:
	~raii_locked_file() noexcept override;

	static auto open(const char *fname, int flags) -> tl::expected<raii_locked_file, error>
	{
		auto locked = raii_file::open(fname, flags).and_then([]<class T>(T &&file) {
			return lock_raii_file(std::forward<T>(file));
		});

		return locked;
	}
	static auto create(const char *fname, int flags, int perms) -> tl::expected<raii_locked_file, error>
	{
		auto locked = raii_file::create(fname, flags, perms).and_then([]<class T>(T &&file) {
			return lock_raii_file(std::forward<T>(file));
		});

		return locked;
	}
	static auto create_temp(const char *fname, int flags, int perms) -> tl::expected<raii_locked_file, error>
	{
		auto locked = raii_file::create_temp(fname, flags, perms).and_then([]<class T>(T &&file) {
			return lock_raii_file(std::forward<T>(file));
		});

		return locked;
	}
	static auto mkstemp(const char *pattern, int flags, int perms) -> tl::expected<raii_locked_file, error>
	{
		auto locked = raii_file::mkstemp(pattern, flags, perms).and_then([]<class T>(T &&file) {
			return lock_raii_file(std::forward<T>(file));
		});

		return locked;
	}

	raii_locked_file &operator=(raii_locked_file &&other) noexcept
	{
		std::swap(fd, other.fd);
		std::swap(temp, other.temp);
		std::swap(fname, other.fname);
		std::swap(st, other.st);

		return *this;
	}

	/**
	 * Unlock a locked file and return back unlocked file transferring ownership.
	 * A locked file cannot be used after this method.
	 */
	auto unlock() -> raii_file;

	raii_locked_file(raii_locked_file &&other) noexcept
		: raii_file(static_cast<raii_file &&>(std::move(other)))
	{
	}
	/* Do not allow copy/default ctor */
	const raii_locked_file &operator=(const raii_locked_file &other) = delete;
	raii_locked_file() = delete;
	raii_locked_file(const raii_locked_file &other) = delete;

private:
	static auto lock_raii_file(raii_file &&unlocked) -> tl::expected<raii_locked_file, error>;
	raii_locked_file(raii_file &&other) noexcept
		: raii_file(std::move(other))
	{
	}
	explicit raii_locked_file(const char *fname, int fd, bool temp)
		: raii_file(fname, fd, temp)
	{
	}
};

/**
 * A mmap wrapper on top of a locked file
 */
struct raii_mmaped_file final {
	~raii_mmaped_file();
	static auto mmap_shared(raii_file &&file, int flags, std::int64_t offset = 0) -> tl::expected<raii_mmaped_file, error>;
	static auto mmap_shared(const char *fname, int open_flags, int mmap_flags, std::int64_t offset = 0) -> tl::expected<raii_mmaped_file, error>;
	// Returns a constant pointer to the underlying map
	auto get_map() const -> void *
	{
		return map;
	}
	auto get_file() const -> const raii_file &
	{
		return file;
	}
	// Passes the ownership of the mmaped memory to the callee
	auto steal_map() -> std::tuple<void *, std::size_t>
	{
		auto ret = std::make_tuple(this->map, map_size);
		this->map = nullptr;
		return ret;
	}

	auto get_size() const -> std::size_t
	{
		return file.get_stat().st_size;
	}

	raii_mmaped_file &operator=(raii_mmaped_file &&other) noexcept
	{
		std::swap(map, other.map);
		std::swap(map_size, other.map_size);
		file = std::move(other.file);

		return *this;
	}

	raii_mmaped_file(raii_mmaped_file &&other) noexcept;

	/* Do not allow copy/default ctor */
	const raii_mmaped_file &operator=(const raii_mmaped_file &other) = delete;
	raii_mmaped_file() = delete;
	raii_mmaped_file(const raii_mmaped_file &other) = delete;

private:
	/* Is intended to be used with map_shared */
	explicit raii_mmaped_file(raii_file &&_file, void *_map, std::size_t sz);
	raii_file file;
	void *map = nullptr;
	std::size_t map_size;
};

/**
 * A helper to have a file to write that will be renamed to the
 * target file if successful or deleted in the case of failure
 */
struct raii_file_sink final {
	static auto create(const char *fname, int flags, int perms, const char *suffix = "new")
		-> tl::expected<raii_file_sink, error>;
	auto write_output() -> bool;
	~raii_file_sink();
	auto get_fd() const -> int
	{
		return file.get_fd();
	}

	raii_file_sink(raii_file_sink &&other) noexcept;
	/* Do not allow copy/default ctor */
	const raii_file_sink &operator=(const raii_file_sink &other) = delete;
	raii_file_sink() = delete;
	raii_file_sink(const raii_file_sink &other) = delete;

private:
	explicit raii_file_sink(raii_locked_file &&_file, const char *_output, std::string &&_tmp_fname);
	raii_locked_file file;
	std::string output_fname;
	std::string tmp_fname;
	bool success;
};

}// namespace rspamd::util

#endif//RSPAMD_FILE_UTIL_HXX
