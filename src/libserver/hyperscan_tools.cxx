/*
 * Copyright 2025 Vsevolod Stakhov
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

#include "config.h"

#ifdef WITH_HYPERSCAN
#include <string>
#include <filesystem>
#include "contrib/ankerl/unordered_dense.h"
#include "contrib/ankerl/svector.h"
#include "contrib/fmt/include/fmt/base.h"
#include "libutil/cxx/file_util.hxx"
#include "libutil/cxx/error.hxx"
#include "hs.h"
#include "logger.h"
#include "worker_util.h"
#include "hyperscan_tools.h"

#include <glob.h>   /* for glob */
#include <unistd.h> /* for unlink */
#include <optional>
#include <cstdlib> /* for std::getenv */
#include "unix-std.h"
#include "rspamd_control.h"
#include "cryptobox.h"

#ifdef HS_MAJOR
#ifndef HS_VERSION_32BIT
#define HS_VERSION_32BIT ((HS_MAJOR << 24) | (HS_MINOR << 16) | (HS_PATCH << 8) | 0)
#endif
#endif// defined(HS_MAJOR)

#if !defined(HS_DB_VERSION) && defined(HS_VERSION_32BIT)
#define HS_DB_VERSION HS_VERSION_32BIT
#endif

#ifndef HS_DB_MAGIC
#define HS_DB_MAGIC (0xdbdbdbdbU)
#endif

#define msg_info_hyperscan(...) rspamd_default_log_function(G_LOG_LEVEL_INFO,               \
															"hyperscan", HYPERSCAN_LOG_TAG, \
															RSPAMD_LOG_FUNC,                \
															__VA_ARGS__)
#define msg_info_hyperscan_lambda(...) rspamd_default_log_function(G_LOG_LEVEL_INFO,               \
																   "hyperscan", HYPERSCAN_LOG_TAG, \
																   log_func,                       \
																   __VA_ARGS__)
#define msg_err_hyperscan(...) rspamd_default_log_function(G_LOG_LEVEL_CRITICAL,           \
														   "hyperscan", HYPERSCAN_LOG_TAG, \
														   RSPAMD_LOG_FUNC,                \
														   __VA_ARGS__)
#define msg_debug_hyperscan_lambda(...) rspamd_conditional_debug_fast(nullptr, nullptr,                                        \
																	  rspamd_hyperscan_log_id, "hyperscan", HYPERSCAN_LOG_TAG, \
																	  log_func,                                                \
																	  __VA_ARGS__)

INIT_LOG_MODULE_PUBLIC(hyperscan)

namespace rspamd::util {

class hs_known_files_cache {
private:
	// These fields are filled when we add new known cache files
	ankerl::svector<std::string, 4> cache_dirs;
	ankerl::svector<std::string, 8> cache_extensions;
	ankerl::unordered_dense::set<std::string> known_cached_files;
	bool loaded = false;

private:
	hs_known_files_cache() = default;

	virtual ~hs_known_files_cache()
	{
		cleanup_maybe();
	}

public:
	hs_known_files_cache(const hs_known_files_cache &) = delete;
	hs_known_files_cache(hs_known_files_cache &&) = delete;

	static auto get() -> hs_known_files_cache &
	{
		static hs_known_files_cache *singleton = nullptr;

		if (singleton == nullptr) {
			singleton = new hs_known_files_cache;
		}

		return *singleton;
	}

	void add_cached_file(const raii_file &file)
	{
		auto fpath = std::filesystem::path{file.get_name()};
		std::error_code ec;

		fpath = std::filesystem::canonical(fpath, ec);

		if (ec && ec.value() != 0) {
			msg_err_hyperscan("invalid path: \"%s\", error message: %s", fpath.c_str(), ec.message().c_str());
			return;
		}

		auto dir = fpath.parent_path();
		auto ext = fpath.extension();

		if (std::find_if(cache_dirs.begin(), cache_dirs.end(),
						 [&](const auto &item) { return item == dir; }) == std::end(cache_dirs)) {
			cache_dirs.emplace_back(std::string{dir});
		}
		if (std::find_if(cache_extensions.begin(), cache_extensions.end(),
						 [&](const auto &item) { return item == ext; }) == std::end(cache_extensions)) {
			cache_extensions.emplace_back(std::string{ext});
		}

		auto is_known = known_cached_files.insert(fpath.string());
		msg_debug_hyperscan("added %s hyperscan file: %s",
							is_known.second ? "new" : "already known",
							fpath.c_str());
	}

	void add_cached_file(const char *fname)
	{
		auto fpath = std::filesystem::path{fname};
		std::error_code ec;

		fpath = std::filesystem::canonical(fpath, ec);

		if (ec && ec.value() != 0) {
			msg_err_hyperscan("invalid path: \"%s\", error message: %s", fname, ec.message().c_str());
			return;
		}

		auto dir = fpath.parent_path();
		auto ext = fpath.extension();

		if (std::find_if(cache_dirs.begin(), cache_dirs.end(),
						 [&](const auto &item) { return item == dir; }) == std::end(cache_dirs)) {
			cache_dirs.emplace_back(dir.string());
		}
		if (std::find_if(cache_extensions.begin(), cache_extensions.end(),
						 [&](const auto &item) { return item == ext; }) == std::end(cache_extensions)) {
			cache_extensions.emplace_back(ext.string());
		}

		auto is_known = known_cached_files.insert(fpath.string());
		msg_debug_hyperscan("added %s hyperscan file: %s",
							is_known.second ? "new" : "already known",
							fpath.c_str());
	}

	void delete_cached_file(const char *fname)
	{
		auto fpath = std::filesystem::path{fname};
		std::error_code ec;

		fpath = std::filesystem::canonical(fpath, ec);

		if (ec && ec.value() != 0) {
			msg_err_hyperscan("invalid path to remove: \"%s\", error message: %s",
							  fname, ec.message().c_str());
			return;
		}

		if (fpath.empty()) {
			msg_err_hyperscan("attempt to remove an empty hyperscan file!");
			return;
		}

		if (unlink(fpath.c_str()) == -1) {
			msg_err_hyperscan("cannot remove hyperscan file %s: %s",
							  fpath.c_str(), strerror(errno));
		}
		else {
			msg_debug_hyperscan("removed hyperscan file %s", fpath.c_str());
		}

		known_cached_files.erase(fpath.string());
	}

	auto is_file_known(const char *fname) -> bool
	{
		auto fpath = std::filesystem::path{fname};
		std::error_code ec;

		fpath = std::filesystem::canonical(fpath, ec);

		if (ec && ec.value() != 0) {
			/* File doesn't exist or can't be canonicalized - not known */
			return false;
		}

		return known_cached_files.contains(fpath.string());
	}

	auto cleanup_maybe() -> void
	{
		auto env_cleanup_disable = std::getenv("RSPAMD_NO_CLEANUP");
		/* We clean dir merely if we are running from the main process */
		if (rspamd_current_worker == nullptr && env_cleanup_disable == nullptr && loaded) {
			const auto *log_func = RSPAMD_LOG_FUNC;
			auto cleanup_dir = [&](std::string_view dir) -> void {
				for (const auto &ext: cache_extensions) {
					glob_t globbuf;

					auto glob_pattern = fmt::format("{}{}*{}",
													dir, G_DIR_SEPARATOR_S, ext);
					msg_debug_hyperscan_lambda("perform glob for pattern: %s",
											   glob_pattern.c_str());
					memset(&globbuf, 0, sizeof(globbuf));

					if (glob(glob_pattern.c_str(), 0, nullptr, &globbuf) == 0) {
						for (auto i = 0; i < globbuf.gl_pathc; i++) {
							auto path = std::string{globbuf.gl_pathv[i]};
							std::size_t nsz;
							struct stat st;

							rspamd_normalize_path_inplace(path.data(), path.size(), &nsz);
							path.resize(nsz);

							if (stat(path.c_str(), &st) == -1) {
								msg_debug_hyperscan_lambda("cannot stat file %s: %s",
														   path.c_str(), strerror(errno));
								continue;
							}

							if (S_ISREG(st.st_mode)) {
								if (!known_cached_files.contains(path)) {
									msg_info_hyperscan_lambda("remove stale hyperscan file %s", path.c_str());
									unlink(path.c_str());
								}
								else {
									msg_debug_hyperscan_lambda("found known hyperscan file %s, size: %Hz",
															   path.c_str(), st.st_size);
								}
							}
						}
					}

					globfree(&globbuf);
				}
			};

			for (const auto &dir: cache_dirs) {
				msg_info_hyperscan("cleaning up directory %s", dir.c_str());
				cleanup_dir(dir);
			}

			cache_dirs.clear();
			cache_extensions.clear();
			known_cached_files.clear();
		}
		else if (rspamd_current_worker == nullptr && env_cleanup_disable != nullptr) {
			msg_info_hyperscan("disable hyperscan cleanup: env variable RSPAMD_NO_CLEANUP is set");
		}
		else if (!loaded) {
			msg_info_hyperscan("disable hyperscan cleanup: not loaded");
		}
	}

	auto notice_loaded() -> void
	{
		loaded = true;
	}
};


/**
 * Simple holder for FD-based mmap (no file path)
 */
struct fd_mmap_holder {
	void *map = nullptr;
	std::size_t size = 0;
	int fd = -1;

	fd_mmap_holder() = default;
	fd_mmap_holder(void *m, std::size_t s, int f)
		: map(m), size(s), fd(f)
	{
	}
	~fd_mmap_holder()
	{
		if (map && map != MAP_FAILED) {
			munmap(map, size);
		}
		if (fd >= 0) {
			close(fd);
		}
	}
	fd_mmap_holder(const fd_mmap_holder &) = delete;
	fd_mmap_holder &operator=(const fd_mmap_holder &) = delete;
	fd_mmap_holder(fd_mmap_holder &&other) noexcept
		: map(other.map), size(other.size), fd(other.fd)
	{
		other.map = nullptr;
		other.size = 0;
		other.fd = -1;
	}
	fd_mmap_holder &operator=(fd_mmap_holder &&other) noexcept
	{
		std::swap(map, other.map);
		std::swap(size, other.size);
		std::swap(fd, other.fd);
		return *this;
	}
};

/**
 * This is a higher level representation of the cached hyperscan file
 */
struct hs_shared_database {
	hs_database_t *db = nullptr; /**< internal database (might be in a shared memory) */
	std::optional<raii_mmaped_file> maybe_map;
	std::optional<fd_mmap_holder> maybe_fd_map; /**< for FD-based loading */
	std::string cached_path;

	~hs_shared_database()
	{
		if (!maybe_map && !maybe_fd_map) {
			hs_free_database(db);
		}
		// Otherwise, handled by maybe_map or maybe_fd_map dtor
	}

	explicit hs_shared_database(raii_mmaped_file &&map, hs_database_t *db)
		: db(db), maybe_map(std::move(map))
	{
		cached_path = maybe_map.value().get_file().get_name();
	}
	explicit hs_shared_database(hs_database_t *db, const char *fname)
		: db(db), maybe_map(std::nullopt)
	{
		if (fname) {
			cached_path = fname;
		}
		else {
			/* Likely a test case */
			cached_path = "";
		}
	}
	explicit hs_shared_database(hs_database_t *db, fd_mmap_holder &&fd_map)
		: db(db), maybe_fd_map(std::move(fd_map))
	{
		cached_path = "";
	}
	hs_shared_database(const hs_shared_database &other) = delete;
	hs_shared_database() = default;
	hs_shared_database(hs_shared_database &&other) noexcept
	{
		*this = std::move(other);
	}
	hs_shared_database &operator=(hs_shared_database &&other) noexcept
	{
		std::swap(db, other.db);
		std::swap(maybe_map, other.maybe_map);
		std::swap(maybe_fd_map, other.maybe_fd_map);
		return *this;
	}
};

struct real_hs_db {
	std::uint32_t magic;
	std::uint32_t version;
	std::uint32_t length;
	std::uint64_t platform;
	std::uint32_t crc32;
};

/**
 * Get the runtime version of Hyperscan library in 32-bit format
 * This is important because the .so version might differ from headers version
 */
static auto
hs_get_runtime_db_version() -> std::uint32_t
{
	static std::uint32_t cached_version = 0;

	if (cached_version == 0) {
		const char *version_str = hs_version();
		unsigned int major = 0, minor = 0, patch = 0;

		// Parse version string like "5.4.0"
		if (sscanf(version_str, "%u.%u.%u", &major, &minor, &patch) == 3) {
			// Format: (major << 24) | (minor << 16) | (patch << 8) | 0
			cached_version = (major << 24) | (minor << 16) | (patch << 8);
			msg_debug_hyperscan("detected hyperscan runtime version: %s (0x%08xd)",
								version_str, cached_version);
		}
		else {
			msg_err_hyperscan("cannot parse hyperscan version string: %s", version_str);
			// Fallback to compile-time version if available
#ifdef HS_DB_VERSION
			cached_version = HS_DB_VERSION;
			msg_debug_hyperscan("using compile-time hyperscan version: 0x%08xd", cached_version);
#else
			cached_version = 0;
#endif
		}
	}

	return cached_version;
}

static auto
hs_is_valid_database(void *raw, std::size_t len, std::string_view fname) -> tl::expected<bool, std::string>
{
	if (len < sizeof(real_hs_db)) {
		return tl::make_unexpected(fmt::format("cannot load hyperscan database from {}: too short", fname));
	}

	static real_hs_db test;

	memcpy(&test, raw, sizeof(test));

	if (test.magic != HS_DB_MAGIC) {
		return tl::make_unexpected(fmt::format("cannot load hyperscan database from {}: invalid magic: {} ({} expected)",
											   fname, test.magic, HS_DB_MAGIC));
	}

	// Use runtime version instead of compile-time version
	auto runtime_version = hs_get_runtime_db_version();
	if (runtime_version != 0 && test.version != runtime_version) {
		return tl::make_unexpected(fmt::format("cannot load hyperscan database from {}: invalid version: 0x{:08x} (0x{:08x} expected)",
											   fname, test.version, runtime_version));
	}

	return true;
}

/**
 * Get platform identifier string for hyperscan cache keys
 * Format: hs{major}{minor}_{platform}_{features}_{hash8}
 * Example: hs54_haswell_avx2_abc12345
 */
static auto
hs_get_platform_id_impl() -> std::string
{
	hs_platform_info_t plt;
	if (hs_populate_platform(&plt) != HS_SUCCESS) {
		return "hs_unknown";
	}

	// Parse version string to get major.minor
	const char *version_str = hs_version();
	unsigned int major = 0, minor = 0;
	sscanf(version_str, "%u.%u", &major, &minor);

	// Determine platform name
	const char *platform_name = "generic";
	switch (plt.tune) {
	case HS_TUNE_FAMILY_HSW:
		platform_name = "haswell";
		break;
	case HS_TUNE_FAMILY_SNB:
		platform_name = "sandy";
		break;
	case HS_TUNE_FAMILY_BDW:
		platform_name = "broadwell";
		break;
	case HS_TUNE_FAMILY_IVB:
		platform_name = "ivy";
		break;
	default:
		break;
	}

	// Build features string
	std::string features;
	if (plt.cpu_features & HS_CPU_FEATURES_AVX2) {
		features = "avx2";
	}
	else if (plt.cpu_features & HS_CPU_FEATURES_AVX512) {
		features = "avx512";
	}
	else {
		features = "base";
	}

	// Create hash of platform info for uniqueness
	unsigned char hash_out[rspamd_cryptobox_HASHBYTES];
	rspamd_cryptobox_hash_state_t hash_state;
	rspamd_cryptobox_hash_init(&hash_state, nullptr, 0);
	rspamd_cryptobox_hash_update(&hash_state, reinterpret_cast<const unsigned char *>(version_str), strlen(version_str));
	rspamd_cryptobox_hash_update(&hash_state, reinterpret_cast<const unsigned char *>(&plt), sizeof(plt));
	rspamd_cryptobox_hash_final(&hash_state, hash_out);

	// Format: hs{major}{minor}_{platform}_{features}_{hash8}
	return fmt::format("hs{}{}_{}_{}_{:02x}{:02x}{:02x}{:02x}",
					   major, minor, platform_name, features,
					   hash_out[0], hash_out[1], hash_out[2], hash_out[3]);
}

static auto
hs_shared_from_unserialized(hs_known_files_cache &hs_cache, raii_mmaped_file &&map) -> tl::expected<hs_shared_database, error>
{
	auto ptr = map.get_map();
	auto db = (hs_database_t *) ptr;

	auto is_valid = hs_is_valid_database(map.get_map(), map.get_size(), map.get_file().get_name());
	if (!is_valid) {
		return tl::make_unexpected(error{is_valid.error(), -1, error_category::IMPORTANT});
	}

	/* Use rspamd_hyperscan_notice_known() to both add to local cache AND notify main process
	 * This ensures .unser files are known to main and won't be deleted during cleanup */
	rspamd_hyperscan_notice_known(map.get_file().get_name().data());
	return tl::expected<hs_shared_database, error>{tl::in_place, std::move(map), db};
}

static auto
hs_shared_from_serialized(hs_known_files_cache &hs_cache, raii_mmaped_file &&map, std::int64_t offset) -> tl::expected<hs_shared_database, error>
{
	hs_database_t *target = nullptr;

	if (auto ret = hs_deserialize_database((const char *) map.get_map() + offset,
										   map.get_size() - offset, &target);
		ret != HS_SUCCESS) {
		return tl::make_unexpected(error{"cannot deserialize database", ret});
	}

	hs_cache.add_cached_file(map.get_file());
	return tl::expected<hs_shared_database, error>{tl::in_place, target, map.get_file().get_name().data()};
}

#if defined(HS_MAJOR) && defined(HS_MINOR) && HS_MAJOR >= 5 && HS_MINOR >= 4
/**
 * Helper function to create unserialized hyperscan database file from serialized data
 * This function handles the entire process of creating a temporary file, deserializing
 * the database into it, and atomically replacing the target file.
 */
template<typename T>
static auto
create_unserialized_file(const char *unserialized_fname, T &&cached_serialized, std::int64_t offset) -> tl::expected<raii_file, error>
{
	const auto *log_func = RSPAMD_LOG_FUNC;
	return raii_locked_file::create(unserialized_fname, O_CREAT | O_RDWR | O_EXCL, 00644)
		.and_then([&](auto &&new_file_locked) -> tl::expected<raii_file, error> {
			auto tmpfile_pattern = fmt::format("{}{}hsmp-XXXXXXXXXXXXXXXXXX",
											   cached_serialized.get_file().get_dir(), G_DIR_SEPARATOR);
			auto tmpfile = raii_locked_file::mkstemp(tmpfile_pattern.data(), O_CREAT | O_RDWR | O_EXCL, 00644);

			if (!tmpfile) {
				return tl::make_unexpected(tmpfile.error());
			}

			auto &tmpfile_checked = tmpfile.value();
			auto tmpfile_name = std::string{tmpfile_checked.get_name()};
			std::size_t unserialized_size;

			if (auto ret = hs_serialized_database_size(((const char *) cached_serialized.get_map()) + offset,
													   cached_serialized.get_size() - offset, &unserialized_size);
				ret != HS_SUCCESS) {
				return tl::make_unexpected(error{
					fmt::format("cannot get unserialized database size: {}", ret),
					EINVAL,
					error_category::IMPORTANT});
			}

			msg_debug_hyperscan_lambda("multipattern: create new database in %s; %Hz size",
									   tmpfile_name.c_str(), unserialized_size);

			void *buf;
#ifdef HAVE_GETPAGESIZE
			auto page_size = getpagesize();
#else
			auto page_size = sysconf(_SC_PAGESIZE);
#endif
			if (page_size == -1) {
				page_size = 4096;
			}
			auto errcode = posix_memalign(&buf, page_size, unserialized_size);
			if (errcode != 0 || buf == nullptr) {
				return tl::make_unexpected(error{"Cannot allocate memory",
												 errno, error_category::CRITICAL});
			}

			if (auto ret = hs_deserialize_database_at(((const char *) cached_serialized.get_map()) + offset,
													  cached_serialized.get_size() - offset, (hs_database_t *) buf);
				ret != HS_SUCCESS) {
				free(buf);
				return tl::make_unexpected(error{
					fmt::format("cannot deserialize hyperscan database: {}", ret), ret});
			}

			if (write(tmpfile_checked.get_fd(), buf, unserialized_size) == -1) {
				free(buf);
				return tl::make_unexpected(error{fmt::format("cannot write to {}: {}",
															 tmpfile_name, ::strerror(errno)),
												 errno, error_category::CRITICAL});
			}

			free(buf);
			/*
			 * Unlink target file before renaming to avoid race condition.
			 * new_file_locked will have flock on that file, so it will be
			 * replaced after unlink safely, and also unlocked.
			 */
			(void) unlink(unserialized_fname);
			if (rename(tmpfile_name.c_str(), unserialized_fname) == -1) {
				if (errno != EEXIST) {
					msg_info_hyperscan_lambda("cannot rename %s -> %s: %s",
											  tmpfile_name.c_str(),
											  unserialized_fname,
											  strerror(errno));
				}
			}
			else {
				/* Unlock file but mark it as immortal first to avoid deletion */
				tmpfile_checked.make_immortal();
				(void) tmpfile_checked.unlock();
			}

			/* Reopen in RO mode */
			return raii_file::open(unserialized_fname, O_RDONLY);
		})
		.or_else([&](auto unused) -> tl::expected<raii_file, error> {
			// Cannot create file, so try to open it in RO mode
			return raii_file::open(unserialized_fname, O_RDONLY);
		});
}
#endif

auto load_cached_hs_file(const char *fname, std::int64_t offset = 0) -> tl::expected<hs_shared_database, error>
{
	auto &hs_cache = hs_known_files_cache::get();
	const auto *log_func = RSPAMD_LOG_FUNC;

	return raii_mmaped_file::mmap_shared(fname, O_RDONLY, PROT_READ, 0)
		.and_then([&]<class T>(T &&cached_serialized) -> tl::expected<hs_shared_database, error> {
			if (cached_serialized.get_size() <= offset) {
				return tl::make_unexpected(error{"Invalid offset", EINVAL, error_category::CRITICAL});
			}
#if defined(HS_MAJOR) && defined(HS_MINOR) && HS_MAJOR >= 5 && HS_MINOR >= 4
			auto unserialized_fname = fmt::format("{}.unser", fname);
			auto unserialized_file = create_unserialized_file(unserialized_fname.c_str(), std::forward<T>(cached_serialized), offset);

			tl::expected<hs_shared_database, error> ret;

			if (unserialized_file.has_value()) {

				auto &unserialized_checked = unserialized_file.value();

				if (unserialized_checked.get_size() == 0) {
					/*
					 * This is a case when we have a file that is currently
					 * being created by another process.
					 * We cannot use it!
					 */
					ret = hs_shared_from_serialized(hs_cache, std::forward<T>(cached_serialized), offset);
				}
				else {
					ret = raii_mmaped_file::mmap_shared(std::move(unserialized_checked), PROT_READ)
							  .and_then([&]<class U>(U &&mmapped_unserialized) -> auto {
								  return hs_shared_from_unserialized(hs_cache, std::forward<U>(mmapped_unserialized));
							  })
							  .or_else([&](const error &err) -> tl::expected<hs_shared_database, error> {
								  // If validation failed (e.g., version mismatch), try to recreate the file
								  msg_info_hyperscan_lambda("unserialized hyperscan file %s is invalid (%s), attempting to recreate",
															unserialized_fname.c_str(), err.error_message.data());

								  // Delete the invalid file
								  if (unlink(unserialized_fname.c_str()) == -1) {
									  msg_debug_hyperscan_lambda("cannot unlink invalid unserialized file %s: %s",
																 unserialized_fname.c_str(), strerror(errno));
								  }

								  // Try to create it again
								  auto recreated_file = create_unserialized_file(unserialized_fname.c_str(),
																				 std::forward<T>(cached_serialized), offset);

								  if (recreated_file.has_value() && recreated_file.value().get_size() > 0) {
									  return raii_mmaped_file::mmap_shared(std::move(recreated_file.value()), PROT_READ)
										  .and_then([&]<class V>(V &&mmapped_recreated) -> auto {
											  return hs_shared_from_unserialized(hs_cache, std::forward<V>(mmapped_recreated));
										  })
										  .or_else([&](const error &recreate_err) -> tl::expected<hs_shared_database, error> {
											  // If recreation also failed, fall back to serialized version
											  msg_info_hyperscan_lambda("failed to recreate unserialized file, using serialized version: %s",
																		recreate_err.error_message.data());
											  return hs_shared_from_serialized(hs_cache, std::forward<T>(cached_serialized), offset);
										  });
								  }

								  // If we couldn't recreate, fall back to serialized version
								  msg_debug_hyperscan_lambda("falling back to serialized version");
								  return hs_shared_from_serialized(hs_cache, std::forward<T>(cached_serialized), offset);
							  });
				}
			}
			else {
				ret = hs_shared_from_serialized(hs_cache, std::forward<T>(cached_serialized), offset);
			}
#else // defined(HS_MAJOR) && defined(HS_MINOR) && HS_MAJOR >= 5 && HS_MINOR >= 4
			auto ret = hs_shared_from_serialized(hs_cache, std::forward<T>(cached_serialized), offset);
#endif// defined(HS_MAJOR) && defined(HS_MINOR) && HS_MAJOR >= 5 && HS_MINOR >= 4 \
	// Add serialized file to cache merely if we have successfully loaded the actual db
			if (ret.has_value()) {
				hs_cache.add_cached_file(cached_serialized.get_file());
			}
			return ret;
		});
}
}// namespace rspamd::util

/* C API */

#define CXX_DB_FROM_C(obj) (reinterpret_cast<rspamd::util::hs_shared_database *>(obj))
#define C_DB_FROM_CXX(obj) (reinterpret_cast<rspamd_hyperscan_t *>(obj))

rspamd_hyperscan_t *
rspamd_hyperscan_maybe_load(const char *filename, goffset offset)
{
	auto maybe_db = rspamd::util::load_cached_hs_file(filename, offset);

	if (maybe_db.has_value()) {
		auto *ndb = new rspamd::util::hs_shared_database;
		*ndb = std::move(maybe_db.value());
		return C_DB_FROM_CXX(ndb);
	}
	else {
		auto error = maybe_db.error();

		switch (error.category) {
		case rspamd::util::error_category::CRITICAL:
			msg_err_hyperscan("critical error when trying to load cached hyperscan: %s",
							  error.error_message.data());
			break;
		case rspamd::util::error_category::IMPORTANT:
			msg_info_hyperscan("error when trying to load cached hyperscan: %s",
							   error.error_message.data());
			break;
		default:
			msg_debug_hyperscan("error when trying to load cached hyperscan: %s",
								error.error_message.data());
			break;
		}
	}

	return nullptr;
}

hs_database_t *
rspamd_hyperscan_get_database(rspamd_hyperscan_t *db)
{
	auto *real_db = CXX_DB_FROM_C(db);
	return real_db->db;
}

rspamd_hyperscan_t *
rspamd_hyperscan_from_raw_db(hs_database_t *db, const char *fname)
{
	auto *ndb = new rspamd::util::hs_shared_database{db, fname};

	return C_DB_FROM_CXX(ndb);
}

void rspamd_hyperscan_free(rspamd_hyperscan_t *db, bool invalid)
{
	auto *real_db = CXX_DB_FROM_C(db);

	if (invalid && !real_db->cached_path.empty()) {
		rspamd::util::hs_known_files_cache::get().delete_cached_file(real_db->cached_path.c_str());
	}
	delete real_db;
}

void rspamd_hyperscan_notice_known(const char *fname)
{
	rspamd::util::hs_known_files_cache::get().add_cached_file(fname);

	if (rspamd_current_worker != nullptr) {
		/* Also notify main process - send only the basename */
		struct rspamd_srv_command notice_cmd;
		const char *basename = strrchr(fname, '/');

		if (basename != nullptr) {
			basename++; /* Skip the '/' */
		}
		else {
			basename = fname; /* No '/' found, use the whole string */
		}

		if (strlen(basename) >= sizeof(notice_cmd.cmd.hyperscan_cache_file.filename)) {
			msg_err("internal error: length of the filename %d ('%s') is larger than control buffer: %d",
					(int) strlen(basename), basename, (int) sizeof(notice_cmd.cmd.hyperscan_cache_file.filename));
		}
		else {
			notice_cmd.type = RSPAMD_SRV_NOTICE_HYPERSCAN_CACHE;
			rspamd_strlcpy(notice_cmd.cmd.hyperscan_cache_file.filename, basename,
						   sizeof(notice_cmd.cmd.hyperscan_cache_file.filename));
			rspamd_srv_send_command(rspamd_current_worker,
									rspamd_current_worker->srv->event_loop, &notice_cmd, -1,
									nullptr,
									nullptr);
		}
	}
}

void rspamd_hyperscan_cleanup_maybe(void)
{
	rspamd::util::hs_known_files_cache::get().cleanup_maybe();
}

gboolean rspamd_hyperscan_is_file_known(const char *fname)
{
	return rspamd::util::hs_known_files_cache::get().is_file_known(fname);
}

void rspamd_hyperscan_notice_loaded(void)
{
	rspamd::util::hs_known_files_cache::get().notice_loaded();
}

const char *rspamd_hyperscan_get_platform_id(void)
{
	static std::string cached_platform_id;

	if (cached_platform_id.empty()) {
		cached_platform_id = rspamd::util::hs_get_platform_id_impl();
	}

	return cached_platform_id.c_str();
}

rspamd_hyperscan_t *rspamd_hyperscan_from_fd(int fd, gsize size)
{
	if (fd < 0 || size == 0) {
		msg_err_hyperscan("invalid fd (%d) or size (%z) for hyperscan database", fd, size);
		return nullptr;
	}

	void *map = mmap(nullptr, size, PROT_READ, MAP_SHARED, fd, 0);
	if (map == MAP_FAILED) {
		msg_err_hyperscan("cannot mmap fd %d: %s", fd, strerror(errno));
		return nullptr;
	}

	auto is_valid = rspamd::util::hs_is_valid_database(map, size, "fd");
	if (!is_valid) {
		msg_err_hyperscan("invalid hyperscan database from fd: %s", is_valid.error().c_str());
		munmap(map, size);
		return nullptr;
	}

	auto *db = reinterpret_cast<hs_database_t *>(map);
	// Create fd_mmap_holder to manage the mapping lifetime
	// Note: we dup() the fd so the holder owns its own copy
	int owned_fd = dup(fd);
	if (owned_fd == -1) {
		msg_err_hyperscan("cannot dup fd %d: %s", fd, strerror(errno));
		munmap(map, size);
		return nullptr;
	}
	rspamd::util::fd_mmap_holder holder{map, size, owned_fd};
	auto *ndb = new rspamd::util::hs_shared_database{db, std::move(holder)};

	msg_info_hyperscan("loaded hyperscan database from fd %d, size %z", fd, size);
	return C_DB_FROM_CXX(ndb);
}

gboolean rspamd_hyperscan_create_shared_unser(const char *serialized_data,
											  gsize serialized_size,
											  int *out_fd,
											  gsize *out_size)
{
	if (!serialized_data || serialized_size == 0 || !out_fd || !out_size) {
		return FALSE;
	}

	std::size_t unserialized_size = 0;
	if (hs_serialized_database_size(serialized_data, serialized_size, &unserialized_size) != HS_SUCCESS) {
		msg_err_hyperscan("cannot determine unserialized database size");
		return FALSE;
	}

	// Create temp file
	char tmppath[] = "/tmp/rspamd_hs_XXXXXX";
	int fd = mkstemp(tmppath);
	if (fd == -1) {
		msg_err_hyperscan("cannot create temp file: %s", strerror(errno));
		return FALSE;
	}

	// Unlink immediately - file stays open via FD
	if (unlink(tmppath) == -1) {
		msg_err_hyperscan("cannot unlink temp file %s: %s", tmppath, strerror(errno));
		close(fd);
		return FALSE;
	}

	// Extend file to required size
	if (ftruncate(fd, unserialized_size) == -1) {
		msg_err_hyperscan("cannot ftruncate temp file: %s", strerror(errno));
		close(fd);
		return FALSE;
	}

	void *map = mmap(nullptr, unserialized_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (map == MAP_FAILED) {
		msg_err_hyperscan("cannot mmap temp file: %s", strerror(errno));
		close(fd);
		return FALSE;
	}

	if (hs_deserialize_database_at(serialized_data, serialized_size, reinterpret_cast<hs_database_t *>(map)) != HS_SUCCESS) {
		msg_err_hyperscan("cannot deserialize database into shared memory");
		munmap(map, unserialized_size);
		close(fd);
		return FALSE;
	}

	if (mprotect(map, unserialized_size, PROT_READ) == -1) {
		msg_err_hyperscan("cannot mprotect shared memory: %s", strerror(errno));
	}

	munmap(map, unserialized_size);

	*out_fd = fd;
	*out_size = unserialized_size;

	msg_info_hyperscan("created shared hyperscan database: serialized %z -> unserialized %z bytes",
					   serialized_size, unserialized_size);

	return TRUE;
}
static const unsigned char rspamd_hs_magic[] = {'r', 's', 'h', 's', 'r', 'e', '1', '2'};
#define RSPAMD_HS_MAGIC_LEN (sizeof(rspamd_hs_magic))

const unsigned char *
rspamd_hyperscan_get_magic(gsize *len)
{
	if (len) {
		*len = RSPAMD_HS_MAGIC_LEN;
	}
	return rspamd_hs_magic;
}

gboolean rspamd_hyperscan_serialize_with_header(hs_database_t *db,
												const unsigned int *ids,
												const unsigned int *flags,
												unsigned int n,
												char **out_data,
												gsize *out_len)
{
	if (!db || !out_data || !out_len) {
		return FALSE;
	}

	/* Serialize the database - hyperscan allocates the buffer */
	char *ser_bytes = nullptr;
	std::size_t ser_size = 0;
	if (hs_serialize_database(db, &ser_bytes, &ser_size) != HS_SUCCESS) {
		msg_err_hyperscan("failed to serialize database");
		return FALSE;
	}

	/* Get platform info */
	hs_platform_info_t plt;
	if (hs_populate_platform(&plt) != HS_SUCCESS) {
		g_free(ser_bytes);
		msg_err_hyperscan("failed to get platform info");
		return FALSE;
	}

	/* Calculate header size */
	std::size_t header_size = RSPAMD_HS_MAGIC_LEN +
							  sizeof(plt) +
							  sizeof(n) +
							  (n > 0 ? sizeof(unsigned int) * n * 2 : 0) +
							  sizeof(uint64_t); /* CRC */

	std::size_t total_size = header_size + ser_size;

	/* Allocate buffer */
	char *buf = static_cast<char *>(g_malloc(total_size));
	char *p = buf;

	/* Magic */
	memcpy(p, rspamd_hs_magic, RSPAMD_HS_MAGIC_LEN);
	p += RSPAMD_HS_MAGIC_LEN;

	/* Platform */
	memcpy(p, &plt, sizeof(plt));
	p += sizeof(plt);

	/* Count */
	memcpy(p, &n, sizeof(n));
	p += sizeof(n);

	/* IDs and flags - remember positions for CRC calculation */
	char *ids_start = p;
	if (n > 0 && ids && flags) {
		memcpy(p, ids, sizeof(unsigned int) * n);
		p += sizeof(unsigned int) * n;
		memcpy(p, flags, sizeof(unsigned int) * n);
		p += sizeof(unsigned int) * n;
	}
	else if (n > 0) {
		memset(p, 0, sizeof(unsigned int) * n * 2);
		p += sizeof(unsigned int) * n * 2;
	}

	/* CRC over IDs + flags + HS blob (compatible with re_cache.c format) */
	rspamd_cryptobox_fast_hash_state_t crc_st;
	rspamd_cryptobox_fast_hash_init(&crc_st, 0xdeadbabe);
	if (n > 0) {
		/* IDs */
		rspamd_cryptobox_fast_hash_update(&crc_st, ids_start, sizeof(unsigned int) * n);
		/* Flags */
		rspamd_cryptobox_fast_hash_update(&crc_st, ids_start + sizeof(unsigned int) * n,
										  sizeof(unsigned int) * n);
	}
	/* HS database */
	rspamd_cryptobox_fast_hash_update(&crc_st, ser_bytes, ser_size);
	uint64_t crc = rspamd_cryptobox_fast_hash_final(&crc_st);

	memcpy(p, &crc, sizeof(crc));
	p += sizeof(crc);

	/* Copy serialized database */
	memcpy(p, ser_bytes, ser_size);
	g_free(ser_bytes);

	*out_data = buf;
	*out_len = total_size;

	return TRUE;
}

static GQuark rspamd_hyperscan_quark(void)
{
	return g_quark_from_static_string("hyperscan");
}

gboolean rspamd_hyperscan_validate_header(const char *data,
										  gsize len,
										  GError **err)
{
	if (len < RSPAMD_HS_MAGIC_LEN) {
		g_set_error(err, rspamd_hyperscan_quark(), EINVAL, "data too small");
		return FALSE;
	}

	/* Check magic */
	if (memcmp(data, rspamd_hs_magic, RSPAMD_HS_MAGIC_LEN) != 0) {
		g_set_error(err, rspamd_hyperscan_quark(), EINVAL, "invalid magic");
		return FALSE;
	}

	const char *p = data + RSPAMD_HS_MAGIC_LEN;
	const char *end = data + len;

	/* Check platform */
	if (static_cast<std::size_t>(end - p) < sizeof(hs_platform_info_t)) {
		g_set_error(err, rspamd_hyperscan_quark(), EINVAL, "truncated platform info");
		return FALSE;
	}

	hs_platform_info_t stored_plt;
	memcpy(&stored_plt, p, sizeof(stored_plt));
	p += sizeof(stored_plt);

	hs_platform_info_t cur_plt;
	if (hs_populate_platform(&cur_plt) != HS_SUCCESS) {
		g_set_error(err, rspamd_hyperscan_quark(), EINVAL, "cannot get current platform");
		return FALSE;
	}

	if (stored_plt.tune != cur_plt.tune) {
		g_set_error(err, rspamd_hyperscan_quark(), EINVAL, "platform mismatch");
		return FALSE;
	}

	/* Read count */
	if (static_cast<std::size_t>(end - p) < sizeof(unsigned int)) {
		g_set_error(err, rspamd_hyperscan_quark(), EINVAL, "truncated count");
		return FALSE;
	}

	unsigned int n;
	memcpy(&n, p, sizeof(n));
	p += sizeof(n);

	/* Remember start of IDs for CRC calculation */
	const char *ids_start = p;
	std::size_t arrays_size = (n > 0) ? sizeof(unsigned int) * n * 2 : 0;
	if (static_cast<std::size_t>(end - p) < arrays_size + sizeof(uint64_t)) {
		g_set_error(err, rspamd_hyperscan_quark(), EINVAL, "truncated arrays or CRC");
		return FALSE;
	}

	p += arrays_size;

	/* Verify CRC (over IDs + flags + HS blob, compatible with re_cache.c) */
	uint64_t stored_crc;
	memcpy(&stored_crc, p, sizeof(stored_crc));
	p += sizeof(stored_crc);

	const char *hs_blob = p;
	std::size_t hs_len = end - p;

	rspamd_cryptobox_fast_hash_state_t crc_st;
	rspamd_cryptobox_fast_hash_init(&crc_st, 0xdeadbabe);
	if (n > 0) {
		/* IDs */
		rspamd_cryptobox_fast_hash_update(&crc_st, ids_start, sizeof(unsigned int) * n);
		/* Flags */
		rspamd_cryptobox_fast_hash_update(&crc_st, ids_start + sizeof(unsigned int) * n,
										  sizeof(unsigned int) * n);
	}
	/* HS database */
	rspamd_cryptobox_fast_hash_update(&crc_st, hs_blob, hs_len);
	uint64_t calc_crc = rspamd_cryptobox_fast_hash_final(&crc_st);

	if (stored_crc != calc_crc) {
		g_set_error(err, rspamd_hyperscan_quark(), EINVAL, "CRC mismatch");
		return FALSE;
	}

	return TRUE;
}

rspamd_hyperscan_t *rspamd_hyperscan_load_from_header(const char *data,
													  gsize len,
													  GError **err)
{
	if (!rspamd_hyperscan_validate_header(data, len, err)) {
		return nullptr;
	}

	/* Skip to HS blob */
	const char *p = data + RSPAMD_HS_MAGIC_LEN + sizeof(hs_platform_info_t);
	unsigned int n;
	memcpy(&n, p, sizeof(n));
	p += sizeof(n);

	/* Skip IDs and flags */
	p += (n > 0) ? sizeof(unsigned int) * n * 2 : 0;
	/* Skip CRC */
	p += sizeof(uint64_t);

	std::size_t hs_len = len - (p - data);

	hs_database_t *db = nullptr;
	if (hs_deserialize_database(p, hs_len, &db) != HS_SUCCESS) {
		g_set_error(err, rspamd_hyperscan_quark(), EINVAL, "deserialize failed");
		return nullptr;
	}

	auto *ndb = new rspamd::util::hs_shared_database{db, nullptr};
	return C_DB_FROM_CXX(ndb);
}

#endif// WITH_HYPERSCAN