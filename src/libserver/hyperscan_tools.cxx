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

#include "config.h"

#ifdef WITH_HYPERSCAN
#include <filesystem>
#include "contrib/ankerl/unordered_dense.h"
#include "contrib/ankerl/svector.h"
#include "fmt/core.h"
#include "libutil/cxx/string.hxx"
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

#define HYPERSCAN_LOG_TAG "hsxxxx"

// Hyperscan does not provide any API to check validity of it's databases
// However, it is required for us to perform migrations properly without
// failing at `hs_alloc_scratch` phase or even `hs_scan` which is **way too late**
// Hence, we have to check hyperscan internal guts to prevent that situation...

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
#define msg_debug_hyperscan(...) rspamd_conditional_debug_fast(nullptr, nullptr,                                        \
															   rspamd_hyperscan_log_id, "hyperscan", HYPERSCAN_LOG_TAG, \
															   RSPAMD_LOG_FUNC,                                         \
															   __VA_ARGS__)
#define msg_debug_hyperscan_lambda(...) rspamd_conditional_debug_fast(nullptr, nullptr,                                        \
																	  rspamd_hyperscan_log_id, "hyperscan", HYPERSCAN_LOG_TAG, \
																	  log_func,                                                \
																	  __VA_ARGS__)

INIT_LOG_MODULE_PUBLIC(hyperscan)

namespace rspamd::util {

/*
 * A singleton class that is responsible for deletion of the outdated hyperscan files
 * One issue is that it must know about HS files in all workers, which is a problem
 * TODO: we need to export hyperscan caches from all workers to a single place where
 * we can clean them up (probably, to the main process)
 */
class hs_known_files_cache {
private:
	// These fields are filled when we add new known cache files
	ankerl::svector<sz::string, 4> cache_dirs;
	ankerl::svector<sz::string, 8> cache_extensions;
	ankerl::unordered_dense::set<sz::string> known_cached_files;
	bool loaded = false;

private:
	hs_known_files_cache() = default;

	virtual ~hs_known_files_cache()
	{
		// Cleanup cache dir
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

		auto dir = sz::string{fpath.parent_path().c_str()};
		auto ext = sz::string{fpath.extension().c_str()};

		if (std::find_if(cache_dirs.begin(), cache_dirs.end(),
						 [&](const auto &item) { return item == dir; }) == std::end(cache_dirs)) {
			cache_dirs.emplace_back(sz::string{dir});
		}
		if (std::find_if(cache_extensions.begin(), cache_extensions.end(),
						 [&](const auto &item) { return item == ext; }) == std::end(cache_extensions)) {
			cache_extensions.emplace_back(sz::string{ext});
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

		auto dir = sz::string{fpath.parent_path().c_str()};
		auto ext = sz::string{fpath.extension().c_str()};

		if (std::find_if(cache_dirs.begin(), cache_dirs.end(),
						 [&](const auto &item) { return item == dir; }) == std::end(cache_dirs)) {
			cache_dirs.emplace_back(dir);
		}
		if (std::find_if(cache_extensions.begin(), cache_extensions.end(),
						 [&](const auto &item) { return item == ext; }) == std::end(cache_extensions)) {
			cache_extensions.emplace_back(ext);
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

	auto cleanup_maybe() -> void
	{
		auto env_cleanup_disable = std::getenv("RSPAMD_NO_CLEANUP");
		/* We clean dir merely if we are running from the main process */
		if (rspamd_current_worker == nullptr && env_cleanup_disable == nullptr && loaded) {
			const auto *log_func = RSPAMD_LOG_FUNC;
			auto cleanup_dir = [&](sz::string_view dir) -> void {
				for (const auto &ext: cache_extensions) {
					glob_t globbuf;

					auto glob_pattern = fmt::format("{}{}*{}",
													dir, G_DIR_SEPARATOR_S, ext);
					msg_debug_hyperscan_lambda("perform glob for pattern: %s",
											   glob_pattern.c_str());
					memset(&globbuf, 0, sizeof(globbuf));

					if (glob(glob_pattern.c_str(), 0, nullptr, &globbuf) == 0) {
						for (auto i = 0; i < globbuf.gl_pathc; i++) {
							auto path = sz::string{globbuf.gl_pathv[i]};
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
 * This is a higher level representation of the cached hyperscan file
 */
struct hs_shared_database {
	hs_database_t *db = nullptr; /**< internal database (might be in a shared memory) */
	std::optional<raii_mmaped_file> maybe_map;
	sz::string cached_path;

	~hs_shared_database()
	{
		if (!maybe_map) {
			hs_free_database(db);
		}
		// Otherwise, handled by maybe_map dtor
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
static auto
hs_is_valid_database(void *raw, std::size_t len, sz::string_view fname) -> tl::expected<bool, sz::string>
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

#ifdef HS_DB_VERSION
	if (test.version != HS_DB_VERSION) {
		return tl::make_unexpected(fmt::format("cannot load hyperscan database from {}: invalid version: {} ({} expected)",
											   fname, test.version, HS_DB_VERSION));
	}
#endif

	return true;
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

	hs_cache.add_cached_file(map.get_file());
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
			auto unserialized_file = raii_locked_file::create(unserialized_fname.c_str(), O_CREAT | O_RDWR | O_EXCL,
															  00644)
										 .and_then([&](auto &&new_file_locked) -> tl::expected<raii_file, error> {
											 auto tmpfile_pattern = fmt::format("{}{}hsmp-XXXXXXXXXXXXXXXXXX",
																				cached_serialized.get_file().get_dir(), G_DIR_SEPARATOR);
											 auto tmpfile = raii_locked_file::mkstemp(tmpfile_pattern.data(), O_CREAT | O_RDWR | O_EXCL,
																					  00644);

											 if (!tmpfile) {
												 return tl::make_unexpected(tmpfile.error());
											 }
											 else {
												 auto &tmpfile_checked = tmpfile.value();
												 // Store owned string
												 auto tmpfile_name = sz::string{tmpfile_checked.get_name()};
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
													 return tl::make_unexpected(error{
														 fmt::format("cannot deserialize hyperscan database: {}", ret), ret});
												 }
												 else {
													 if (write(tmpfile_checked.get_fd(), buf, unserialized_size) == -1) {
														 free(buf);
														 return tl::make_unexpected(error{fmt::format("cannot write to {}: {}",
																									  tmpfile_name, ::strerror(errno)),
																						  errno, error_category::CRITICAL});
													 }
													 else {
														 free(buf);
														 /*
														 * Unlink target file before renaming to avoid
														 * race condition.
														 * So what we have is that `new_file_locked`
														 * will have flock on that file, so it will be
														 * replaced after unlink safely, and also unlocked.
														 */
														 (void) unlink(unserialized_fname.c_str());
														 if (rename(tmpfile_name.c_str(),
																	unserialized_fname.c_str()) == -1) {
															 if (errno != EEXIST) {
																 msg_info_hyperscan_lambda("cannot rename %s -> %s: %s",
																						   tmpfile_name.c_str(),
																						   unserialized_fname.c_str(),
																						   strerror(errno));
															 }
														 }
														 else {
															 /* Unlock file but mark it as immortal first to avoid deletion */
															 tmpfile_checked.make_immortal();
															 (void) tmpfile_checked.unlock();
														 }
													 }
												 }
												 /* Reopen in RO mode */
												 return raii_file::open(unserialized_fname.c_str(), O_RDONLY);
											 };
										 })
										 .or_else([&](auto unused) -> tl::expected<raii_file, error> {
											 // Cannot create file, so try to open it in RO mode
											 return raii_file::open(unserialized_fname.c_str(), O_RDONLY);
										 });

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
		/* Also notify main process */
		struct rspamd_srv_command notice_cmd;

		if (strlen(fname) >= sizeof(notice_cmd.cmd.hyperscan_cache_file.path)) {
			msg_err("internal error: length of the filename %d ('%s') is larger than control buffer path: %d",
					(int) strlen(fname), fname, (int) sizeof(notice_cmd.cmd.hyperscan_cache_file.path));
		}
		else {
			notice_cmd.type = RSPAMD_SRV_NOTICE_HYPERSCAN_CACHE;
			rspamd_strlcpy(notice_cmd.cmd.hyperscan_cache_file.path, fname, sizeof(notice_cmd.cmd.hyperscan_cache_file.path));
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

void rspamd_hyperscan_notice_loaded(void)
{
	rspamd::util::hs_known_files_cache::get().notice_loaded();
}

#endif// WITH_HYPERSCAN