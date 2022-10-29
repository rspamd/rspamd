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
#include "config.h"

#ifdef WITH_HYPERSCAN
#include <string>
#include "contrib/ankerl/unordered_dense.h"
#include "contrib/ankerl/svector.h"
#include "fmt/core.h"
#include "libutil/cxx/file_util.hxx"
#include "libutil/cxx/error.hxx"
#include "hs.h"
#include "logger.h"
#include "worker_util.h"
#include "hyperscan_tools.h"

#include <glob.h> /* for glob */
#include <unistd.h> /* for unlink */
#include <optional>
#include "unix-std.h"
#include "rspamd_control.h"

#define HYPERSCAN_LOG_TAG "hsxxxx"

#define msg_info_hyperscan(...)   rspamd_default_log_function (G_LOG_LEVEL_INFO, \
        "hyperscan", HYPERSCAN_LOG_TAG, \
        RSPAMD_LOG_FUNC, \
        __VA_ARGS__)
#define msg_info_hyperscan_lambda(...)   rspamd_default_log_function (G_LOG_LEVEL_INFO, \
        "hyperscan", HYPERSCAN_LOG_TAG, \
        log_func, \
        __VA_ARGS__)
#define msg_err_hyperscan(...)   rspamd_default_log_function (G_LOG_LEVEL_CRITICAL, \
        "hyperscan", HYPERSCAN_LOG_TAG, \
        RSPAMD_LOG_FUNC, \
        __VA_ARGS__)
#define msg_debug_hyperscan(...)  rspamd_conditional_debug_fast (nullptr, nullptr, \
        rspamd_hyperscan_log_id, "hyperscan", HYPERSCAN_LOG_TAG, \
        RSPAMD_LOG_FUNC, \
        __VA_ARGS__)
#define msg_debug_hyperscan_lambda(...) rspamd_conditional_debug_fast (nullptr, nullptr, \
        rspamd_hyperscan_log_id, "hyperscan", HYPERSCAN_LOG_TAG, \
        log_func, \
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
	ankerl::svector<std::string, 4> cache_dirs;
	ankerl::svector<std::string, 8> cache_extensions;
	ankerl::unordered_dense::set<std::string> known_cached_files;
private:
	hs_known_files_cache() = default;

	virtual ~hs_known_files_cache() {
		// Cleanup cache dir
		cleanup_maybe();
	}

	/* Have to duplicate raii_file methods to use raw filenames */
	static auto get_dir(std::string_view fname) -> std::string_view {
		auto sep_pos = fname.rfind(G_DIR_SEPARATOR);

		if (sep_pos == std::string::npos) {
			return std::string_view{fname};
		}

		while (sep_pos >= 1 && fname[sep_pos - 1] == G_DIR_SEPARATOR) {
			sep_pos --;
		}

		return std::string_view{fname.data(), sep_pos};
	}

	static auto get_extension(std::string_view fname) -> std::string_view {
		auto sep_pos = fname.rfind(G_DIR_SEPARATOR);

		if (sep_pos == std::string::npos) {
			sep_pos = 0;
		}

		auto filename = std::string_view{fname.data() + sep_pos};
		auto dot_pos = filename.find('.');

		if (dot_pos == std::string::npos) {
			return std::string_view{};
		}
		else {
			return std::string_view{filename.data() + dot_pos + 1, filename.size() - dot_pos - 1};
		}
	}
public:
	hs_known_files_cache(const hs_known_files_cache &) = delete;
	hs_known_files_cache(hs_known_files_cache &&) = delete;

	static auto get() -> hs_known_files_cache& {
		static hs_known_files_cache *singleton = nullptr;

		if (singleton == nullptr) {
			singleton = new hs_known_files_cache;
		}

		return *singleton;
	}

	void add_cached_file(const raii_file &file) {
		auto dir = file.get_dir();
		auto ext = file.get_extension();

		if (std::find_if(cache_dirs.begin(), cache_dirs.end(),
			[&](const auto& item){ return item == dir; }) == std::end(cache_dirs)) {
			cache_dirs.emplace_back(std::string{dir});
		}
		if (std::find_if(cache_extensions.begin(), cache_extensions.end(),
			[&](const auto& item){ return item == ext; }) == std::end(cache_extensions)) {
			cache_extensions.emplace_back(std::string{ext});
		}

		auto is_known = known_cached_files.insert(file.get_name());
		msg_debug_hyperscan("added %s known hyperscan file: %*s",
			is_known.second ? "new" : "already",
			(int)file.get_name().size(),
			file.get_name().data());
	}

	void add_cached_file(const char *fname) {

		auto mut_fname = std::string{fname};
		std::size_t sz;
		rspamd_normalize_path_inplace(mut_fname.data(), mut_fname.size(), &sz);
		mut_fname.resize(sz);
		auto dir = hs_known_files_cache::get_dir(mut_fname);
		auto ext =  hs_known_files_cache::get_extension(mut_fname);

		if (std::find_if(cache_dirs.begin(), cache_dirs.end(),
			[&](const auto& item){ return item == dir; }) == std::end(cache_dirs)) {
			cache_dirs.emplace_back(std::string{dir});
		}
		if (std::find_if(cache_extensions.begin(), cache_extensions.end(),
			[&](const auto& item){ return item == ext; }) == std::end(cache_extensions)) {
			cache_extensions.emplace_back(std::string{ext});
		}

		auto is_known = known_cached_files.insert(mut_fname);
		msg_debug_hyperscan("added %s known hyperscan file: %s",
			is_known.second ? "new" : "already",
			mut_fname.c_str());
	}

	auto cleanup_maybe() -> void {
		/* We clean dir merely if we are running from the main process */
		if (rspamd_current_worker == nullptr) {
			const auto *log_func = RSPAMD_LOG_FUNC;
			auto cleanup_dir = [&](std::string_view dir) -> void {
				for (const auto &ext : cache_extensions) {
					glob_t globbuf;

					auto glob_pattern = fmt::format("{}{}*.{}",
						dir, G_DIR_SEPARATOR_S, ext);
					msg_debug_hyperscan_lambda("perform glob for pattern: %s",
						glob_pattern.c_str());
					memset(&globbuf, 0, sizeof(globbuf));

					if (glob(glob_pattern.c_str(), 0, nullptr, &globbuf) == 0) {
						for (auto i = 0; i < globbuf.gl_pathc; i++) {
							const auto *path = globbuf.gl_pathv[i];
							struct stat st;

							if (stat(path, &st) == -1) {
								msg_debug_hyperscan_lambda("cannot stat file %s: %s",
									path, strerror(errno));
								continue;
							}

							if (S_ISREG(st.st_mode)) {
								if (!known_cached_files.contains(path)) {
									msg_info_hyperscan_lambda("remove stale hyperscan file %s", path);
									unlink(path);
								}
								else {
									msg_debug_hyperscan_lambda("found known hyperscan file %s, size: %Hz",
										path, st.st_size);
								}
							}
						}
					}

					globfree(&globbuf);
				}
			};

			for (const auto &dir: cache_dirs) {
				msg_debug_hyperscan("cleaning up directory %s", dir.c_str());
				cleanup_dir(dir);
			}

			cache_dirs.clear();
			cache_extensions.clear();
			known_cached_files.clear();
		}
	}
};


/**
 * This is a higher level representation of the cached hyperscan file
 */
struct hs_shared_database {
	hs_database_t *db = nullptr; /**< internal database (might be in a shared memory) */
	std::optional<raii_mmaped_file> maybe_map;

	~hs_shared_database() {
		if (!maybe_map) {
			hs_free_database(db);
		}
		// Otherwise, handled by maybe_map dtor
	}

	explicit hs_shared_database(raii_mmaped_file &&map, hs_database_t *db) : db(db), maybe_map(std::move(map)) {}
	explicit hs_shared_database(hs_database_t *db) : db(db), maybe_map(std::nullopt) {}
	hs_shared_database(const hs_shared_database &other) = delete;
	hs_shared_database() = default;
	hs_shared_database(hs_shared_database &&other) noexcept {
		*this = std::move(other);
	}
	hs_shared_database& operator=(hs_shared_database &&other) noexcept {
		std::swap(db, other.db);
		std::swap(maybe_map, other.maybe_map);
		return *this;
	}
};

static auto
hs_shared_from_unserialized(raii_mmaped_file &&map) -> tl::expected<hs_shared_database, error>
{
	auto ptr = map.get_map();
	return tl::expected<hs_shared_database, error>{tl::in_place, std::move(map), (hs_database_t *)ptr};
}

static auto
hs_shared_from_serialized(raii_mmaped_file &&map, std::int64_t offset) -> tl::expected<hs_shared_database, error>
{
	hs_database_t *target = nullptr;

	if (auto ret = hs_deserialize_database((const char *)map.get_map() + offset,
		map.get_size() - offset, &target); ret != HS_SUCCESS) {
		return tl::make_unexpected(error {"cannot deserialize database", ret});
	}

	return tl::expected<hs_shared_database, error>{tl::in_place, target};
}

auto load_cached_hs_file(const char *fname, std::int64_t offset = 0) -> tl::expected<hs_shared_database, error>
{
	auto &hs_cache = hs_known_files_cache::get();
	const auto *log_func = RSPAMD_LOG_FUNC;

	return raii_mmaped_file::mmap_shared(fname, O_RDONLY, PROT_READ, 0)
		.and_then([&]<class T>(T &&cached_serialized) -> tl::expected<hs_shared_database, error> {
			if (cached_serialized.get_size() <= offset) {
				return tl::make_unexpected(error {"Invalid offset", EINVAL, error_category::CRITICAL });
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
						std::size_t unserialized_size;

						hs_serialized_database_size(((const char *)cached_serialized.get_map()) + offset,
							cached_serialized.get_size() - offset, &unserialized_size);

						msg_debug_hyperscan_lambda("multipattern: create new database in %s; %Hz size",
							tmpfile_pattern.data(), unserialized_size);
						void *buf;
						posix_memalign(&buf, 16, unserialized_size);
						if (buf == nullptr) {
							return tl::make_unexpected(error {"Cannot allocate memory", errno, error_category::CRITICAL });
						}

						// Store owned string
						auto tmpfile_name = std::string{tmpfile_checked.get_name()};

						if (auto ret = hs_deserialize_database_at(((const char *)cached_serialized.get_map()) + offset,
								cached_serialized.get_size() - offset, (hs_database_t *) buf); ret != HS_SUCCESS) {
							return tl::make_unexpected(error {
								fmt::format("cannot deserialize hyperscan database: {}", ret), ret });
						}
						else {
							if (write(tmpfile_checked.get_fd(), buf, unserialized_size) == -1) {
								free(buf);
								return tl::make_unexpected(error { fmt::format("cannot write to {}: {}",
									tmpfile_name, ::strerror(errno)), errno, error_category::CRITICAL });
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

			hs_cache.add_cached_file(cached_serialized.get_file());

			if (unserialized_file.has_value()) {

				auto &unserialized_checked = unserialized_file.value();

				if (unserialized_checked.get_size() == 0) {
					/*
					 * This is a case when we have a file that is currently
					 * being created by another process.
					 * We cannot use it!
					 */
					return hs_shared_from_serialized(std::forward<T>(cached_serialized), offset);
				}
				else {
					hs_cache.add_cached_file(unserialized_checked);
					return raii_mmaped_file::mmap_shared(std::move(unserialized_checked), PROT_READ)
						.and_then([&]<class U>(U &&mmapped_unserialized) -> auto {
							return hs_shared_from_unserialized(std::forward<U>(mmapped_unserialized));
						});
				}
			}
			else {
				return hs_shared_from_serialized(std::forward<T>(cached_serialized), offset);
			}
#else // defined(HS_MAJOR) && defined(HS_MINOR) && HS_MAJOR >= 5 && HS_MINOR >= 4
			hs_cache.add_cached_file(cached_serialized.get_file());
			return hs_shared_from_serialized(std::forward<T>(cached_serialized), offset);
#endif // defined(HS_MAJOR) && defined(HS_MINOR) && HS_MAJOR >= 5 && HS_MINOR >= 4
		});
}
} // namespace rspamd::util

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

		switch(error.category) {
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

hs_database_t*
rspamd_hyperscan_get_database(rspamd_hyperscan_t *db)
{
	auto *real_db = CXX_DB_FROM_C(db);
	return real_db->db;
}

rspamd_hyperscan_t *
rspamd_hyperscan_from_raw_db(hs_database_t *db)
{
	auto *ndb = new rspamd::util::hs_shared_database{db};

	return C_DB_FROM_CXX(ndb);
}

void
rspamd_hyperscan_free(rspamd_hyperscan_t *db)
{
	auto *real_db = CXX_DB_FROM_C(db);

	delete real_db;
}

void
rspamd_hyperscan_notice_known(const char *fname)
{
	rspamd::util::hs_known_files_cache::get().add_cached_file(fname);

	if (rspamd_current_worker != nullptr) {
		/* Also notify main process */
		struct rspamd_srv_command notice_cmd;

		if (strlen(fname) >= sizeof(notice_cmd.cmd.hyperscan_cache_file.path)) {
			msg_err("internal error: length of the filename %d ('%s') is larger than control buffer path: %d",
				(int)strlen(fname), fname, (int)sizeof(notice_cmd.cmd.hyperscan_cache_file.path));
		}
		else {
			notice_cmd.type = RSPAMD_NOTICE_HYPERSCAN_CACHE;
			rspamd_srv_send_command(rspamd_current_worker,
				rspamd_current_worker->srv->event_loop, &notice_cmd, -1,
				nullptr,
				nullptr);
		}
	}
}

void
rspamd_hyperscan_cleanup_maybe(void)
{
	rspamd::util::hs_known_files_cache::get().cleanup_maybe();
}

#endif // WITH_HYPERSCAN