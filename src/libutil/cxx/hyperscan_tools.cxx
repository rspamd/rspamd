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

#include <glob.h> /* for glob */
#include <sys/stat.h> /* for stat */
#include <unistd.h> /* for unlink */

namespace rspamd::util {

class hs_known_files_cache {
private:
	// These fields are filled when we add new known cache files
	ankerl::svector<std::string, 4> cache_dirs;
	ankerl::svector<std::string, 8> cache_extensions;
	ankerl::unordered_dense::set<std::string> known_cached_files;
	bool need_cleanup = false;
private:
	hs_known_files_cache() = default;

	virtual ~hs_known_files_cache() {
		// Cleanup cache dir
		if (need_cleanup) {
			auto cleanup_dir = [&](std::string_view dir) -> void {
				for (const auto &ext : cache_extensions) {
					glob_t globbuf;

					auto glob_pattern = fmt::format("{}{}*.{}",
							dir, G_DIR_SEPARATOR_S, ext);
					memset(&globbuf, 0, sizeof(globbuf));

					if (glob(glob_pattern.c_str(), 0, nullptr, &globbuf) == 0) {
						for (auto i = 0; i < globbuf.gl_pathc; i++) {
							const auto *path = globbuf.gl_pathv[i];
							struct stat st;

							if (stat(path, &st) == -1) {
								continue;
							}

							if (S_ISREG(st.st_mode)) {
								if (!known_cached_files.contains(path)) {
									unlink(path);
								}
							}
						}
					}

					globfree(&globbuf);
				}
			};

			for (const auto &dir: cache_dirs) {
				cleanup_dir(dir);
			}
		}
	}
public:
	hs_known_files_cache(const hs_known_files_cache &) = delete;
	hs_known_files_cache(hs_known_files_cache &&) = delete;

	static auto get(bool need_cleanup) -> hs_known_files_cache& {
		static hs_known_files_cache *singleton = nullptr;

		if (singleton == nullptr) {
			singleton = new hs_known_files_cache;
			singleton->need_cleanup = need_cleanup;
		}

		return *singleton;
	}
};


} // namespace rspamd::util


#endif