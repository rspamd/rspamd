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

/**
 * A simple RAII object to contain a file descriptor with an flock wrap
 * A file is unlocked and closed when not needed
 */
struct raii_locked_file final {
	~raii_locked_file();
	static auto open(const char *fname, int flags) -> tl::expected<raii_locked_file, std::string>;
private:
	int fd;
	explicit raii_locked_file(int _fd) : fd(_fd) {}
};

#endif //RSPAMD_LOCKED_FILE_HXX
