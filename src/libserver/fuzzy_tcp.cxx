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

#include <deque>
#include <memory>
#include <optional>
#include "libutil/upstream.h"
#include "contrib/ankerl/unordered_dense.h"
#include "fuzzy_tcp.h"
#include "libutil/unix-std.h"
#include "contrib/libev/ev.h"
#include "libutil/cxx/error.hxx"
#include "contrib/expected/expected.hpp"
#include "fmt/core.h"

namespace rspamd {

enum class fuzzy_tcp_connection_state {
	UNCONNECTED,
	CONNECTING,
	CONNECTED,
	ERRORRED
};
/*
 * Handles a single connection to some fuzzy upstream
 */
class fuzzy_tcp_connection {
	int fd;
	struct upstream *cur_upstream;
	struct upstream_list *ls;
	fuzzy_tcp_connection_state state;
	ev_io io;
	ev_timer tm;
	std::optional<util::error> cur_error;

	static void connect_cb(EV_P_ ev_io *watcher, int revent)
	{
		auto *new_this = reinterpret_cast<fuzzy_tcp_connection *>(watcher->data);

		new_this->state = fuzzy_tcp_connection_state::CONNECTED;
		ev_io_stop(EV_A_ watcher);
	}

public:
	fuzzy_tcp_connection() = delete;
	explicit fuzzy_tcp_connection(struct upstream_list *ls)
		: fd(-1),
		  cur_upstream(nullptr),
		  ls(ls),
		  state(fuzzy_tcp_connection_state::UNCONNECTED)
	{
	}

	~fuzzy_tcp_connection()
	{
		if (fd != -1) {
			close(fd);
		}
		if (cur_upstream) {
			rspamd_upstream_unref(cur_upstream);
		}
	}

	[[nodiscard]] auto is_connected() const
	{
		return state == fuzzy_tcp_connection_state::CONNECTED;
	}

	tl::expected<bool, util::error> connect(struct ev_loop *loop)
	{
		switch (state) {
		case fuzzy_tcp_connection_state::UNCONNECTED: {

			if (!cur_upstream) {
				cur_upstream = rspamd_upstream_get(ls, RSPAMD_UPSTREAM_ROUND_ROBIN, nullptr, 0);
			}

			const auto *addr = rspamd_upstream_addr_cur(cur_upstream);
			socklen_t socklen;
			auto *sa = rspamd_inet_address_get_sa(addr, &socklen);
			if (::connect(fd, sa, socklen) == -1) {

				if (errno != EINPROGRESS) {
					return tl::make_unexpected(util::error(fmt::format("connect to {} failed",
																	   rspamd_inet_address_to_string(addr)),
														   errno, util::error_category::IMPORTANT));
				}

				/* Not connected now, will be connected once available */
				io.data = reinterpret_cast<void *>(this);
				ev_io_init(&io, fuzzy_tcp_connection::connect_cb, fd, EV_WRITE);
				ev_io_start(loop, &io);
				state = fuzzy_tcp_connection_state::CONNECTING;

				return false;
			}

			state = fuzzy_tcp_connection_state::CONNECTED;
			return true;
		}
		case fuzzy_tcp_connection_state::CONNECTED:
			return true;
		case fuzzy_tcp_connection_state::CONNECTING:
			/* Already sent request, cannot do anything else */
			return false;
		case fuzzy_tcp_connection_state::ERRORRED:
			/* Some error has taken place, cannot recover */
			return tl::make_unexpected(cur_error.value());
		}
	};

	/*
 * Handles all fuzzy tcp connections for all upstream lists
 */
	class fuzzy_tcp_connections_manager {
		ankerl::unordered_dense::map<struct upstream_list *, std::shared_ptr<fuzzy_tcp_connection>> connections;

	public:
		std::shared_ptr<fuzzy_tcp_connection> get_connection(struct upstream_list *upstream_list)
		{
			auto it = connections.find(upstream_list);

			if (it != connections.end()) {
				return it->second;
			}

			return nullptr;
		}
	};
};

}// namespace rspamd