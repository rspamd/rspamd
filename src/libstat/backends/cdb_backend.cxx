/*-
 * Copyright 2021 Vsevolod Stakhov
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

/*
 * CDB read only statistics backend
 */

#include "config.h"
#include "stat_internal.h"
#include "contrib/cdb/cdb.h"

#include <utility>
#include <memory>
#include <string>
#include <optional>
#include "contrib/expected/expected.hpp"
#include "fmt/core.h"

namespace rspamd::stat::cdb {

class ro_backend final {
public:
	explicit ro_backend(struct rspamd_statfile *_st, std::unique_ptr<struct cdb> &&_db)
			: st(_st), db(std::move(_db)) {}
	ro_backend() = delete;
	ro_backend(const ro_backend &) = delete;
	ro_backend(ro_backend &&other) noexcept {
		*this = std::move(other);
	}
	ro_backend& operator=(ro_backend &&other) noexcept
	{
		std::swap(st, other.st);
		std::swap(db, other.db);

		return *this;
	}
	~ro_backend() {
		if (db) {
			// Might be worth to use unique ptr with a custom deleter
			cdb_free(db.get());
		}
	}

	auto load_cdb() -> tl::expected<bool, std::string>;
	auto process_token(const rspamd_token_t *tok) const -> std::optional<float>;
private:
	struct rspamd_statfile *st;
	std::unique_ptr<struct cdb> db;
	bool loaded = false;
	std::uint64_t learns_spam = 0;
	std::uint64_t learns_ham = 0;
};

template<typename T>
static inline auto
cdb_get_key_as_double(struct cdb *cdb, T key) -> std::optional<double>
{
	auto pos = cdb_find(cdb, (void *)&key, sizeof(key));

	if (pos > 0) {
		auto vpos = cdb_datapos(cdb);
		auto vlen = cdb_datalen(cdb);

		if (vlen == sizeof(double)) {
			double ret;
			cdb_read(cdb, (void *)&ret, vlen, vpos);

			return ret;
		}
	}

	return std::nullopt;
}

template<typename T>
static inline auto
cdb_get_key_as_float_pair(struct cdb *cdb, T key) -> std::optional<std::pair<float, float>>
{
	auto pos = cdb_find(cdb, (void *)&key, sizeof(key));

	if (pos > 0) {
		auto vpos = cdb_datapos(cdb);
		auto vlen = cdb_datalen(cdb);

		if (vlen == sizeof(float) * 2) {
			union {
				struct {
					float v1;
					float v2;
				} d;
				char c[sizeof(float) * 2];
			} u;
			cdb_read(cdb, (void *)u.c, vlen, vpos);

			return std::make_pair(u.d.v1, u.d.v2);
		}
	}

	return std::nullopt;
}


auto
ro_backend::load_cdb() -> tl::expected<bool, std::string>
{
	if (!db) {
		return tl::make_unexpected("no database loaded");
	}

	/* Now get number of learns */
	std::int64_t cdb_key;
	static const char learn_spam_key[8] = "lrnspam", learn_ham_key[8] = "lrnham";

	auto check_key = [&](const char *key, std::uint64_t &target) -> tl::expected<bool, std::string> {
		memcpy((void *)&cdb_key, key, sizeof(cdb_key));

		auto maybe_value = cdb_get_key_as_double(db.get(), cdb_key);

		if (!maybe_value) {
			return tl::make_unexpected(fmt::format("missing {} key", key));
		}

		// Convert from double to int
		target = (std::uint64_t)maybe_value.value();

		return true;
	};

	auto res = check_key(learn_spam_key, learns_spam);

	if (!res) {
		return res;
	}

	res = check_key(learn_ham_key, learns_ham);

	if (!res) {
		return res;
	}

	loaded = true;

	return true; // expected
}

auto
ro_backend::process_token(const rspamd_token_t *tok) const -> std::optional<float>
{
	if (!loaded) {
		return std::nullopt;
	}

	auto maybe_value = cdb_get_key_as_float_pair(db.get(), tok->data);

	if (maybe_value) {
		auto [spam_count, ham_count] = maybe_value.value();

		if (st->stcf->is_spam) {
			return spam_count;
		}
		else {
			return ham_count;
		}
	}

	return std::nullopt;
}

auto
open_cdb(struct rspamd_statfile *st) -> tl::expected<ro_backend, std::string>
{
	const auto *stf = st->stcf;

	const auto *filename = ucl_object_lookup_any(stf->opts,
			"filename", "path", "cdb", nullptr);

	if (filename && ucl_object_type(filename) == UCL_STRING) {
		const auto *path = ucl_object_tostring(filename);

		auto fd = rspamd_file_xopen(path, O_RDONLY, 0, true);

		if (fd == -1) {
			return tl::make_unexpected(fmt::format("cannot open {}: {}",
					path, strerror(errno)));
		}

		auto &&cdbs = std::make_unique<struct cdb>();

		if (cdb_init(cdbs.get(), fd) == -1) {
			return tl::make_unexpected(fmt::format("cannot init cdb in {}: {}",
					path, strerror(errno)));
		}

		ro_backend bk{st, std::move(cdbs)};

		auto res = bk.load_cdb();

		if (!res) {
			return tl::make_unexpected(res.error());
		}

		return bk;
	}
	else {
		return tl::make_unexpected("missing/malformed filename attribute");
	}
}

}

/* C exports */
gpointer
rspamd_cdb_init(struct rspamd_stat_ctx* ctx,
						 struct rspamd_config* cfg,
						 struct rspamd_statfile* st)
{
	auto maybe_backend = rspamd::stat::cdb::open_cdb(st);

	if (maybe_backend) {
		/* Move into a new pointer */
		auto *result = new rspamd::stat::cdb::ro_backend(std::move(maybe_backend.value()));

		return result;
	}
	else {
		msg_err_config("cannot load cdb backend: %s", maybe_backend.error().c_str());
	}

	return nullptr;
}
gpointer
rspamd_cdb_runtime(struct rspamd_task* task,
							struct rspamd_statfile_config* stcf,
							gboolean learn,
							gpointer ctx)
{
	/* In CDB we don't have any dynamic stuff */
	return ctx;
}

gboolean
rspamd_cdb_process_tokens(struct rspamd_task* task,
								   GPtrArray* tokens,
								   gint id,
								   gpointer ctx)
{
	return false;
}
gboolean
rspamd_cdb_finalize_process(struct rspamd_task* task,
									 gpointer runtime,
									 gpointer ctx)
{
	return false;
}
gboolean
rspamd_cdb_learn_tokens(struct rspamd_task* task,
								 GPtrArray* tokens,
								 gint id,
								 gpointer ctx)
{
	return false;
}
gboolean
rspamd_cdb_finalize_learn(struct rspamd_task* task,
								   gpointer runtime,
								   gpointer ctx,
								   GError** err)
{
	return false;
}

gulong rspamd_cdb_total_learns(struct rspamd_task* task,
							   gpointer runtime,
							   gpointer ctx)
{
	return 0;
}
gulong
rspamd_cdb_inc_learns(struct rspamd_task* task,
							 gpointer runtime,
							 gpointer ctx)
{
	return (gulong)-1;
}
gulong
rspamd_cdb_dec_learns(struct rspamd_task* task,
							 gpointer runtime,
							 gpointer ctx)
{
	return (gulong)-1;
}
gulong
rspamd_cdb_learns(struct rspamd_task* task,
						 gpointer runtime,
						 gpointer ctx)
{
	return 0;
}
ucl_object_t*
rspamd_cdb_get_stat(gpointer runtime, gpointer ctx)
{
	return nullptr;
}
gpointer
rspamd_cdb_load_tokenizer_config(gpointer runtime, gsize* len)
{
	return nullptr;
}
void
rspamd_cdb_close(gpointer ctx)
{

}