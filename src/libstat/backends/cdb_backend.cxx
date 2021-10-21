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
#include "contrib/robin-hood/robin_hood.h"
#include "fmt/core.h"

namespace rspamd::stat::cdb {

/*
 * Utility class to share cdb instances over statfiles instances, as each
 * cdb has tokens for both ham and spam classes
 */
class cdb_shared_storage {
public:
	using cdb_element_t = std::shared_ptr<struct cdb>;
	cdb_shared_storage() noexcept = default;

	auto get_cdb(const char *path) const -> std::optional<cdb_element_t> {
		auto found = elts.find(path);

		if (found != elts.end()) {
			if (!found->second.expired()) {
				return found->second.lock();
			}
		}

		return std::nullopt;
	}
	/* Create a new smart pointer over POD cdb structure */
	static auto new_cdb() -> cdb_element_t {
		auto ret = cdb_element_t(new struct cdb, cdb_deleter());
		memset(ret.get(), 0, sizeof(struct cdb));
		return ret;
	}
	/* Enclose cdb into storage */
	auto push_cdb(const char *path, cdb_element_t cdbp) -> cdb_element_t {
		auto found = elts.find(path);

		if (found != elts.end()) {
			if (found->second.expired()) {
				/* OK, move in lieu of the expired weak pointer */

				found->second = cdbp;
				return cdbp;
			}
			else {
				/*
				 * Existing and not expired, return the existing one
				 */
				return found->second.lock();
			}
		}
		else {
			/* Not existing, make a weak ptr and return the original */
			elts.emplace(path,std::weak_ptr<struct cdb>(cdbp));
			return cdbp;
		}
	}
private:
	/*
	 * We store weak pointers here to allow owning cdb statfiles to free
	 * expensive cdb before this cache is terminated (e.g. on dynamic cdb reload)
	 */
	robin_hood::unordered_flat_map<std::string, std::weak_ptr<struct cdb>> elts;

	struct cdb_deleter {
		void operator()(struct cdb *c) const {
			cdb_free(c);
		}
	};
};

static cdb_shared_storage cdb_shared_storage;

class ro_backend final {
public:
	explicit ro_backend(struct rspamd_statfile *_st, cdb_shared_storage::cdb_element_t _db)
			: st(_st), db(_db) {}
	ro_backend() = delete;
	ro_backend(const ro_backend &) = delete;
	ro_backend(ro_backend &&other) noexcept {
		*this = std::move(other);
	}
	ro_backend& operator=(ro_backend &&other) noexcept
	{
		std::swap(st, other.st);
		std::swap(db, other.db);
		std::swap(loaded, other.loaded);
		std::swap(learns_spam, other.learns_spam);
		std::swap(learns_ham, other.learns_ham);

		return *this;
	}
	~ro_backend() {}

	auto load_cdb() -> tl::expected<bool, std::string>;
	auto process_token(const rspamd_token_t *tok) const -> std::optional<float>;
	constexpr auto is_spam() const -> bool {
		return st->stcf->is_spam;
	}
	auto get_learns() const -> std::uint64_t {
		if (is_spam()) {
			return learns_spam;
		}
		else {
			return learns_ham;
		}
	}
	auto get_total_learns() const -> std::uint64_t {
		return learns_spam + learns_ham;
	}
private:
	struct rspamd_statfile *st;
	cdb_shared_storage::cdb_element_t db;
	bool loaded = false;
	std::uint64_t learns_spam = 0;
	std::uint64_t learns_ham = 0;
};

template<typename T>
static inline auto
cdb_get_key_as_int64(struct cdb *cdb, T key) -> std::optional<std::int64_t>
{
	auto pos = cdb_find(cdb, (void *)&key, sizeof(key));

	if (pos > 0) {
		auto vpos = cdb_datapos(cdb);
		auto vlen = cdb_datalen(cdb);

		if (vlen == sizeof(std::int64_t)) {
			std::int64_t ret;
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
	static const char learn_spam_key[9] = "_lrnspam", learn_ham_key[9] = "_lrnham_";

	auto check_key = [&](const char *key, std::uint64_t &target) -> tl::expected<bool, std::string> {
		memcpy((void *)&cdb_key, key, sizeof(cdb_key));

		auto maybe_value = cdb_get_key_as_int64(db.get(), cdb_key);

		if (!maybe_value) {
			return tl::make_unexpected(fmt::format("missing {} key", key));
		}

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

		if (is_spam()) {
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
	const char *path = nullptr;
	const auto *stf = st->stcf;

	auto get_filename = [](const ucl_object_t *obj) -> const char * {
		const auto *filename = ucl_object_lookup_any(obj,
				"filename", "path", "cdb", nullptr);

		if (filename && ucl_object_type(filename) == UCL_STRING) {
			return ucl_object_tostring(filename);
		}

		return nullptr;
	};

	/* First search in backend configuration */
	const auto *obj = ucl_object_lookup (st->classifier->cfg->opts, "backend");
	if (obj != NULL && ucl_object_type (obj) == UCL_OBJECT) {
		path = get_filename(obj);
	}

	/* Now try statfiles config */
	if (!path && stf->opts) {
		path = get_filename(stf->opts);
	}

	/* Now try classifier config */
	if (!path && st->classifier->cfg->opts) {
		path = get_filename(st->classifier->cfg->opts);
	}

	if (!path) {
		return tl::make_unexpected("missing/malformed filename attribute");
	}

	auto cached_cdb_maybe = cdb_shared_storage.get_cdb(path);
	cdb_shared_storage::cdb_element_t cdbp;

	if (!cached_cdb_maybe) {

		auto fd = rspamd_file_xopen(path, O_RDONLY, 0, true);

		if (fd == -1) {
			return tl::make_unexpected(fmt::format("cannot open {}: {}",
					path, strerror(errno)));
		}

		cdbp = cdb_shared_storage::new_cdb();

		if (cdb_init(cdbp.get(), fd) == -1) {
			close(fd);

			return tl::make_unexpected(fmt::format("cannot init cdb in {}: {}",
					path, strerror(errno)));
		}

		cdbp = cdb_shared_storage.push_cdb(path, cdbp);

		close(fd);
	}
	else {
		cdbp = cached_cdb_maybe.value();
	}

	if (!cdbp) {
		return tl::make_unexpected(fmt::format("cannot init cdb in {}: internal error",
				path));
	}

	ro_backend bk{st, cdbp};

	auto res = bk.load_cdb();

	if (!res) {
		return tl::make_unexpected(res.error());
	}

	return bk;
}

}

#define CDB_FROM_RAW(p) (reinterpret_cast<rspamd::stat::cdb::ro_backend *>(p))

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
	auto *cdbp = CDB_FROM_RAW(ctx);
	bool seen_values = false;

	for (auto i = 0u; i < tokens->len; i++) {
		rspamd_token_t *tok;
		tok = reinterpret_cast<rspamd_token_t *>(g_ptr_array_index(tokens, i));

		auto res = cdbp->process_token(tok);

		if (res) {
			tok->values[id] = res.value();
			seen_values = true;
		}
		else {
			tok->values[id] = 0;
		}
	}

	if (seen_values) {
		if (cdbp->is_spam()) {
			task->flags |= RSPAMD_TASK_FLAG_HAS_SPAM_TOKENS;
		}
		else {
			task->flags |= RSPAMD_TASK_FLAG_HAS_HAM_TOKENS;
		}
	}

	return true;

}
gboolean
rspamd_cdb_finalize_process(struct rspamd_task* task,
									 gpointer runtime,
									 gpointer ctx)
{
	return true;
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
	auto *cdbp = CDB_FROM_RAW(ctx);
	return cdbp->get_total_learns();
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
	auto *cdbp = CDB_FROM_RAW(ctx);
	return cdbp->get_learns();
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
	auto *cdbp = CDB_FROM_RAW(ctx);
	delete cdbp;
}