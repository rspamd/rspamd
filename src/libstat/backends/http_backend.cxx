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
#include "stat_internal.h"
#include "libserver/http/http_connection.h"
#include "libserver/mempool_vars_internal.h"
#include "upstream.h"
#include "contrib/ankerl/unordered_dense.h"
#include <vector>

namespace rspamd::stat::http {

#define msg_debug_stat_http(...)  rspamd_conditional_debug_fast (NULL, NULL, \
        rspamd_stat_http_log_id, "stat_http", task->task_pool->tag.uid, \
        RSPAMD_LOG_FUNC, \
        __VA_ARGS__)

INIT_LOG_MODULE(stat_http)

/* Represents all http backends defined in some configuration */
class http_backends_collection {
	std::vector<struct rspamd_statfile *> backends;
	double timeout = 1.0; /* Default timeout */
	struct upstream_list *read_servers = nullptr;
	struct upstream_list *write_servers = nullptr;
public:
	static auto get() -> http_backends_collection& {
		static http_backends_collection *singleton = nullptr;

		if (singleton == nullptr) {
			singleton = new http_backends_collection;
		}

		return *singleton;
	}

	/**
	 * Add a new backend and (optionally initialize the basic backend parameters
	 * @param ctx
	 * @param cfg
	 * @param st
	 * @return
	 */
	auto add_backend(struct rspamd_stat_ctx *ctx,
					 struct rspamd_config *cfg,
					 struct rspamd_statfile *st) -> bool;
	/**
	 * Remove a statfile cleaning things up if the last statfile is removed
	 * @param st
	 * @return
	 */
	auto remove_backend(struct rspamd_statfile *st) -> bool;

	upstream *get_upstream(bool is_learn);

private:
	http_backends_collection() = default;
	auto first_init(struct rspamd_stat_ctx *ctx,
					struct rspamd_config *cfg,
					struct rspamd_statfile *st) -> bool;
};

/*
 * Created one per each task
 */
class http_backend_runtime final {
public:
	static auto create(struct rspamd_task *task, bool is_learn) -> http_backend_runtime *;
	/* Add a new statfile with a specific id to the list of statfiles */
	auto notice_statfile(int id, const struct rspamd_statfile_config *st) -> void {
		seen_statfiles[id] = st;
	}

	auto process_tokens(struct rspamd_task* task,
						GPtrArray* tokens,
						gint id,
						bool learn) -> bool;
private:
	http_backends_collection *all_backends;
	ankerl::unordered_dense::map<int, const struct rspamd_statfile_config *> seen_statfiles;
	struct upstream *selected;
private:
	http_backend_runtime(struct rspamd_task *task, bool is_learn) :
			all_backends(&http_backends_collection::get()) {
		selected = all_backends->get_upstream(is_learn);
	}
	~http_backend_runtime() = default;
	static auto dtor(void *p) -> void {
		((http_backend_runtime *)p)->~http_backend_runtime();
	}
};

/*
 * Efficient way to make a messagepack payload from stat tokens,
 * avoiding any intermediate libraries, as we would send many tokens
 * all together
 */
static auto
stat_tokens_to_msgpack(GPtrArray *tokens) -> std::vector<std::uint8_t>
{
	std::vector<std::uint8_t> ret;
	rspamd_token_t *cur;
	int i;

	/*
	 * We define array, it's size and N elements each is uint64_t
	 * Layout:
	 * 0xdd - array marker
	 * [4 bytes be] - size of the array
	 * [ 0xcf + <8 bytes BE integer>] * N - array elements
	 */
	ret.resize(tokens->len * (sizeof(std::uint64_t) + 1) + 5);
	ret.push_back('\xdd');
	std::uint32_t ulen = GUINT32_TO_BE(tokens->len);
	std::copy((const std::uint8_t *)&ulen,
			((const std::uint8_t *)&ulen) + sizeof(ulen), std::back_inserter(ret));

	PTR_ARRAY_FOREACH(tokens, i, cur) {
		ret.push_back('\xcf');
		std::uint64_t val = GUINT64_TO_BE(cur->data);
		std::copy((const std::uint8_t *)&val,
				((const std::uint8_t *)&val) + sizeof(val), std::back_inserter(ret));
	}

	return ret;
}

auto http_backend_runtime::create(struct rspamd_task *task, bool is_learn) -> http_backend_runtime *
{
	/* Alloc type provide proper size and alignment */
	auto *allocated_runtime = rspamd_mempool_alloc_type(task->task_pool, http_backend_runtime);

	rspamd_mempool_add_destructor(task->task_pool, http_backend_runtime::dtor, allocated_runtime);

	return new (allocated_runtime) http_backend_runtime{task, is_learn};
}

auto
http_backend_runtime::process_tokens(struct rspamd_task *task, GPtrArray *tokens, gint id, bool learn) -> bool
{
	if (!learn) {
		if (id == seen_statfiles.size() - 1) {
			/* Emit http request on the last statfile */
		}
	}
	else {
		/* On learn we need to learn all statfiles that we were requested to learn */
		if (seen_statfiles.empty()) {
			/* Request has been already set, or nothing to learn */
			return true;
		}
		else {
			seen_statfiles.clear();
		}
	}

	return true;
}

auto
http_backends_collection::add_backend(struct rspamd_stat_ctx *ctx,
									  struct rspamd_config *cfg,
									  struct rspamd_statfile *st) -> bool
{
	/* On empty list of backends we know that we need to load backend data actually */
	if (backends.empty()) {
		if (!first_init(ctx, cfg, st)) {
			return false;
		}
	}

	backends.push_back(st);

	return true;
}

auto http_backends_collection::first_init(struct rspamd_stat_ctx *ctx,
										  struct rspamd_config *cfg,
										  struct rspamd_statfile *st) -> bool
{
	auto try_load_backend_config = [&](const ucl_object_t *obj) -> bool {
		if (!obj || ucl_object_type(obj) != UCL_OBJECT) {
			return false;
		}

		/* First try to load read servers */
		auto *rs = ucl_object_lookup_any(obj, "read_servers", "servers", nullptr);
		if (rs) {
			read_servers = rspamd_upstreams_create(cfg->ups_ctx);

			if (read_servers == nullptr) {
				return false;
			}

			if (!rspamd_upstreams_from_ucl(read_servers, rs, 80, this)) {
				rspamd_upstreams_destroy(read_servers);
				return false;
			}
		}
		auto *ws = ucl_object_lookup_any(obj, "write_servers", "servers", nullptr);
		if (ws) {
			write_servers = rspamd_upstreams_create(cfg->ups_ctx);

			if (write_servers == nullptr) {
				return false;
			}

			if (!rspamd_upstreams_from_ucl(write_servers, rs, 80, this)) {
				rspamd_upstreams_destroy(write_servers);
				return false;
			}
		}

		auto *tim = ucl_object_lookup(obj, "timeout");

		if (tim) {
			timeout = ucl_object_todouble(tim);
		}

		return true;
	};

	auto ret = false;
	auto obj = ucl_object_lookup (st->classifier->cfg->opts, "backend");
	if (obj != nullptr) {
		ret = try_load_backend_config(obj);
	}

	/* Now try statfiles config */
	if (!ret && st->stcf->opts) {
		ret = try_load_backend_config(st->stcf->opts);
	}

	/* Now try classifier config */
	if (!ret && st->classifier->cfg->opts) {
		ret = try_load_backend_config(st->classifier->cfg->opts);
	}

	return ret;
}

auto http_backends_collection::remove_backend(struct rspamd_statfile *st) -> bool
{
	auto backend_it = std::remove(std::begin(backends), std::end(backends), st);

	if (backend_it != std::end(backends)) {
		/* Fast erasure with no order preservation */
		std::swap(*backend_it, backends.back());
		backends.pop_back();

		if (backends.empty()) {
			/* De-init collection - likely config reload */
			if (read_servers) {
				rspamd_upstreams_destroy(read_servers);
				read_servers = nullptr;
			}

			if (write_servers) {
				rspamd_upstreams_destroy(write_servers);
				write_servers = nullptr;
			}
		}

		return true;
	}

	return false;
}

upstream *http_backends_collection::get_upstream(bool is_learn)
{
	auto *ups_list = read_servers;
	if (is_learn) {
		ups_list = write_servers;
	}

	return rspamd_upstream_get(ups_list, RSPAMD_UPSTREAM_ROUND_ROBIN, nullptr, 0);
}

}

/* C API */

gpointer
rspamd_http_init(struct rspamd_stat_ctx* ctx,
				struct rspamd_config* cfg,
				struct rspamd_statfile* st)
{
	auto &collections = rspamd::stat::http::http_backends_collection::get();

	if (!collections.add_backend(ctx, cfg, st)) {
		msg_err_config("cannot load http backend");

		return nullptr;
	}

	return (void *)&collections;
}
gpointer
rspamd_http_runtime(struct rspamd_task* task,
					struct rspamd_statfile_config* stcf,
					gboolean learn,
					gpointer ctx,
					gint id)
{
	auto maybe_existing = rspamd_mempool_get_variable(task->task_pool, RSPAMD_MEMPOOL_HTTP_STAT_BACKEND_RUNTIME);

	if (maybe_existing != nullptr) {
		auto real_runtime = (rspamd::stat::http::http_backend_runtime *)maybe_existing;
		real_runtime->notice_statfile(id, stcf);

		return maybe_existing;
	}

	auto runtime = rspamd::stat::http::http_backend_runtime::create(task, learn);

	if (runtime) {
		runtime->notice_statfile(id, stcf);
		rspamd_mempool_set_variable(task->task_pool, RSPAMD_MEMPOOL_HTTP_STAT_BACKEND_RUNTIME,
				(void *)runtime, nullptr);
	}

	return (void *)runtime;
}

gboolean
rspamd_http_process_tokens(struct rspamd_task* task,
						  GPtrArray* tokens,
						  gint id,
						  gpointer runtime)
{
	auto real_runtime = (rspamd::stat::http::http_backend_runtime *)runtime;

	if (real_runtime) {
		return real_runtime->process_tokens(task, tokens, id, false);
	}


	return false;

}
gboolean
rspamd_http_finalize_process(struct rspamd_task* task,
							gpointer runtime,
							gpointer ctx)
{
	/* Not needed */
	return true;
}

gboolean
rspamd_http_learn_tokens(struct rspamd_task* task,
						GPtrArray* tokens,
						gint id,
						gpointer runtime)
{
	auto real_runtime = (rspamd::stat::http::http_backend_runtime *)runtime;

	if (real_runtime) {
		return real_runtime->process_tokens(task, tokens, id, true);
	}


	return false;
}
gboolean
rspamd_http_finalize_learn(struct rspamd_task* task,
						  gpointer runtime,
						  gpointer ctx,
						  GError** err)
{
	return false;
}

gulong rspamd_http_total_learns(struct rspamd_task* task,
							   gpointer runtime,
							   gpointer ctx)
{
	/* TODO */
	return 0;
}
gulong
rspamd_http_inc_learns(struct rspamd_task* task,
					  gpointer runtime,
					  gpointer ctx)
{
	/* TODO */
	return 0;
}
gulong
rspamd_http_dec_learns(struct rspamd_task* task,
					  gpointer runtime,
					  gpointer ctx)
{
	/* TODO */
	return (gulong)-1;
}
gulong
rspamd_http_learns(struct rspamd_task* task,
				  gpointer runtime,
				  gpointer ctx)
{
	/* TODO */
	return 0;
}
ucl_object_t*
rspamd_http_get_stat(gpointer runtime, gpointer ctx)
{
	/* TODO */
	return nullptr;
}
gpointer
rspamd_http_load_tokenizer_config(gpointer runtime, gsize* len)
{
	return nullptr;
}
void
rspamd_http_close(gpointer ctx)
{
	/* TODO */
}