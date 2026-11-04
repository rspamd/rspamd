/*
 * Copyright 2026 Vsevolod Stakhov
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

/* DKIM plugin signing key ownership when sign_cache_size = 0 */

#ifndef RSPAMD_RSPAMD_CXX_UNIT_DKIM_CACHE_HXX
#define RSPAMD_RSPAMD_CXX_UNIT_DKIM_CACHE_HXX

#define DOCTEST_CONFIG_IMPLEMENTATION_IN_DLL
#include "doctest/doctest.h"

#include "config.h"
#include "libserver/cfg_file.h"
#include "libserver/dkim.h"
#include "libserver/task.h"

#ifdef __SANITIZE_ADDRESS__
#include <sanitizer/asan_interface.h>
#endif

#include <array>

extern "C" {
/* Defined in src/plugins/dkim_check.c */
struct dkim_ctx;
int dkim_module_init(struct rspamd_config *cfg, struct module_ctx **ctx);
rspamd_dkim_sign_key_t *dkim_module_load_key_format(struct rspamd_task *task,
													struct dkim_ctx *dkim_module_ctx,
													const char *key, gsize keylen,
													enum rspamd_dkim_key_format key_format);
}

TEST_SUITE("dkim_cache")
{
	TEST_CASE("uncached sign key is released with the task")
	{
		auto *cfg = rspamd_config_new(RSPAMD_CONFIG_INIT_DEFAULT);
		struct module_ctx *mctx = nullptr;
		REQUIRE(dkim_module_init(cfg, &mctx) == 0);
		/* dkim_module_config is not called, so there is no sign key cache */
		auto *dkim_ctx = reinterpret_cast<struct dkim_ctx *>(mctx);

		/* A raw 32 byte seed loads as an ed25519 key */
		std::array<char, 32> seed;
		seed.fill('k');
		auto *task = rspamd_task_new(nullptr, nullptr, nullptr, nullptr, nullptr, FALSE);
		auto *key = dkim_module_load_key_format(task, dkim_ctx, seed.data(), seed.size(),
												RSPAMD_DKIM_KEY_RAW);
		REQUIRE(key != nullptr);

		/* The returned key is borrowed: a caller takes its own reference */
		rspamd_dkim_sign_key_ref(key);
		rspamd_task_free(task);
		CHECK(rspamd_dkim_sign_key_get_type(key) == RSPAMD_DKIM_KEY_EDDSA);

		/* The task dropped the reference from loading, so this frees the key */
		rspamd_dkim_sign_key_unref(key);
#ifdef __SANITIZE_ADDRESS__
		CHECK(__asan_address_is_poisoned(key) != 0);
#endif

		rspamd_config_free(cfg);
	}
}

#endif
