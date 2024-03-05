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
#include "libutil/str_util.h"
#include "khash.h"
#include "lua_classnames.h"

const char *rspamd_archive_classname = "rspamd{archive}";
const char *rspamd_cdb_builder_classname = "rspamd{cdb_builder}";
const char *rspamd_cdb_classname = "rspamd{cdb}";
const char *rspamd_classifier_classname = "rspamd{classifier}";
const char *rspamd_config_classname = "rspamd{config}";
const char *rspamd_cryptobox_hash_classname = "rspamd{cryptobox_hash}";
const char *rspamd_cryptobox_keypair_classname = "rspamd{cryptobox_keypair}";
const char *rspamd_cryptobox_pubkey_classname = "rspamd{cryptobox_pubkey}";
const char *rspamd_cryptobox_secretbox_classname = "rspamd{cryptobox_secretbox}";
const char *rspamd_cryptobox_signature_classname = "rspamd{cryptobox_signature}";
const char *rspamd_csession_classname = "rspamd{csession}";
const char *rspamd_ev_base_classname = "rspamd{ev_base}";
const char *rspamd_expr_classname = "rspamd{expr}";
const char *rspamd_html_tag_classname = "rspamd{html_tag}";
const char *rspamd_html_classname = "rspamd{html}";
const char *rspamd_image_classname = "rspamd{image}";
const char *rspamd_int64_classname = "rspamd{int64}";
const char *rspamd_ip_classname = "rspamd{ip}";
const char *rspamd_kann_node_classname = "rspamd{kann_node}";
const char *rspamd_kann_classname = "rspamd{kann}";
const char *rspamd_map_classname = "rspamd{map}";
const char *rspamd_mempool_classname = "rspamd{mempool}";
const char *rspamd_mimepart_classname = "rspamd{mimepart}";
const char *rspamd_monitored_classname = "rspamd{monitored}";
const char *rspamd_redis_classname = "rspamd{redis}";
const char *rspamd_regexp_classname = "rspamd{regexp}";
const char *rspamd_resolver_classname = "rspamd{resolver}";
const char *rspamd_rsa_privkey_classname = "rspamd{rsa_privkey}";
const char *rspamd_rsa_pubkey_classname = "rspamd{rsa_pubkey}";
const char *rspamd_rsa_signature_classname = "rspamd{rsa_signature}";
const char *rspamd_session_classname = "rspamd{session}";
const char *rspamd_spf_record_classname = "rspamd{spf_record}";
const char *rspamd_sqlite3_stmt_classname = "rspamd{sqlite3_stmt}";
const char *rspamd_sqlite3_classname = "rspamd{sqlite3}";
const char *rspamd_statfile_classname = "rspamd{statfile}";
const char *rspamd_task_classname = "rspamd{task}";
const char *rspamd_tcp_sync_classname = "rspamd{tcp_sync}";
const char *rspamd_tcp_classname = "rspamd{tcp}";
const char *rspamd_tensor_classname = "rspamd{tensor}";
const char *rspamd_textpart_classname = "rspamd{textpart}";
const char *rspamd_text_classname = "rspamd{text}";
const char *rspamd_trie_classname = "rspamd{trie}";
const char *rspamd_upstream_list_classname = "rspamd{upstream_list}";
const char *rspamd_upstream_classname = "rspamd{upstream}";
const char *rspamd_url_classname = "rspamd{url}";
const char *rspamd_worker_classname = "rspamd{worker}";
const char *rspamd_zstd_compress_classname = "rspamd{zstd_compress}";
const char *rspamd_zstd_decompress_classname = "rspamd{zstd_decompress}";

KHASH_INIT(rspamd_lua_static_classes, const char *, const char *, 1, rspamd_str_hash, rspamd_str_equal);

static khash_t(rspamd_lua_static_classes) *lua_static_classes = NULL;

#define CLASS_PUT_STR(s)                                                              \
	do {                                                                              \
		int _r = 0;                                                                   \
		khiter_t it = kh_put(rspamd_lua_static_classes, lua_static_classes, #s, &_r); \
		g_assert(_r > 0);                                                             \
		kh_value(lua_static_classes, it) = rspamd_##s##_classname;                    \
	} while (0)

RSPAMD_CONSTRUCTOR(rspamd_lua_init_classnames)
{
	lua_static_classes = kh_init(rspamd_lua_static_classes);
	kh_resize(rspamd_lua_static_classes, lua_static_classes, RSPAMD_MAX_LUA_CLASSES);

	CLASS_PUT_STR(archive);
	CLASS_PUT_STR(cdb_builder);
	CLASS_PUT_STR(cdb);
	CLASS_PUT_STR(classifier);
	CLASS_PUT_STR(config);
	CLASS_PUT_STR(cryptobox_hash);
	CLASS_PUT_STR(cryptobox_keypair);
	CLASS_PUT_STR(cryptobox_pubkey);
	CLASS_PUT_STR(cryptobox_secretbox);
	CLASS_PUT_STR(cryptobox_signature);
	CLASS_PUT_STR(csession);
	CLASS_PUT_STR(ev_base);
	CLASS_PUT_STR(expr);
	CLASS_PUT_STR(html_tag);
	CLASS_PUT_STR(html);
	CLASS_PUT_STR(image);
	CLASS_PUT_STR(int64);
	CLASS_PUT_STR(ip);
	CLASS_PUT_STR(kann_node);
	CLASS_PUT_STR(kann);
	CLASS_PUT_STR(map);
	CLASS_PUT_STR(mempool);
	CLASS_PUT_STR(mimepart);
	CLASS_PUT_STR(monitored);
	CLASS_PUT_STR(redis);
	CLASS_PUT_STR(regexp);
	CLASS_PUT_STR(resolver);
	CLASS_PUT_STR(rsa_privkey);
	CLASS_PUT_STR(rsa_pubkey);
	CLASS_PUT_STR(rsa_signature);
	CLASS_PUT_STR(session);
	CLASS_PUT_STR(spf_record);
	CLASS_PUT_STR(sqlite3_stmt);
	CLASS_PUT_STR(sqlite3);
	CLASS_PUT_STR(statfile);
	CLASS_PUT_STR(task);
	CLASS_PUT_STR(tcp_sync);
	CLASS_PUT_STR(tcp);
	CLASS_PUT_STR(tensor);
	CLASS_PUT_STR(textpart);
	CLASS_PUT_STR(text);
	CLASS_PUT_STR(trie);
	CLASS_PUT_STR(upstream_list);
	CLASS_PUT_STR(upstream);
	CLASS_PUT_STR(url);
	CLASS_PUT_STR(worker);
	CLASS_PUT_STR(zstd_compress);
	CLASS_PUT_STR(zstd_decompress);

	/* Check consistency */
	g_assert(kh_size(lua_static_classes) == RSPAMD_MAX_LUA_CLASSES);
}

const char *
rspamd_lua_static_classname(const char *name, guint len)
{
	khiter_t k;

	g_assert(lua_static_classes != NULL);
	char classbuf[128];

	rspamd_strlcpy(classbuf, name, MIN(sizeof(classbuf), len + 1));
	name = classbuf;

	k = kh_get(rspamd_lua_static_classes, lua_static_classes, name);

	if (k != kh_end(lua_static_classes)) {
		return kh_value(lua_static_classes, k);
	}

	return NULL;
}

RSPAMD_DESTRUCTOR(rspamd_lua_deinit_classnames)
{
	if (lua_static_classes != NULL) {
		kh_destroy(rspamd_lua_static_classes, lua_static_classes);
	}
}