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


#ifndef RSPAMD_LUA_CLASSNAMES_H
#define RSPAMD_LUA_CLASSNAMES_H

/*
 * Here are static definitions of all classes used in Rspamd Lua API
 */

extern const char *rspamd_archive_classname;
extern const char *rspamd_cdb_builder_classname;
extern const char *rspamd_cdb_classname;
extern const char *rspamd_classifier_classname;
extern const char *rspamd_config_classname;
extern const char *rspamd_cryptobox_hash_classname;
extern const char *rspamd_cryptobox_keypair_classname;
extern const char *rspamd_cryptobox_pubkey_classname;
extern const char *rspamd_cryptobox_secretbox_classname;
extern const char *rspamd_cryptobox_signature_classname;
extern const char *rspamd_csession_classname;
extern const char *rspamd_ev_base_classname;
extern const char *rspamd_expr_classname;
extern const char *rspamd_html_tag_classname;
extern const char *rspamd_html_classname;
extern const char *rspamd_image_classname;
extern const char *rspamd_int64_classname;
extern const char *rspamd_ip_classname;
extern const char *rspamd_kann_node_classname;
extern const char *rspamd_kann_classname;
extern const char *rspamd_map_classname;
extern const char *rspamd_mempool_classname;
extern const char *rspamd_mimepart_classname;
extern const char *rspamd_monitored_classname;
extern const char *rspamd_redis_classname;
extern const char *rspamd_regexp_classname;
extern const char *rspamd_resolver_classname;
extern const char *rspamd_rsa_privkey_classname;
extern const char *rspamd_rsa_pubkey_classname;
extern const char *rspamd_rsa_signature_classname;
extern const char *rspamd_session_classname;
extern const char *rspamd_spf_record_classname;
extern const char *rspamd_sqlite3_stmt_classname;
extern const char *rspamd_sqlite3_classname;
extern const char *rspamd_statfile_classname;
extern const char *rspamd_task_classname;
extern const char *rspamd_tcp_sync_classname;
extern const char *rspamd_tcp_classname;
extern const char *rspamd_tensor_classname;
extern const char *rspamd_textpart_classname;
extern const char *rspamd_text_classname;
extern const char *rspamd_trie_classname;
extern const char *rspamd_upstream_list_classname;
extern const char *rspamd_upstream_classname;
extern const char *rspamd_url_classname;
extern const char *rspamd_worker_classname;
extern const char *rspamd_zstd_compress_classname;
extern const char *rspamd_zstd_decompress_classname;

#endif//RSPAMD_LUA_CLASSNAMES_H
