/*-
 * Copyright 2016 Vsevolod Stakhov
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

#ifndef RSPAMD_MEMPOOL_VARS_INTERNAL_H
#define RSPAMD_MEMPOOL_VARS_INTERNAL_H

/* Basic rspamd mempool variables names */
#define RSPAMD_MEMPOOL_AVG_WORDS_LEN "avg_words_len"
#define RSPAMD_MEMPOOL_SHORT_WORDS_CNT "short_words_cnt"
#define RSPAMD_MEMPOOL_HEADERS_HASH "headers_hash"
#define RSPAMD_MEMPOOL_MTA_TAG "MTA-Tag"
#define RSPAMD_MEMPOOL_MTA_NAME "MTA-Name"
#define RSPAMD_MEMPOOL_SPF_DOMAIN "spf_domain"
#define RSPAMD_MEMPOOL_SPF_RECORD "spf_record"
#define RSPAMD_MEMPOOL_PRINCIPAL_RECIPIENT "principal_recipient"
#define RSPAMD_MEMPOOL_PROFILE "profile"
#define RSPAMD_MEMPOOL_MILTER_REPLY "milter_reply"
#define RSPAMD_MEMPOOL_DKIM_SIGNATURE "dkim-signature"
#define RSPAMD_MEMPOOL_DMARC_CHECKS "dmarc_checks"
#define RSPAMD_MEMPOOL_DKIM_BH_CACHE "dkim_bh_cache"
#define RSPAMD_MEMPOOL_DKIM_CHECK_RESULTS "dkim_results"
#define RSPAMD_MEMPOOL_DKIM_SIGN_KEY "dkim_key"
#define RSPAMD_MEMPOOL_DKIM_SIGN_SELECTOR "dkim_selector"
#define RSPAMD_MEMPOOL_ARC_SIGN_KEY "arc_key"
#define RSPAMD_MEMPOOL_ARC_SIGN_SELECTOR "arc_selector"
#define RSPAMD_MEMPOOL_STAT_SIGNATURE "stat_signature"
#define RSPAMD_MEMPOOL_FUZZY_RESULT "fuzzy_hashes"
#define RSPAMD_MEMPOOL_SPAM_LEARNS "spam_learns"
#define RSPAMD_MEMPOOL_HAM_LEARNS "ham_learns"
#define RSPAMD_MEMPOOL_RE_MAPS_CACHE "re_maps_cache"

#endif
