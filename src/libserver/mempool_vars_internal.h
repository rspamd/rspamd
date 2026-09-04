/*
 * Copyright 2025 Vsevolod Stakhov
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
/*
 * Policy results published by the spf and dmarc modules so that other modules
 * do not have to reimplement them by matching the (configurable) symbol names.
 *
 * spf_result: none, pass, fail, softfail, neutral, permerror, temperror
 * dmarc_result: no_record, pass, fail_none, fail_quarantine, fail_reject,
 *               permerror, temperror
 *
 * Both are plain NUL terminated strings and are simply absent if the
 * corresponding check has not been performed.
 */
#define RSPAMD_MEMPOOL_SPF_RESULT "spf_result"
#define RSPAMD_MEMPOOL_DMARC_RESULT "dmarc_result"
/*
 * Set by the hfilter module to a gboolean telling whether the PTR name of the
 * sender matches one of its generic/dynamic naming patterns. Absent when
 * hfilter or its hostname checks are disabled, or when there is no PTR name.
 */
#define RSPAMD_MEMPOOL_HOSTNAME_GENERIC "hostname_generic"
#define RSPAMD_MEMPOOL_PRINCIPAL_RECIPIENT "principal_recipient"
#define RSPAMD_MEMPOOL_PROFILE "profile"
#define RSPAMD_MEMPOOL_MILTER_REPLY "milter_reply"
#define RSPAMD_MEMPOOL_DKIM_SIGNATURE "dkim-signature"
#define RSPAMD_MEMPOOL_DMARC_CHECKS "dmarc_checks"
#define RSPAMD_MEMPOOL_DKIM_BH_CACHE "dkim_bh_cache"
#define RSPAMD_MEMPOOL_DKIM_CHECK_RESULTS "dkim_results"
#define RSPAMD_MEMPOOL_DKIM_ALIGNMENT "dkim_alignment"
#define RSPAMD_MEMPOOL_DKIM_ALIGNMENT_TEMPFAIL "dkim_alignment_tempfail"
#define RSPAMD_MEMPOOL_DKIM_SIGN_KEY "dkim_key"
#define RSPAMD_MEMPOOL_DKIM_SIGN_SELECTOR "dkim_selector"
#define RSPAMD_MEMPOOL_ARC_SIGN_KEY "arc_key"
#define RSPAMD_MEMPOOL_ARC_SIGN_SELECTOR "arc_selector"
#define RSPAMD_MEMPOOL_STAT_SIGNATURE "stat_signature"
#define RSPAMD_MEMPOOL_FUZZY_RESULT "fuzzy_hashes"
#define RSPAMD_MEMPOOL_FUZZY_MATCHES "fuzzy_matches"
#define RSPAMD_MEMPOOL_FUZZY_CHECKED "fuzzy_checked"
#define RSPAMD_MEMPOOL_SPAM_LEARNS "spam_learns"
#define RSPAMD_MEMPOOL_HAM_LEARNS "ham_learns"
#define RSPAMD_MEMPOOL_RE_MAPS_CACHE "re_maps_cache"
#define RSPAMD_MEMPOOL_HTTP_STAT_BACKEND_RUNTIME "stat_http_runtime"
#define RSPAMD_MEMPOOL_FUZZY_STAT "fuzzy_stat"

#endif
