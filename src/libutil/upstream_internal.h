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

/*
 * Internal hooks into the upstream subsystem. NOT a public API — the
 * stability story is "tests and same-tree consumers only". The public
 * surface lives in upstream.h.
 */
#ifndef RSPAMD_UPSTREAM_INTERNAL_H
#define RSPAMD_UPSTREAM_INTERNAL_H

#include "config.h"
#include "upstream.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Plain-data view of one SRV target. Used both by the real DNS callback
 * (built from rdns_reply_entry) and the test entry point — keeping the
 * diff logic agnostic of the DNS client struct layout.
 */
struct rspamd_upstream_srv_entry {
	const char *target;
	uint16_t port;
	uint16_t weight;
	uint16_t priority;
};

/*
 * Apply a snapshot of SRV targets to a parent upstream:
 *   - new keys → create member upstream
 *   - existing keys → refresh weight/priority and re-resolve A/AAAA
 *   - keys present on parent but missing in `entries` → graceful drain
 *
 * Caller must own `parent` (refcount keeps it alive); the parent must
 * have been created with the SRV_RESOLVE flag (e.g. via
 * `rspamd_upstreams_add_upstream` with a "service=..." string).
 *
 * Tests use this to drive SRV expansion deterministically without DNS.
 */
void rspamd_upstream_srv_apply(struct upstream *parent,
							   const struct rspamd_upstream_srv_entry *entries,
							   size_t n);

/*
 * Force a freshly-created SRV member out of PENDING_RESOLVE into the
 * alive list with a single synthetic loopback address. Test-only:
 * production code never bypasses DNS like this. `ip_str` must be a
 * numeric IPv4 / IPv6 literal (parsed by rspamd_parse_inet_address).
 */
void rspamd_upstream_member_force_alive_for_test(struct upstream *member,
												 const char *ip_str);

/*
 * Return the first SRV parent placeholder in the list, or NULL if none.
 * Test-only: SRV parents are deliberately invisible to the public
 * iteration APIs (foreach, count) since they aren't selectable
 * upstreams. Tests need a way to reach the parent for srv_apply.
 */
struct upstream *rspamd_upstream_srv_test_get_parent(struct upstream_list *ups);

/*
 * Install an event loop on the context without going through
 * rspamd_upstreams_library_config (which requires a full rspamd_config).
 * Test-only: lets unit tests drive ev_now() and timer firing through the
 * libev fake-clock hook (see ev.h: ev_set_fake_time_cb).
 */
void rspamd_upstream_ctx_set_event_loop_for_test(struct upstream_ctx *ctx,
												 struct ev_loop *event_loop);

#ifdef __cplusplus
}
#endif

#endif /* RSPAMD_UPSTREAM_INTERNAL_H */
