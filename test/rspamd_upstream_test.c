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
#include "config.h"
#include "rspamd.h"
#include "ottery.h"
#include <math.h>

const char *test_upstream_list = "microsoft.com:443:1,google.com:80:2,kernel.org:443:3";
const char *new_upstream_list = "freebsd.org:80";
char test_key[32];

static void
rspamd_upstream_test_method (struct upstream_list *ls,
		enum rspamd_upstream_rotation rot, const gchar *expected)
{
	struct upstream *up;

	if (rot != RSPAMD_UPSTREAM_HASHED) {
		up = rspamd_upstream_get (ls, rot, NULL, 0);
		g_assert (up != NULL);
		g_assert (strcmp (rspamd_upstream_name (up), expected) == 0);
	}
	else {
		up = rspamd_upstream_get (ls, RSPAMD_UPSTREAM_HASHED, test_key,
					sizeof (test_key));
		g_assert (up != NULL);
		g_assert (strcmp (rspamd_upstream_name (up), expected) == 0);
	}
}

static void
rspamd_upstream_timeout_handler (int fd, short what, void *arg)
{
	struct rspamd_dns_resolver *resolver = (struct rspamd_dns_resolver *)arg;

	rdns_resolver_release (resolver->r);
}

void
rspamd_upstream_test_func (void)
{
	struct upstream_list *ls, *nls;
	struct upstream *up, *upn;
	struct event_base *ev_base = event_init ();
	struct rspamd_dns_resolver *resolver;
	struct rspamd_config *cfg;
	gint i, success = 0;
	const gint assumptions = 100500;
	gdouble p;
	struct event ev;
	struct timeval tv;
	rspamd_inet_addr_t *addr, *next_addr, *paddr;

	cfg = rspamd_config_new (RSPAMD_CONFIG_INIT_SKIP_LUA);
	cfg->dns_retransmits = 2;
	cfg->dns_timeout = 0.5;
	cfg->upstream_max_errors = 1;
	cfg->upstream_revive_time = 0.5;
	cfg->upstream_error_time = 2;

	resolver = dns_resolver_init (NULL, ev_base, cfg);
	rspamd_upstreams_library_config (cfg, cfg->ups_ctx, ev_base, resolver->r);

	/*
	 * Test v4/v6 priorities
	 */
	nls = rspamd_upstreams_create (cfg->ups_ctx);
	g_assert (rspamd_upstreams_add_upstream (nls, "127.0.0.1", 0,
			RSPAMD_UPSTREAM_PARSE_DEFAULT,
			NULL));
	up = rspamd_upstream_get (nls, RSPAMD_UPSTREAM_RANDOM, NULL, 0);
	rspamd_parse_inet_address (&paddr, "127.0.0.2", 0);
	g_assert (rspamd_upstream_add_addr (up, paddr));
	rspamd_parse_inet_address (&paddr, "::1", 0);
	g_assert (rspamd_upstream_add_addr (up, paddr));
	/* Rewind to start */
	addr = rspamd_upstream_addr_next (up);
	addr = rspamd_upstream_addr_next (up);
	/* cur should be zero here */
	addr = rspamd_upstream_addr_next (up);
	next_addr = rspamd_upstream_addr_next (up);
	g_assert (rspamd_inet_address_get_af (addr) == AF_INET);
	g_assert (rspamd_inet_address_get_af (next_addr) == AF_INET);
	next_addr = rspamd_upstream_addr_next (up);
	g_assert (rspamd_inet_address_get_af (next_addr) == AF_INET6);
	next_addr = rspamd_upstream_addr_next (up);
	g_assert (rspamd_inet_address_get_af (next_addr) == AF_INET);
	next_addr = rspamd_upstream_addr_next (up);
	g_assert (rspamd_inet_address_get_af (next_addr) == AF_INET);
	next_addr = rspamd_upstream_addr_next (up);
	g_assert (rspamd_inet_address_get_af (next_addr) == AF_INET6);
	/* Test errors with IPv6 */
	rspamd_upstream_fail (up, TRUE);
	/* Now we should have merely IPv4 addresses in rotation */
	addr = rspamd_upstream_addr_next (up);
	for (i = 0; i < 256; i++) {
		next_addr = rspamd_upstream_addr_next (up);
		g_assert (rspamd_inet_address_get_af (addr) == AF_INET);
		g_assert (rspamd_inet_address_get_af (next_addr) == AF_INET);
		g_assert (rspamd_inet_address_compare (addr, next_addr, FALSE) != 0);
		addr = next_addr;
	}
	rspamd_upstreams_destroy (nls);

	ls = rspamd_upstreams_create (cfg->ups_ctx);
	g_assert (rspamd_upstreams_parse_line (ls, test_upstream_list, 443, NULL));
	g_assert (rspamd_upstreams_count (ls) == 3);

	/* Test master-slave rotation */
	rspamd_upstream_test_method (ls, RSPAMD_UPSTREAM_MASTER_SLAVE, "kernel.org");
	rspamd_upstream_test_method (ls, RSPAMD_UPSTREAM_MASTER_SLAVE, "kernel.org");

	/* Test round-robin rotation */
	rspamd_upstream_test_method (ls, RSPAMD_UPSTREAM_ROUND_ROBIN, "kernel.org");
	rspamd_upstream_test_method (ls, RSPAMD_UPSTREAM_ROUND_ROBIN, "kernel.org");
	rspamd_upstream_test_method (ls, RSPAMD_UPSTREAM_ROUND_ROBIN, "google.com");
	rspamd_upstream_test_method (ls, RSPAMD_UPSTREAM_ROUND_ROBIN, "kernel.org");
	rspamd_upstream_test_method (ls, RSPAMD_UPSTREAM_ROUND_ROBIN, "google.com");
	rspamd_upstream_test_method (ls, RSPAMD_UPSTREAM_ROUND_ROBIN, "microsoft.com");

	/* Test stable hashing */
	nls = rspamd_upstreams_create (cfg->ups_ctx);
	g_assert (rspamd_upstreams_parse_line (nls, test_upstream_list, 443, NULL));
	g_assert (rspamd_upstreams_parse_line (nls, new_upstream_list, 443, NULL));
	for (i = 0; i < assumptions; i ++) {
		ottery_rand_bytes (test_key, sizeof (test_key));
		up = rspamd_upstream_get (ls, RSPAMD_UPSTREAM_HASHED, test_key,
			sizeof (test_key));
		upn = rspamd_upstream_get (nls, RSPAMD_UPSTREAM_HASHED, test_key,
			sizeof (test_key));

		if (strcmp (rspamd_upstream_name (up), rspamd_upstream_name (upn)) == 0) {
			success ++;
		}
	}

	p = 1.0 - fabs (3.0 / 4.0 - (gdouble)success / (gdouble)assumptions);
	/*
	 * P value is calculated as following:
	 * when we add/remove M upstreams from the list, the probability of hash
	 * miss should be close to the relation N / (N + M), where N is the size of
	 * the previous upstreams list.
	 */
	msg_debug ("p value for hash consistency: %.6f", p);
	g_assert (p > 0.9);

	rspamd_upstreams_destroy (nls);


	/* Upstream fail test */
	evtimer_set (&ev, rspamd_upstream_timeout_handler, resolver);
	event_base_set (ev_base, &ev);

	up = rspamd_upstream_get (ls, RSPAMD_UPSTREAM_MASTER_SLAVE, NULL, 0);
	for (i = 0; i < 100; i ++) {
		rspamd_upstream_fail (up, TRUE);
	}
	g_assert (rspamd_upstreams_alive (ls) == 2);

	tv.tv_sec = 2;
	tv.tv_usec = 0;
	event_add (&ev, &tv);

	event_base_loop (ev_base, 0);
	g_assert (rspamd_upstreams_alive (ls) == 3);

	rspamd_upstreams_destroy (ls);
	REF_RELEASE (cfg);
}
