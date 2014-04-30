
#include "../src/config.h"
#include "tests.h"
#include "../src/dns.h"
#include "../src/logger.h"
#include "../src/main.h"
#include "../src/events.h"
#include "../src/cfg_file.h"

static guint requests = 0;
extern struct event_base *base;

static void
test_dns_cb (struct rspamd_dns_reply *reply, gpointer arg)
{
	union rspamd_reply_element *elt;
	GList *cur;

	msg_debug ("got reply with code %s for request %s", dns_strerror (reply->code), reply->request->requested_name);
	if (reply->code == DNS_RC_NOERROR) {
		cur = reply->elements;
		while (cur) {
			elt = cur->data;
			switch (reply->request->type) {
			case DNS_REQUEST_A:
				msg_debug ("got ip: %s", inet_ntoa (elt->a.addr[0]));
				break;
			case DNS_REQUEST_PTR:
				msg_debug ("got name %s", elt->ptr.name);
				break;
			case DNS_REQUEST_TXT:
				msg_debug ("got txt %s", elt->txt.data);
				break;
			case DNS_REQUEST_SPF:
				msg_debug ("got spf %s", elt->spf.data);
				break;
			case DNS_REQUEST_SRV:
				msg_debug ("got srv pri: %d, weight: %d, port: %d, target: %s", elt->srv.weight,
						elt->srv.priority, elt->srv.port, elt->srv.target);
				break;
			case DNS_REQUEST_MX:
				msg_debug ("got mx %s:%d", elt->mx.name, elt->mx.priority);
				break;
			}
			cur = g_list_next (cur);
		}
	}
	if (-- requests == 0) {
		destroy_session (reply->request->session);
	}
}

gboolean
session_fin (gpointer unused)
{
	struct timeval tv;

	tv.tv_sec = 0;
	tv.tv_usec = 0;
	event_loopexit (&tv);

	return TRUE;
}

void
rspamd_dns_test_func ()
{
	struct rspamd_dns_resolver *resolver;
	struct rspamd_config *cfg;
	rspamd_mempool_t *pool;
	struct rspamd_async_session *s;
	struct in_addr ina;

	cfg = (struct rspamd_config *)g_malloc (sizeof (struct rspamd_config));
	bzero (cfg, sizeof (struct rspamd_config));
	cfg->cfg_pool = rspamd_mempool_new (rspamd_mempool_suggest_size ());
	cfg->dns_retransmits = 10;
	cfg->dns_timeout = 1000;

	pool = rspamd_mempool_new (rspamd_mempool_suggest_size ());

	s = new_async_session (pool, session_fin, NULL, NULL, NULL);

	resolver = dns_resolver_init (base, cfg);

	ina.s_addr = inet_addr ("81.19.70.3");

	requests ++;
	g_assert (make_dns_request (resolver, s, pool, test_dns_cb, NULL, DNS_REQUEST_A, "google.com"));
	requests ++;
	g_assert (make_dns_request (resolver, s, pool, test_dns_cb, NULL, DNS_REQUEST_PTR, &ina));
	requests ++;
	g_assert (make_dns_request (resolver, s, pool, test_dns_cb, NULL, DNS_REQUEST_MX, "rambler.ru"));
	requests ++;
	g_assert (make_dns_request (resolver, s, pool, test_dns_cb, NULL, DNS_REQUEST_TXT, "rambler.ru"));
	requests ++;
	g_assert (make_dns_request (resolver, s, pool, test_dns_cb, NULL, DNS_REQUEST_TXT, "google.com"));
	requests ++;
	g_assert (make_dns_request (resolver, s, pool, test_dns_cb, NULL, DNS_REQUEST_SPF, "rambler.ru"));
	requests ++;
	g_assert (make_dns_request (resolver, s, pool, test_dns_cb, NULL, DNS_REQUEST_SRV, "xmpp-server", "tcp", "jabber.org"));
	requests ++;
	g_assert (make_dns_request (resolver, s, pool, test_dns_cb, NULL, DNS_REQUEST_TXT, "non-existent.arpa"));

	g_assert (resolver != NULL);



	event_loop (0);
}
