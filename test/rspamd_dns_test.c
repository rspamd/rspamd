
#include "../src/config.h"
#include "tests.h"
#include "../src/dns.h"
#include "../src/logger.h"
#include "../src/events.h"
#include "../src/cfg_file.h"

static guint requests = 0;

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

void
session_fin (gpointer unused)
{
	struct timeval tv;

	tv.tv_sec = 0;
	tv.tv_usec = 0;
	event_loopexit (&tv);
}

void
rspamd_dns_test_func ()
{
	struct rspamd_dns_resolver *resolver;
	struct config_file *cfg;
	memory_pool_t *pool;
	struct rspamd_async_session *s;

	cfg = (struct config_file *)g_malloc (sizeof (struct config_file));
	bzero (cfg, sizeof (struct config_file));
	cfg->cfg_pool = memory_pool_new (memory_pool_get_size ());
	cfg->dns_retransmits = 10;
	cfg->dns_timeout = 1000;

	pool = memory_pool_new (memory_pool_get_size ());

	event_init ();
	s = new_async_session (pool, session_fin, NULL);

	resolver = dns_resolver_init (cfg);

	requests ++;
	g_assert (make_dns_request (resolver, s, pool, test_dns_cb, NULL, DNS_REQUEST_A, "google.com"));
	requests ++;
	g_assert (make_dns_request (resolver, s, pool, test_dns_cb, NULL, DNS_REQUEST_PTR, inet_addr ("81.19.70.3")));
	requests ++;
	g_assert (make_dns_request (resolver, s, pool, test_dns_cb, NULL, DNS_REQUEST_MX, "rambler.ru"));
	requests ++;
	g_assert (make_dns_request (resolver, s, pool, test_dns_cb, NULL, DNS_REQUEST_TXT, "rambler.ru"));
	requests ++;
	g_assert (make_dns_request (resolver, s, pool, test_dns_cb, NULL, DNS_REQUEST_SPF, "rambler.ru"));
	requests ++;
	g_assert (make_dns_request (resolver, s, pool, test_dns_cb, NULL, DNS_REQUEST_SRV, "xmpp-server", "tcp", "jabber.org"));
	requests ++;
	g_assert (make_dns_request (resolver, s, pool, test_dns_cb, NULL, DNS_REQUEST_TXT, "non-existent.arpa"));

	g_assert (resolver != NULL);



	event_loop (0);
}
