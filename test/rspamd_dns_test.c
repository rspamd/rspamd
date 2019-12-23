
#include "config.h"
#include "tests.h"
#include "dns.h"
#include "logger.h"
#include "rspamd.h"
#include "async_session.h"
#include "cfg_file.h"

static guint requests = 0;
extern struct ev_loop *event_loop;
struct rspamd_dns_resolver *resolver;

gboolean
session_fin (gpointer unused)
{
	ev_break (event_loop, EVBREAK_ALL);

	return TRUE;
}

static void
test_dns_cb (struct rdns_reply *reply, gpointer arg)
{
	struct rdns_reply_entry *cur;
	const struct rdns_request_name *name =
			rdns_request_get_name (reply->request, NULL);

	msg_debug ("got reply with code %s for request %s",
			rdns_strerror (reply->code), name->name);
	if (reply->code == RDNS_RC_NOERROR) {
		cur = reply->entries;
		while (cur) {
			switch (cur->type) {
			case RDNS_REQUEST_A:
				msg_debug ("got ip: %s", inet_ntoa (cur->content.a.addr));
				break;
			case RDNS_REQUEST_PTR:
				msg_debug ("got name %s", cur->content.ptr.name);
				break;
			case RDNS_REQUEST_TXT:
				msg_debug ("got txt %s", cur->content.txt.data);
				break;
			case RDNS_REQUEST_SPF:
				msg_debug ("got spf %s", cur->content.txt.data);
				break;
			case RDNS_REQUEST_SRV:
				msg_debug ("got srv pri: %d, weight: %d, port: %d, target: %s", cur->content.srv.weight,
						cur->content.srv.priority, cur->content.srv.port, cur->content.srv.target);
				break;
			case RDNS_REQUEST_MX:
				msg_debug ("got mx %s:%d", cur->content.mx.name, cur->content.mx.priority);
				break;
			}
			cur = cur->next;
		}
	}
	if (-- requests == 0) {
		session_fin (NULL);
	}
}

void
rspamd_dns_test_func ()
{

	struct rspamd_config *cfg;
	rspamd_mempool_t *pool;
	struct rspamd_async_session *s;

	cfg = (struct rspamd_config *)g_malloc (sizeof (struct rspamd_config));
	bzero (cfg, sizeof (struct rspamd_config));
	cfg->cfg_pool = rspamd_mempool_new (rspamd_mempool_suggest_size (), NULL, 0);
	cfg->dns_retransmits = 2;
	cfg->dns_timeout = 0.5;

	pool = rspamd_mempool_new (rspamd_mempool_suggest_size (), NULL, 0);

	s = rspamd_session_create (pool, session_fin, NULL, NULL, NULL);

	resolver = rspamd_dns_resolver_init (NULL, event_loop, cfg);

	requests ++;
	g_assert (rspamd_dns_resolver_request (resolver, s, pool, test_dns_cb, NULL, RDNS_REQUEST_A, "google.com"));
	requests ++;
	g_assert (rspamd_dns_resolver_request (resolver, s, pool, test_dns_cb, NULL, RDNS_REQUEST_PTR, "81.19.70.3"));
	requests ++;
	g_assert (rspamd_dns_resolver_request (resolver, s, pool, test_dns_cb, NULL, RDNS_REQUEST_MX, "rambler.ru"));
	requests ++;
	g_assert (rspamd_dns_resolver_request (resolver, s, pool, test_dns_cb, NULL, RDNS_REQUEST_TXT, "rambler.ru"));
	requests ++;
	g_assert (rspamd_dns_resolver_request (resolver, s, pool, test_dns_cb, NULL, RDNS_REQUEST_TXT, "google.com"));
	requests ++;
	g_assert (rspamd_dns_resolver_request (resolver, s, pool, test_dns_cb, NULL, RDNS_REQUEST_SPF, "rambler.ru"));
	requests ++;
	g_assert (rspamd_dns_resolver_request (resolver, s, pool, test_dns_cb, NULL, RDNS_REQUEST_SRV,
			"_xmpp-server._tcp.jabber.org"));
	requests ++;
	g_assert (rspamd_dns_resolver_request (resolver, s, pool, test_dns_cb, NULL, RDNS_REQUEST_TXT, "non-existent.arpa"));

	g_assert (resolver != NULL);

	ev_run (event_loop, 0);
}
