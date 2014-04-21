#ifndef RSPAMD_SPF_H
#define RSPAMD_SPF_H

#include "config.h"

struct rspamd_task;
struct spf_record;

typedef void (*spf_cb_t)(struct spf_record *record, struct rspamd_task *task);

typedef enum spf_mech_e {
	SPF_FAIL,
	SPF_SOFT_FAIL,
	SPF_PASS,
	SPF_NEUTRAL
} spf_mech_t;

typedef enum spf_action_e {
	SPF_RESOLVE_MX,
	SPF_RESOLVE_A,
	SPF_RESOLVE_PTR,
	SPF_RESOLVE_AAA,
	SPF_RESOLVE_REDIRECT,
	SPF_RESOLVE_INCLUDE,
	SPF_RESOLVE_EXISTS,
	SPF_RESOLVE_EXP
} spf_action_t;

struct spf_addr {
	union {
		struct {
			union {
				struct in_addr in4;
#ifdef HAVE_INET_PTON
				struct in6_addr in6;
#endif
			} d;
			guint32 mask;
			gboolean ipv6;
			gboolean parsed;
			gboolean addr_any;
		} normal;
		GList *list;
	} data;
	gboolean is_list;
	spf_mech_t mech;
	gchar *spf_string;
};

struct spf_record {
	gchar **elts;

	gchar *cur_elt;
	gint elt_num;
	gint nested;
	gint dns_requests;
	gint requests_inflight;

	guint ttl;

	GList *addrs;
	gchar *cur_domain;
	gchar *sender;
	gchar *sender_domain;
	gchar *local_part;
	struct rspamd_task *task;
	spf_cb_t callback;

	gboolean in_include;
};


/*
 * Resolve spf record for specified task and call a callback after resolution fails/succeed
 */
gboolean resolve_spf (struct rspamd_task *task, spf_cb_t callback);

/*
 * Get a domain for spf for specified task
 */
gchar *get_spf_domain (struct rspamd_task *task);


#endif
