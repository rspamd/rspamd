#ifndef RSPAMD_SPF_H
#define RSPAMD_SPF_H

#include "config.h"
#include "ref.h"

struct rspamd_task;
struct spf_resolved;

typedef void (*spf_cb_t)(struct spf_resolved *record, struct rspamd_task *task);

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

#define RSPAMD_SPF_FLAG_IPV6 (1 << 0)
#define RSPAMD_SPF_FLAG_IPV4 (1 << 1)
#define RSPAMD_SPF_FLAG_ANY (1 << 2)
#define RSPAMD_SPF_FLAG_PARSED (1 << 3)
#define RSPAMD_SPF_FLAG_VALID (1 << 4)
#define RSPAMD_SPF_FLAG_REFRENCE (1 << 5)

struct spf_addr {
	guchar addr6[sizeof (struct in6_addr)];
	guchar addr4[sizeof (struct in_addr)];
	union {
		struct {
			guint16 mask_v4;
			guint16 mask_v6;
		} dual;
		guint32 idx;
	} m;
	guint flags;
	spf_mech_t mech;
	gchar *spf_string;
};

struct spf_resolved {
	gchar *domain;
	guint ttl;
	GArray *elts; /* Flat list of struct spf_addr */
	ref_entry_t ref; /* Refcounting */
};


/*
 * Resolve spf record for specified task and call a callback after resolution fails/succeed
 */
gboolean resolve_spf (struct rspamd_task *task, spf_cb_t callback);

/*
 * Get a domain for spf for specified task
 */
const gchar * get_spf_domain (struct rspamd_task *task);


/*
 * Increase refcount
 */
struct spf_resolved * spf_record_ref (struct spf_resolved *rec);

/*
 * Decrease refcount
 */
void spf_record_unref (struct spf_resolved *rec);

#endif
