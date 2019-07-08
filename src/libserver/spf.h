#ifndef RSPAMD_SPF_H
#define RSPAMD_SPF_H

#include "config.h"
#include "ref.h"
#include "addr.h"

#ifdef  __cplusplus
extern "C" {
#endif

struct rspamd_task;
struct spf_resolved;

typedef void (*spf_cb_t) (struct spf_resolved *record,
						  struct rspamd_task *task, gpointer cbdata);

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

#define RSPAMD_SPF_FLAG_IPV6 (1u << 0u)
#define RSPAMD_SPF_FLAG_IPV4 (1u << 1u)
#define RSPAMD_SPF_FLAG_PROCESSED (1u << 2u)
#define RSPAMD_SPF_FLAG_ANY (1u << 3u)
#define RSPAMD_SPF_FLAG_PARSED (1u << 4u)
#define RSPAMD_SPF_FLAG_INVALID (1u << 5u)
#define RSPAMD_SPF_FLAG_REFERENCE (1u << 6u)
#define RSPAMD_SPF_FLAG_REDIRECT (1u << 7u)
#define RSPAMD_SPF_FLAG_TEMPFAIL (1u << 8u)
#define RSPAMD_SPF_FLAG_NA (1u << 9u)
#define RSPAMD_SPF_FLAG_PERMFAIL (1u << 10u)
#define RSPAMD_SPF_FLAG_RESOLVED (1u << 11u)

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
	struct spf_addr *prev, *next;
};

struct spf_resolved {
	gchar *domain;
	guint ttl;
	gboolean temp_failed;
	gboolean na;
	gboolean perm_failed;
	guint64 digest;
	GArray *elts; /* Flat list of struct spf_addr */
	ref_entry_t ref; /* Refcounting */
};


/*
 * Resolve spf record for specified task and call a callback after resolution fails/succeed
 */
gboolean rspamd_spf_resolve (struct rspamd_task *task, spf_cb_t callback,
							 gpointer cbdata);

/*
 * Get a domain for spf for specified task
 */
const gchar *rspamd_spf_get_domain (struct rspamd_task *task);


/*
 * Increase refcount
 */
struct spf_resolved *spf_record_ref (struct spf_resolved *rec);

/*
 * Decrease refcount
 */
void spf_record_unref (struct spf_resolved *rec);

/**
 * Prints address + mask in a freshly allocated string (must be freed)
 * @param addr
 * @return
 */
gchar *spf_addr_mask_to_string (struct spf_addr *addr);

/**
 * Returns spf address that matches the specific task (or nil if not matched)
 * @param task
 * @param rec
 * @return
 */
struct spf_addr *spf_addr_match_task (struct rspamd_task *task,
									  struct spf_resolved *rec);

#ifdef  __cplusplus
}
#endif

#endif
