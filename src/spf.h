#ifndef RSPAMD_SPF_H
#define RSPAMD_SPF_H

#include "config.h"

struct worker_task;
struct spf_record;

typedef void (*spf_cb_t)(struct spf_record *record, struct worker_task *task);

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
	SPF_RESOLVE_REDIRECT,
	SPF_RESOLVE_INCLUDE,
	SPF_RESOLVE_EXP
} spf_action_t;

struct spf_addr {
	uint32_t addr;
	uint32_t mask;
	spf_mech_t mech;
};

struct spf_record {
	char **elts;

	char **cur_elt;
	int nested;
	int dns_requests;

	GList *addrs;
	char *cur_domain;
	struct worker_task *task;
	spf_cb_t callback;
};


gboolean resolve_spf (struct worker_task *task, spf_cb_t callback);


#endif
