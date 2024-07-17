/*
 * Copyright 2024 Vsevolod Stakhov
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

#ifndef RSPAMD_SPF_H
#define RSPAMD_SPF_H

#include "config.h"
#include "ref.h"
#include "addr.h"

#ifdef __cplusplus
extern "C" {
#endif

struct rspamd_task;
struct spf_resolved;

typedef void (*spf_cb_t)(struct spf_resolved *record,
						 struct rspamd_task *task, gpointer cbdata);

typedef enum spf_mech_e {
	SPF_FAIL,
	SPF_SOFT_FAIL,
	SPF_PASS,
	SPF_NEUTRAL
} spf_mech_t;

static inline char spf_mech_char(spf_mech_t mech)
{
	switch (mech) {
	case SPF_FAIL:
		return '-';
	case SPF_SOFT_FAIL:
		return '~';
	case SPF_PASS:
		return '+';
	case SPF_NEUTRAL:
	default:
		return '?';
	}
}

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
#define RSPAMD_SPF_FLAG_CACHED (1u << 12u)
#define RSPAMD_SPF_FLAG_PLUSALL (1u << 13u)

/** Default SPF limits for avoiding abuse **/
#define SPF_MAX_NESTING 10
#define SPF_MAX_DNS_REQUESTS 30
#define SPF_MIN_CACHE_TTL (60 * 5) /* 5 minutes */

struct spf_addr {
	unsigned char addr6[sizeof(struct in6_addr)];
	unsigned char addr4[sizeof(struct in_addr)];
	union {
		struct {
			uint16_t mask_v4;
			uint16_t mask_v6;
		} dual;
		uint32_t idx;
	} m;
	unsigned int flags;
	spf_mech_t mech;
	char *spf_string;
	struct spf_addr *prev, *next;
};

enum rspamd_spf_resolved_flags {
	RSPAMD_SPF_RESOLVED_NORMAL = 0,
	RSPAMD_SPF_RESOLVED_TEMP_FAILED = (1u << 0u),
	RSPAMD_SPF_RESOLVED_PERM_FAILED = (1u << 1u),
	RSPAMD_SPF_RESOLVED_NA = (1u << 2u),
};

struct spf_resolved {
	char *domain;
	char *top_record;
	unsigned int ttl;
	int flags;
	double timestamp;
	uint64_t digest;
	GArray *elts;    /* Flat list of struct spf_addr */
	ref_entry_t ref; /* Refcounting */
};

struct rspamd_spf_cred {
	char *local_part;
	char *domain;
	char *sender;
};

/*
 * Resolve spf record for specified task and call a callback after resolution fails/succeed
 */
gboolean rspamd_spf_resolve(struct rspamd_task *task,
							spf_cb_t callback,
							gpointer cbdata,
							struct rspamd_spf_cred *cred);

/*
 * Get a domain for spf for specified task
 */
const char *rspamd_spf_get_domain(struct rspamd_task *task);

struct rspamd_spf_cred *rspamd_spf_get_cred(struct rspamd_task *task);
/*
 * Increase refcount
 */
struct spf_resolved *_spf_record_ref(struct spf_resolved *rec, const char *loc);
#define spf_record_ref(rec) \
	_spf_record_ref((rec), G_STRLOC)
/*
 * Decrease refcount
 */
void _spf_record_unref(struct spf_resolved *rec, const char *loc);
#define spf_record_unref(rec) \
	_spf_record_unref((rec), G_STRLOC)

/**
 * Prints address + mask in a freshly allocated string (must be freed)
 * @param addr
 * @return
 */
char *spf_addr_mask_to_string(struct spf_addr *addr);

/**
 * Returns spf address that matches the specific task (or nil if not matched)
 * @param task
 * @param rec
 * @return
 */
struct spf_addr *spf_addr_match_task(struct rspamd_task *task,
									 struct spf_resolved *rec);

void spf_library_config(const ucl_object_t *obj);

#ifdef __cplusplus
}
#endif

#endif
