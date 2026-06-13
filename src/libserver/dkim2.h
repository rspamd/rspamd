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
 * DKIM2 verification (draft-ietf-dkim-dkim2-spec)
 *
 * DKIM2 is a separate protocol from DKIM (RFC 6376): signatures are computed
 * over the Message-Instance and DKIM2-Signature header fields only, while the
 * binding to the actual message content is indirect, via hashes stored in
 * Message-Instance headers. Hence this module shares no verification logic
 * with dkim.c; only the DNS key record handling is reused.
 */

#ifndef RSPAMD_DKIM2_H
#define RSPAMD_DKIM2_H

#include "config.h"
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RSPAMD_DKIM2_SIGNHEADER "DKIM2-Signature"
#define RSPAMD_DKIM2_MIHEADER "Message-Instance"

/* Sanity limit for the number of hops in a DKIM2 chain */
#define RSPAMD_DKIM2_MAX_HOPS 50

struct rspamd_task;

enum rspamd_dkim2_result_code {
	RSPAMD_DKIM2_NONE = 0, /* no DKIM2 headers found */
	RSPAMD_DKIM2_PASS,
	RSPAMD_DKIM2_FAIL,      /* hash or signature mismatch */
	RSPAMD_DKIM2_TEMPERROR, /* e.g. DNS temporary failure */
	RSPAMD_DKIM2_PERMERROR, /* malformed/missing fields, no key, etc */
};

struct rspamd_dkim2_hop_result {
	const char *domain;      /* d= tag */
	const char *selector;    /* selector of the first signature set */
	const char *fail_reason; /* NULL if hop is ok */
	unsigned int idx;        /* i= tag */
	enum rspamd_dkim2_result_code rcode;
};

struct rspamd_dkim2_verify_result {
	enum rspamd_dkim2_result_code rcode; /* overall result */
	const char *fail_reason;             /* NULL if ok */
	unsigned int nhops;
	const struct rspamd_dkim2_hop_result *hops; /* array of nhops elements */
	unsigned int ninstances;                    /* number of Message-Instance headers */
	/*
	 * Instances with verified hashes, counting from the latest backwards;
	 * older instances are verified by applying r= recipes within internal
	 * limits, so this can legitimately be less than ninstances
	 */
	unsigned int verified_instances;
};

struct rspamd_dkim2_verify_params {
	unsigned int time_jitter; /* allowed clock skew for future t= values, seconds */
	unsigned int max_age;     /* max signature age in seconds, 0 = default (14 days) */
	bool check_envelope;      /* match mf=/rt= of the last hop against SMTP envelope */
};

typedef struct rspamd_dkim2_chain_s rspamd_dkim2_chain_t;

/**
 * Parse all Message-Instance and DKIM2-Signature headers of a task and
 * perform structural validation of the chain (consecutive m=/i= numbering,
 * mandatory tags etc).
 * The returned object is allocated in the task pool and destroyed with it.
 * @return chain object or NULL; if NULL and *err is NULL, the message simply
 * has no DKIM2 headers; otherwise *err describes a permanent error
 */
rspamd_dkim2_chain_t *rspamd_dkim2_chain_parse(struct rspamd_task *task,
											   GError **err);

/**
 * Number of hops (DKIM2-Signature headers) in the chain
 */
unsigned int rspamd_dkim2_chain_len(const rspamd_dkim2_chain_t *chain);

typedef void (*rspamd_dkim2_verify_cb)(struct rspamd_task *task,
									   const struct rspamd_dkim2_verify_result *res,
									   void *ud);

/**
 * Verify a parsed DKIM2 chain: computes current message hashes, checks the
 * envelope (optionally), fetches public keys via DNS and verifies all hop
 * signatures. The callback may be called synchronously if no DNS requests
 * could be scheduled.
 * @return false if verification could not be started (callback is not called)
 */
bool rspamd_dkim2_chain_verify(rspamd_dkim2_chain_t *chain,
							   struct rspamd_task *task,
							   const struct rspamd_dkim2_verify_params *params,
							   rspamd_dkim2_verify_cb cb,
							   void *ud);

#ifdef __cplusplus
}
#endif

#endif /* RSPAMD_DKIM2_H */
