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
 * DKIM2 verification (draft-ietf-dkim-dkim2-spec-09)
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
#include "dkim.h"

#ifdef __cplusplus
extern "C" {
#endif

#define RSPAMD_DKIM2_SIGNHEADER "DKIM2-Signature"
#define RSPAMD_DKIM2_MIHEADER "Message-Instance"

/* Sanity limit for the number of hops in a DKIM2 chain */
#define RSPAMD_DKIM2_MAX_HOPS 50

struct rspamd_task;

/* Output states of a verification (Section 14.1 of the draft) */
enum rspamd_dkim2_result_code {
	RSPAMD_DKIM2_NONE = 0,  /* no DKIM2 headers found */
	RSPAMD_DKIM2_PASS,      /* a Fully Verified DKIM2 Message */
	RSPAMD_DKIM2_FAIL,      /* verified not to be one: hash, signature, custody... */
	RSPAMD_DKIM2_TEMPERROR, /* a DNS record could not be retrieved now */
	RSPAMD_DKIM2_PERMERROR, /* cannot be verified: malformed fields, no key, etc */
};

struct rspamd_dkim2_hop_result {
	const char *domain;      /* d= tag */
	const char *selector;    /* selector of the first signature, NULL if not checked */
	const char *fail_reason; /* NULL if the signatures of the hop are ok */
	unsigned int idx;        /* i= tag */
	/*
	 * RSPAMD_DKIM2_NONE means that the signatures were not checked: only the
	 * last hop is verified when the message has already failed other checks
	 */
	enum rspamd_dkim2_result_code rcode;
};

struct rspamd_dkim2_verify_result {
	enum rspamd_dkim2_result_code rcode; /* overall result */
	const char *fail_reason;             /* human-readable reason, NULL if ok */
	unsigned int nhops;
	const struct rspamd_dkim2_hop_result *hops; /* array of nhops elements */
	unsigned int ninstances;                    /* number of Message-Instance headers */
	/*
	 * Instances with verified hashes, counting from the latest backwards;
	 * older instances are recreated by applying the r= recipes. A message
	 * with unverified instances is never a pass.
	 */
	unsigned int verified_instances;
	/*
	 * The message is Provisionally Verified (Section 13.2): the latest
	 * signature and instance are valid and match the SMTP envelope, whatever
	 * the overall result is. Requires the envelope to be known and checked.
	 */
	bool provisional;
};

struct rspamd_dkim2_verify_params {
	unsigned int time_jitter; /* how far in the future t= can be, seconds, 0 = default (1 day) */
	unsigned int max_age;     /* max signature age in seconds, 0 = default (14 days) */
	/*
	 * What is known about the SMTP transaction, as told by the MTA and not
	 * guessed from the message: mf=/rt= of the last hop are matched against
	 * the envelope of the task for the halves that are known
	 */
	bool have_mail_from;
	bool have_rcpt;
};

typedef struct rspamd_dkim2_chain_s rspamd_dkim2_chain_t;

/**
 * Parse all Message-Instance and DKIM2-Signature headers of a task and
 * perform structural validation of the chain (consecutive m=/i= numbering,
 * mandatory tags etc); a structural error is a PERMERROR.
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
 * Verify a parsed DKIM2 chain: checks the hashes of all message instances
 * (recreating the older ones with recipes), the timestamps, the envelope
 * (optionally), the Chain of Custody and the From header fields, fetches
 * public keys and domain policies via DNS and verifies all hop signatures.
 * The callback may be called synchronously if no DNS requests could be
 * scheduled. A chain can be verified only once.
 * @return false if verification could not be started (callback is not called)
 */
bool rspamd_dkim2_chain_verify(rspamd_dkim2_chain_t *chain,
							   struct rspamd_task *task,
							   const struct rspamd_dkim2_verify_params *params,
							   rspamd_dkim2_verify_cb cb,
							   void *ud);

/**
 * Sign an original message, that is a message without DKIM2 header fields,
 * on behalf of its Originator: makes the m=1 Message-Instance and the i=1
 * DKIM2-Signature header fields. The SMTP envelope of the task is recorded
 * in the signature, so it has to be the one the message will be sent with.
 * The values are folded, allocated in the task pool and do not include the
 * field names.
 * @return false if the message cannot be signed, *err tells why
 */
bool rspamd_dkim2_sign(struct rspamd_task *task,
					   rspamd_dkim_sign_key_t *key,
					   const char *domain,
					   const char *selector,
					   const char **mi_out,
					   const char **sig_out,
					   GError **err);

#ifdef __cplusplus
}
#endif

#endif /* RSPAMD_DKIM2_H */
