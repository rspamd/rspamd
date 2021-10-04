/*-
 * Copyright 2021 Vsevolod Stakhov
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


#ifndef RSPAMD_RECEIVED_H
#define RSPAMD_RECEIVED_H

#include "config.h"
#include "libutil/addr.h"

#ifdef  __cplusplus
extern "C" {
#endif
/*
 * C bindings for C++ received code
 */

enum rspamd_received_type {
	RSPAMD_RECEIVED_SMTP = 1u << 0u,
	RSPAMD_RECEIVED_ESMTP = 1u << 1u,
	RSPAMD_RECEIVED_ESMTPA = 1u << 2u,
	RSPAMD_RECEIVED_ESMTPS = 1u << 3u,
	RSPAMD_RECEIVED_ESMTPSA = 1u << 4u,
	RSPAMD_RECEIVED_LMTP = 1u << 5u,
	RSPAMD_RECEIVED_IMAP = 1u << 6u,
	RSPAMD_RECEIVED_LOCAL = 1u << 7u,
	RSPAMD_RECEIVED_HTTP = 1u << 8u,
	RSPAMD_RECEIVED_MAPI = 1u << 9u,
	RSPAMD_RECEIVED_UNKNOWN = 1u << 10u,
	RSPAMD_RECEIVED_FLAG_ARTIFICIAL = (1u << 11u),
	RSPAMD_RECEIVED_FLAG_SSL = (1u << 12u),
	RSPAMD_RECEIVED_FLAG_AUTHENTICATED = (1u << 13u),
};

#define RSPAMD_RECEIVED_FLAG_TYPE_MASK (RSPAMD_RECEIVED_SMTP| \
            RSPAMD_RECEIVED_ESMTP| \
            RSPAMD_RECEIVED_ESMTPA| \
            RSPAMD_RECEIVED_ESMTPS| \
            RSPAMD_RECEIVED_ESMTPSA| \
            RSPAMD_RECEIVED_LMTP| \
            RSPAMD_RECEIVED_IMAP| \
            RSPAMD_RECEIVED_LOCAL| \
            RSPAMD_RECEIVED_HTTP| \
            RSPAMD_RECEIVED_MAPI| \
            RSPAMD_RECEIVED_UNKNOWN)

struct rspamd_email_address;
struct rspamd_received_header_chain;
struct rspamd_mime_header;

/**
 * Parse received header from an input header data
 * @param task
 * @param data
 * @param sz
 * @param hdr
 * @return
 */
bool rspamd_received_header_parse(struct rspamd_task *task,
		const char *data, size_t sz, struct rspamd_mime_header *hdr);


/**
 * Process task data and the most top received and fix either part if needed
 * @param task
 * @return
 */
bool rspamd_received_maybe_fix_task(struct rspamd_task *task);

#ifdef  __cplusplus
}
#endif


#endif //RSPAMD_RECEIVED_H
