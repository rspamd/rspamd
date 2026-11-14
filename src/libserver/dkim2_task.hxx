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
 * Helpers of the DKIM2 module that are shared by the verifier and the signer
 * and work on a task or with the crypto library
 */

#ifndef RSPAMD_DKIM2_TASK_HXX
#define RSPAMD_DKIM2_TASK_HXX
#pragma once

#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <openssl/evp.h>

#include "dkim2_util.hxx"

struct rspamd_task;

namespace rspamd::dkim2 {

/* Header and body digests of one message state for one hash algorithm */
struct message_digests_t {
	std::string hdr;
	std::string body;
};

/**
 * Compute the header and body hashes of a message (Sections 6.1 and 6.2);
 * nullopt if the crypto library fails
 */
auto hash_message(std::span<const raw_header_t> headers, std::string_view body,
				  const EVP_MD *md) -> std::optional<message_digests_t>;

/**
 * The header fields of the message of a task, read by the strict scanner
 */
auto message_headers(struct rspamd_task *task)
	-> tl::expected<std::vector<raw_header_t>, std::string>;

/**
 * The body of the message of a task, as it is on the wire
 */
auto message_body(struct rspamd_task *task) -> std::string_view;

/**
 * Lowercase ASCII form (A-labels) of a domain, nullopt if it has none
 */
auto domain_alabel(struct rspamd_task *task, std::string_view domain)
	-> std::optional<std::string>;

}// namespace rspamd::dkim2

#endif /* RSPAMD_DKIM2_TASK_HXX */
