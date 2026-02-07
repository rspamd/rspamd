/*
 * Copyright 2025 Vsevolod Stakhov
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

#ifndef RSPAMD_MULTIPART_RESPONSE_HXX
#define RSPAMD_MULTIPART_RESPONSE_HXX

#include <string>
#include <string_view>
#include <vector>

namespace rspamd::http {

struct response_part {
	std::string name;
	std::string content_type;
	std::string_view data; /* Points to external buffer; caller must keep alive */
	bool compress = false;
};

class multipart_response {
public:
	multipart_response();

	void add_part(std::string name, std::string content_type,
				  std::string_view data, bool compress = false);

	/**
	 * Serialize the multipart response.
	 * @param zstream ZSTD compression stream (may be null if no compression needed)
	 * @return serialized body
	 */
	auto serialize(void *zstream = nullptr) const -> std::string;

	/**
	 * Get the Content-Type header value including boundary.
	 */
	auto content_type() const -> std::string;

	auto get_boundary() const -> std::string_view
	{
		return boundary_;
	}

private:
	std::string boundary_;
	std::vector<response_part> parts_;
};

}// namespace rspamd::http

/* C bridge - include the C-only header */
#include "multipart_response.h"

#endif// RSPAMD_MULTIPART_RESPONSE_HXX
