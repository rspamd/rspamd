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
#include <sys/uio.h>

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
	 * Prepare body as iovec segments for zero-copy writev.
	 * Boundary/header strings and compressed buffers are owned internally.
	 * Data pointers for uncompressed parts reference the original part.data.
	 * @param zstream ZSTD compression stream (may be null)
	 */
	void prepare_iov(void *zstream = nullptr);

	const struct iovec *body_iov() const
	{
		return body_iov_.data();
	}
	std::size_t body_iov_count() const
	{
		return body_iov_.size();
	}
	std::size_t body_total_len() const
	{
		return body_total_len_;
	}

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

	/* Iov support (populated by prepare_iov) */
	std::vector<struct iovec> body_iov_;
	std::vector<std::string> owned_headers_;    /* boundary+headers per part */
	std::vector<std::string> owned_compressed_; /* compressed data buffers */
	std::size_t body_total_len_ = 0;
};

}// namespace rspamd::http

/* C bridge - include the C-only header */
#include "multipart_response.h"

#endif// RSPAMD_MULTIPART_RESPONSE_HXX
