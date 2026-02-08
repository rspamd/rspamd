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

#include "multipart_response.hxx"
#include "ottery.h"
#include "printf.h"
#include <cstdlib>
#include <cstring>

#ifdef SYS_ZSTD
#include "zstd.h"
#else
#include "contrib/zstd/zstd.h"
#endif

namespace rspamd::http {

multipart_response::multipart_response()
{
	/* Generate a random boundary using ottery CSPRNG */
	char buf[64];
	uint64_t rnd = ottery_rand_uint64();
	static unsigned int counter = 0;
	rspamd_snprintf(buf, sizeof(buf), "rspamd-v3-%016xL-%ud",
					rnd, counter++);
	boundary_ = buf;
}

void multipart_response::add_part(std::string name, std::string content_type,
								  std::string_view data, bool compress)
{
	parts_.push_back({std::move(name), std::move(content_type), data, compress});
}

auto multipart_response::serialize(void *zstream) const -> std::string
{
	std::string out;
	out.reserve(4096);

	for (const auto &part: parts_) {
		out.append("--");
		out.append(boundary_);
		out.append("\r\n");

		/* Content-Disposition */
		out.append("Content-Disposition: form-data; name=\"");
		out.append(part.name);
		out.append("\"\r\n");

		/* Content-Type */
		if (!part.content_type.empty()) {
			out.append("Content-Type: ");
			out.append(part.content_type);
			out.append("\r\n");
		}

		/* Compress if requested and zstream is available */
		if (part.compress && zstream && !part.data.empty()) {
			auto *cstream = static_cast<ZSTD_CStream *>(zstream);
			size_t bound = ZSTD_compressBound(part.data.size());
			std::string compressed(bound, '\0');

			ZSTD_inBuffer zin{};
			zin.src = part.data.data();
			zin.size = part.data.size();
			zin.pos = 0;

			ZSTD_outBuffer zout{};
			zout.dst = compressed.data();
			zout.size = compressed.size();
			zout.pos = 0;

			ZSTD_CCtx_reset(cstream, ZSTD_reset_session_only);

			bool ok = true;
			while (zin.pos < zin.size) {
				size_t r = ZSTD_compressStream2(cstream, &zout, &zin, ZSTD_e_continue);
				if (ZSTD_isError(r)) {
					ok = false;
					break;
				}
			}

			if (ok) {
				size_t r = ZSTD_compressStream2(cstream, &zout, &zin, ZSTD_e_end);
				if (ZSTD_isError(r)) {
					ok = false;
				}
			}

			if (ok) {
				compressed.resize(zout.pos);
				out.append("Content-Encoding: zstd\r\n");
				out.append("\r\n");
				out.append(compressed);
			}
			else {
				/* Fallback: write uncompressed */
				out.append("\r\n");
				out.append(part.data);
			}
		}
		else {
			out.append("\r\n");
			out.append(part.data);
		}

		out.append("\r\n");
	}

	/* Closing boundary */
	out.append("--");
	out.append(boundary_);
	out.append("--\r\n");

	return out;
}

void multipart_response::prepare_iov(void *zstream)
{
	body_iov_.clear();
	owned_headers_.clear();
	owned_compressed_.clear();
	body_total_len_ = 0;

	for (size_t idx = 0; idx < parts_.size(); idx++) {
		const auto &part = parts_[idx];

		/* Build part header string */
		std::string hdr;
		if (idx == 0) {
			hdr.append("--");
		}
		else {
			hdr.append("\r\n--");
		}
		hdr.append(boundary_);
		hdr.append("\r\n");
		hdr.append("Content-Disposition: form-data; name=\"");
		hdr.append(part.name);
		hdr.append("\"\r\n");
		if (!part.content_type.empty()) {
			hdr.append("Content-Type: ");
			hdr.append(part.content_type);
			hdr.append("\r\n");
		}

		/* Handle compression */
		bool compressed = false;
		if (part.compress && zstream && !part.data.empty()) {
			auto *cstream = static_cast<ZSTD_CStream *>(zstream);
			size_t bound = ZSTD_compressBound(part.data.size());
			std::string compressed_buf(bound, '\0');

			ZSTD_inBuffer zin{};
			zin.src = part.data.data();
			zin.size = part.data.size();
			zin.pos = 0;

			ZSTD_outBuffer zout{};
			zout.dst = compressed_buf.data();
			zout.size = compressed_buf.size();
			zout.pos = 0;

			ZSTD_CCtx_reset(cstream, ZSTD_reset_session_only);

			bool ok = true;
			while (zin.pos < zin.size) {
				size_t r = ZSTD_compressStream2(cstream, &zout, &zin, ZSTD_e_continue);
				if (ZSTD_isError(r)) {
					ok = false;
					break;
				}
			}

			if (ok) {
				size_t r = ZSTD_compressStream2(cstream, &zout, &zin, ZSTD_e_end);
				if (ZSTD_isError(r)) {
					ok = false;
				}
			}

			if (ok) {
				compressed_buf.resize(zout.pos);
				compressed = true;
				hdr.append("Content-Encoding: zstd\r\n");
				hdr.append("\r\n");
				owned_compressed_.push_back(std::move(compressed_buf));
			}
		}
		if (!compressed) {
			hdr.append("\r\n");
		}

		/* Store owned header, add iov for it */
		owned_headers_.push_back(std::move(hdr));
		body_iov_.push_back({
			const_cast<char *>(owned_headers_.back().data()),
			owned_headers_.back().size(),
		});
		body_total_len_ += owned_headers_.back().size();

		/* Add iov for data (compressed or original — zero-copy for original) */
		if (compressed) {
			const auto &comp = owned_compressed_.back();
			body_iov_.push_back({
				const_cast<char *>(comp.data()),
				comp.size(),
			});
			body_total_len_ += comp.size();
		}
		else if (!part.data.empty()) {
			body_iov_.push_back({
				const_cast<char *>(part.data.data()),
				part.data.size(),
			});
			body_total_len_ += part.data.size();
		}
	}

	/* Closing boundary: "\r\n--boundary--\r\n" */
	std::string trailer = "\r\n--" + boundary_ + "--\r\n";
	owned_headers_.push_back(std::move(trailer));
	body_iov_.push_back({
		const_cast<char *>(owned_headers_.back().data()),
		owned_headers_.back().size(),
	});
	body_total_len_ += owned_headers_.back().size();
}

auto multipart_response::content_type() const -> std::string
{
	return "multipart/mixed; boundary=\"" + boundary_ + "\"";
}

}// namespace rspamd::http


/*
 * C bridge implementation
 */

struct rspamd_multipart_response_c {
	rspamd::http::multipart_response resp;
	std::string cached_content_type;
};

extern "C" {

struct rspamd_multipart_response_c *
rspamd_multipart_response_new(void)
{
	return new rspamd_multipart_response_c();
}

void rspamd_multipart_response_add_part(
	struct rspamd_multipart_response_c *resp,
	const char *name,
	const char *content_type,
	const char *data, gsize len,
	gboolean compress)
{
	if (!resp) {
		return;
	}
	resp->resp.add_part(
		name ? name : "",
		content_type ? content_type : "",
		{data, len},
		compress != FALSE);
}

rspamd_fstring_t *
rspamd_multipart_response_serialize(
	struct rspamd_multipart_response_c *resp,
	void *zstream)
{
	if (!resp) {
		return nullptr;
	}
	auto serialized = resp->resp.serialize(zstream);
	return rspamd_fstring_new_init(serialized.data(), serialized.size());
}

void rspamd_multipart_response_prepare_iov(
	struct rspamd_multipart_response_c *resp,
	void *zstream)
{
	if (!resp) {
		return;
	}
	resp->resp.prepare_iov(zstream);
}

const struct iovec *
rspamd_multipart_response_body_iov(
	struct rspamd_multipart_response_c *resp,
	gsize *count,
	gsize *total_len)
{
	if (!resp) {
		if (count) *count = 0;
		if (total_len) *total_len = 0;
		return NULL;
	}
	if (count) *count = resp->resp.body_iov_count();
	if (total_len) *total_len = resp->resp.body_total_len();
	return resp->resp.body_iov();
}

const char *
rspamd_multipart_response_content_type(
	struct rspamd_multipart_response_c *resp)
{
	if (!resp) {
		return "multipart/mixed";
	}
	resp->cached_content_type = resp->resp.content_type();
	return resp->cached_content_type.c_str();
}

void rspamd_multipart_response_free(
	struct rspamd_multipart_response_c *resp)
{
	delete resp;
}

} /* extern "C" */
