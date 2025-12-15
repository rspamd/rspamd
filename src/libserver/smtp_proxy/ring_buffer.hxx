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

#ifndef RSPAMD_RING_BUFFER_HXX
#define RSPAMD_RING_BUFFER_HXX

#pragma once

#include "config.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <algorithm>
#include <array>
#include <optional>
#include <string_view>
#include <utility>
#include <span>

#include <sys/uio.h>// for readv/writev

namespace rspamd::io {

/**
 * Fixed-capacity ring buffer for I/O operations with watermarks.
 */
template<std::size_t Capacity = 16384>
class ring_buffer {
public:
	static constexpr std::size_t capacity = Capacity;

	/**
	 * I/O operation result
	 */
	enum class io_result {
		ok,         // Operation completed successfully
		would_block,// EAGAIN/EWOULDBLOCK - try again later
		error,      // I/O error occurred
		eof,        // End of file/connection closed
		buffer_full,// No space left in buffer
		buffer_empty// No data available in buffer
	};

	ring_buffer() = default;
	~ring_buffer() = default;

	ring_buffer(const ring_buffer &) = delete;
	ring_buffer &operator=(const ring_buffer &) = delete;
	ring_buffer(ring_buffer &&) noexcept = default;
	ring_buffer &operator=(ring_buffer &&) noexcept = default;

	/**
	 * Set watermark thresholds for backpressure
	 * @param low Resume reading when bytes drop below this
	 * @param high Stop reading when bytes exceed this
	 */
	auto set_watermarks(std::size_t low, std::size_t high) noexcept -> void
	{
		low_watermark_ = low;
		high_watermark_ = high;
	}

	/**
	 * Check if buffer has reached high watermark
	 */
	[[nodiscard]] auto is_above_high_watermark() const noexcept -> bool
	{
		return size() >= high_watermark_;
	}

	/**
	 * Check if buffer has dropped below low watermark
	 */
	[[nodiscard]] auto is_below_low_watermark() const noexcept -> bool
	{
		return size() <= low_watermark_;
	}

	/**
	 * Current number of bytes in buffer
	 */
	[[nodiscard]] auto size() const noexcept -> std::size_t
	{
		return size_;
	}

	/**
	 * Available space for writing
	 */
	[[nodiscard]] auto available_space() const noexcept -> std::size_t
	{
		return capacity - size_;
	}

	/**
	 * Check if buffer is empty
	 */
	[[nodiscard]] auto empty() const noexcept -> bool
	{
		return size_ == 0;
	}

	/**
	 * Check if buffer is full
	 */
	[[nodiscard]] auto full() const noexcept -> bool
	{
		return size_ >= capacity;
	}

	/**
	 * Reset buffer to empty state
	 */
	auto reset() noexcept -> void
	{
		read_head_ = 0;
		write_head_ = 0;
		size_ = 0;
	}

	/**
	 * Read from file descriptor into buffer
	 * @param fd File descriptor to read from
	 * @return io_result indicating outcome
	 */
	auto read_from_fd(int fd) noexcept -> std::pair<io_result, std::size_t>
	{
		if (full()) {
			return {io_result::buffer_full, 0};
		}

		// Calculate contiguous write region
		auto [ptr1, len1, ptr2, len2] = get_write_regions();

		struct iovec iov[2];
		int iovcnt = 0;

		if (len1 > 0) {
			iov[iovcnt].iov_base = ptr1;
			iov[iovcnt].iov_len = len1;
			iovcnt++;
		}
		if (len2 > 0) {
			iov[iovcnt].iov_base = ptr2;
			iov[iovcnt].iov_len = len2;
			iovcnt++;
		}

		if (iovcnt == 0) {
			return {io_result::buffer_full, 0};
		}

		ssize_t n = ::readv(fd, iov, iovcnt);

		if (n < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				return {io_result::would_block, 0};
			}
			return {io_result::error, 0};
		}

		if (n == 0) {
			return {io_result::eof, 0};
		}

		advance_write(static_cast<std::size_t>(n));
		return {io_result::ok, static_cast<std::size_t>(n)};
	}

	/**
	 * Write from buffer to file descriptor
	 * @param fd File descriptor to write to
	 * @return io_result indicating outcome
	 */
	auto write_to_fd(int fd) noexcept -> std::pair<io_result, std::size_t>
	{
		if (empty()) {
			return {io_result::buffer_empty, 0};
		}

		// Calculate contiguous read region
		auto [ptr1, len1, ptr2, len2] = get_read_regions();

		struct iovec iov[2];
		int iovcnt = 0;

		if (len1 > 0) {
			iov[iovcnt].iov_base = const_cast<std::uint8_t *>(ptr1);
			iov[iovcnt].iov_len = len1;
			iovcnt++;
		}
		if (len2 > 0) {
			iov[iovcnt].iov_base = const_cast<std::uint8_t *>(ptr2);
			iov[iovcnt].iov_len = len2;
			iovcnt++;
		}

		if (iovcnt == 0) {
			return {io_result::buffer_empty, 0};
		}

		ssize_t n = ::writev(fd, iov, iovcnt);

		if (n < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				return {io_result::would_block, 0};
			}
			return {io_result::error, 0};
		}

		consume(static_cast<std::size_t>(n));
		return {io_result::ok, static_cast<std::size_t>(n)};
	}

	/**
	 * Copy data into the buffer
	 * @param data Pointer to data to copy
	 * @param len Length of data
	 * @return Number of bytes actually copied
	 */
	auto write(const void *data, std::size_t len) noexcept -> std::size_t
	{
		const auto *src = static_cast<const std::uint8_t *>(data);
		std::size_t to_write = std::min(len, available_space());
		std::size_t written = 0;

		while (written < to_write) {
			std::size_t chunk = std::min(to_write - written, capacity - write_head_);
			std::memcpy(&buffer_[write_head_], src + written, chunk);
			advance_write(chunk);
			written += chunk;
		}

		return written;
	}

	/**
	 * Copy data into the buffer from string_view
	 */
	auto write(std::string_view sv) noexcept -> std::size_t
	{
		return write(sv.data(), sv.size());
	}

	/**
	 * Get read regions as two spans (handles wrap-around)
	 * @return Tuple of (ptr1, len1, ptr2, len2)
	 */
	[[nodiscard]] auto get_read_regions() const noexcept
		-> std::tuple<const std::uint8_t *, std::size_t, const std::uint8_t *, std::size_t>
	{
		if (size_ == 0) {
			return {nullptr, 0, nullptr, 0};
		}

		std::size_t first_len = std::min(size_, capacity - read_head_);
		const std::uint8_t *first_ptr = &buffer_[read_head_];

		if (first_len < size_) {
			// Data wraps around
			return {first_ptr, first_len, &buffer_[0], size_ - first_len};
		}

		return {first_ptr, first_len, nullptr, 0};
	}

	/**
	 * Get write regions as two spans (handles wrap-around)
	 */
	[[nodiscard]] auto get_write_regions() noexcept
		-> std::tuple<std::uint8_t *, std::size_t, std::uint8_t *, std::size_t>
	{
		std::size_t avail = available_space();
		if (avail == 0) {
			return {nullptr, 0, nullptr, 0};
		}

		std::size_t first_len = std::min(avail, capacity - write_head_);
		std::uint8_t *first_ptr = &buffer_[write_head_];

		if (first_len < avail) {
			return {first_ptr, first_len, &buffer_[0], avail - first_len};
		}

		return {first_ptr, first_len, nullptr, 0};
	}

	/**
	 * Peek at buffer contents without consuming
	 * Copies data to linear output buffer
	 * @param out Output buffer
	 * @param max_len Maximum bytes to peek
	 * @return Number of bytes copied
	 */
	[[nodiscard]] auto peek(void *out, std::size_t max_len) const noexcept -> std::size_t
	{
		auto *dst = static_cast<std::uint8_t *>(out);
		std::size_t to_peek = std::min(max_len, size_);
		auto [ptr1, len1, ptr2, len2] = get_read_regions();

		std::size_t copied = 0;
		if (len1 > 0 && copied < to_peek) {
			std::size_t chunk = std::min(len1, to_peek - copied);
			std::memcpy(dst + copied, ptr1, chunk);
			copied += chunk;
		}
		if (len2 > 0 && copied < to_peek) {
			std::size_t chunk = std::min(len2, to_peek - copied);
			std::memcpy(dst + copied, ptr2, chunk);
			copied += chunk;
		}

		return copied;
	}

	/**
	 * Peek at a specific position without consuming
	 * @param offset Offset from read head
	 * @return Byte value or nullopt if out of range
	 */
	[[nodiscard]] auto peek_at(std::size_t offset) const noexcept -> std::optional<std::uint8_t>
	{
		if (offset >= size_) {
			return std::nullopt;
		}
		std::size_t pos = (read_head_ + offset) % capacity;
		return buffer_[pos];
	}

	/**
	 * Consume bytes from the buffer
	 * @param len Number of bytes to consume
	 */
	auto consume(std::size_t len) noexcept -> void
	{
		len = std::min(len, size_);
		read_head_ = (read_head_ + len) % capacity;
		size_ -= len;
	}

	/**
	 * Get pointer and length for contiguous data from read head
	 * Returns (ptr, len) for the first contiguous segment only.
	 * Use get_read_regions() if you need both segments of wrapped data.
	 */
	[[nodiscard]] auto get_contiguous_data() const noexcept -> std::pair<const std::uint8_t *, std::size_t>
	{
		if (size_ == 0) {
			return {nullptr, 0};
		}
		std::size_t first_len = std::min(size_, capacity - read_head_);
		return {&buffer_[read_head_], first_len};
	}

	/**
	 * Copy data from buffer to string_view (uses temporary storage)
	 * Note: The returned view is only valid until the next buffer modification
	 * @param len Maximum length to copy
	 * @return string_view of the data
	 */
	[[nodiscard]] auto peek_string(std::size_t len) const noexcept -> std::string_view
	{
		auto [ptr1, len1, ptr2, len2] = get_read_regions();

		// If data is contiguous, return direct view
		if (len <= len1) {
			return {reinterpret_cast<const char *>(ptr1), std::min(len, len1)};
		}

		// Data wraps - can't return contiguous view without copy
		// Return only the first segment for now
		return {reinterpret_cast<const char *>(ptr1), len1};
	}

	/**
	 * Advance write head after external write to write regions
	 * @param len Number of bytes written
	 */
	auto advance_write(std::size_t len) noexcept -> void
	{
		write_head_ = (write_head_ + len) % capacity;
		size_ += len;
	}

private:
	alignas(64) std::array<std::uint8_t, Capacity> buffer_{};
	std::size_t read_head_ = 0;
	std::size_t write_head_ = 0;
	std::size_t size_ = 0;
	std::size_t low_watermark_ = Capacity / 4;
	std::size_t high_watermark_ = Capacity * 3 / 4;
};

}// namespace rspamd::io

#endif// RSPAMD_RING_BUFFER_HXX
