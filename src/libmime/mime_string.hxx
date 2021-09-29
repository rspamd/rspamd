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
#ifndef RSPAMD_MIME_STRING_HXX
#define RSPAMD_MIME_STRING_HXX
#pragma once

#include <string>
#include <string_view>
#include <memory>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iosfwd>
#include "function2/function2.hpp"
#include "unicode/utf8.h"
#include "contrib/fastutf8/fastutf8.h"

namespace rspamd {
/*
 * The motivation for another string is to have utf8 valid string replacing
 * all bad things with FFFFD replacement character and filtering \0 and other
 * strange stuff defined by policies
 * This string always exclude \0 characters and ignore them! This is how MUA acts,
 * and we also store a flag about bad characters
 */
template<class T=char, class Allocator = std::allocator<T>> class basic_mime_string;

using mime_string = basic_mime_string<char>;

/* Helpers for type safe flags */
enum class mime_string_flags : std::uint8_t {
	MIME_STRING_DEFAULT = 0,
	MIME_STRING_SEEN_ZEROES = 0x1 << 0,
	MIME_STRING_SEEN_INVALID = 0x1 << 1,
};

mime_string_flags operator |(mime_string_flags lhs, mime_string_flags rhs)
{
	using ut = std::underlying_type<mime_string_flags>::type;
	return static_cast<mime_string_flags>(static_cast<ut>(lhs) | static_cast<ut>(rhs));
}

mime_string_flags operator &(mime_string_flags lhs, mime_string_flags rhs)
{
	using ut = std::underlying_type<mime_string_flags>::type;
	return static_cast<mime_string_flags>(static_cast<ut>(lhs) & static_cast<ut>(rhs));
}

bool operator !(mime_string_flags fl)
{
	return fl == mime_string_flags::MIME_STRING_DEFAULT;
}

template<class T, class Allocator>
class basic_mime_string : private Allocator {
public:
	using storage_type = std::basic_string<T, std::char_traits<T>, Allocator>;
	using view_type = std::basic_string_view<T, std::char_traits<T>>;
	using filter_type = fu2::function_view<UChar32 (UChar32)>;
	/* Ctors */
	basic_mime_string() noexcept : Allocator() {}
	explicit basic_mime_string(const Allocator& alloc) noexcept : Allocator(alloc) {}

	basic_mime_string(const T* str, std::size_t sz, const Allocator& alloc = Allocator()) noexcept :
			Allocator(alloc)
	{
		append_c_string_unfiltered(str, sz);
	}

	basic_mime_string(const storage_type &st,
					  const Allocator& alloc = Allocator()) noexcept :
			basic_mime_string(st.data(), st.size(), alloc) {}

	basic_mime_string(const view_type &st,
					  const Allocator& alloc = Allocator()) noexcept :
			basic_mime_string(st.data(), st.size(), alloc) {}

	/**
	 * Creates a string with a filter function. It is calee responsibility to
	 * ensure that the filter functor survives long enough to work with a string
	 * @param str
	 * @param sz
	 * @param filt
	 * @param alloc
	 */
	basic_mime_string(const T* str, std::size_t sz,
					  filter_type &&filt,
					  const Allocator& alloc = Allocator()) noexcept :
			Allocator(alloc),
			filter_func(std::forward<filter_type>(filt))
	{
		append_c_string_filtered(str, sz);
	}

	basic_mime_string(const storage_type &st,
					  filter_type &&filt,
					  const Allocator& alloc = Allocator()) noexcept :
			basic_mime_string(st.data(), st.size(), std::forward<filter_type>(filt), alloc) {}
	basic_mime_string(const view_type &st,
					  filter_type &&filt,
					  const Allocator& alloc = Allocator()) noexcept :
			basic_mime_string(st.data(), st.size(), std::forward<filter_type>(filt), alloc) {}

	auto size() const -> std::size_t {
		return storage.size();
	}

	auto data() const -> const T* {
		return storage.data();
	}

	constexpr auto has_zeroes() const -> bool {
		return !!(flags & mime_string_flags::MIME_STRING_SEEN_ZEROES);
	}

	constexpr auto has_invalid() const -> bool {
		return !!(flags & mime_string_flags::MIME_STRING_SEEN_INVALID);
	}

	/**
	 * Assign mime string from another string using move operation if a source string
	 * is utf8 valid.
	 * If this function returns false, then ownership has not been transferred
	 * and the `other` string is unmodified as well as the storage
	 * @param other
	 * @return
	 */
	[[nodiscard]] auto assign_if_valid(storage_type &&other) -> bool {
		if (filter_func) {
			/* No way */
			return false;
		}
		if (rspamd_fast_utf8_validate((const unsigned char *)other.data(), other.size()) == 0) {
			std::swap(storage, other);

			return true;
		}

		return false;
	}

	/**
	 * Copy to the internal storage discarding the contained value
	 * @param other
	 * @return
	 */
	auto assign_copy(const storage_type &other) {
		storage.clear();

		if (filter_func) {
			append_c_string_filtered(other.data(), other.size());
		}
		else {
			append_c_string_unfiltered(other.data(), other.size());
		}
	}

	auto append(const T* str, std::size_t size) -> std::size_t {
		if (filter_func) {
			return append_c_string_filtered(str, size);
		}
		else {
			return append_c_string_unfiltered(str, size);
		}
	}
	auto append(const storage_type &other) -> std::size_t {
		return append(other.data(), other.size());
	}
	auto append(const view_type &other) -> std::size_t {
		return append(other.data(), other.size());
	}

	auto operator ==(const basic_mime_string &other) {
		return other.storage == storage;
	}
	auto operator ==(const storage_type &other) {
		return other == storage;
	}
	auto operator ==(const view_type &other) {
		return other == storage;
	}
	auto operator ==(const T* other) {
		if (other == NULL) {
			return false;
		}
		auto olen = strlen(other);
		if (storage.size() == olen) {
			return memcmp(storage.data(), other, olen) == 0;
		}

		return false;
	}

	friend std::ostream& operator<< (std::ostream& os, const T& value) {
		os << value.storage;
		return os;
	}
private:
	mime_string_flags flags = mime_string_flags::MIME_STRING_DEFAULT;
	storage_type storage;
	filter_type filter_func;

	auto append_c_string_unfiltered(const T* str, std::size_t len) -> std::size_t {
		/* This is fast path */
		const auto *p = str;
		const auto *end = str + len;
		std::ptrdiff_t err_offset;
		auto orig_size = storage.size();

		storage.reserve(len + storage.size());

		if (memchr(str, 0, len) != NULL) {
			/* Fallback to slow path */
			flags = flags | mime_string_flags::MIME_STRING_SEEN_ZEROES;
			return append_c_string_filtered(str, len);
		}

		while (p < end && len > 0 &&
		        (err_offset = rspamd_fast_utf8_validate((const unsigned char *)p, len)) > 0) {
			auto cur_offset = err_offset - 1;
			storage.append(p, cur_offset);

			while (cur_offset < len) {
				auto tmp = cur_offset;
				UChar32 uc;

				U8_NEXT(p, cur_offset, len, uc);

				if (uc < 0) {
					storage.append("\uFFFD");
					flags = flags | mime_string_flags::MIME_STRING_SEEN_INVALID;
				}
				else {
					cur_offset = tmp;
					break;
				}
			}

			p += cur_offset;
			len = end - p;
		}

		storage.append(p, len);
		return storage.size() - orig_size;
	}

	auto append_c_string_filtered(const T* str, std::size_t len) -> std::size_t {
		std::ptrdiff_t i = 0, o = 0;
		UChar32 uc;
		char tmp[4];
		auto orig_size = storage.size();
		/* Slow path */

		storage.reserve(len + storage.size());

		while (i < len) {
			U8_NEXT(str, i, len, uc);

			if (uc < 0) {
				/* Replace with 0xFFFD */
				storage.append("\uFFFD");
				flags = flags | mime_string_flags::MIME_STRING_SEEN_INVALID;
			}
			else {
				if (filter_func) {
					uc = filter_func(uc);
				}

				if (uc == 0) {
					/* Special case, ignore it */
					flags = flags | mime_string_flags::MIME_STRING_SEEN_ZEROES;
				}
				else {
					o = 0;
					U8_APPEND_UNSAFE(tmp, o, uc);
					storage.append(tmp, o);
				}
			}
		}

		return storage.size() - orig_size;
	}
};

}

#endif //RSPAMD_MIME_STRING_HXX
