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
#include "libutil/mem_pool.h"
#include "function2/function2.hpp"
#include "unicode/utf8.h"
#include "contrib/fastutf8/fastutf8.h"

namespace rspamd::mime {
/*
 * The motivation for another string is to have utf8 valid string replacing
 * all bad things with FFFFD replacement character and filtering \0 and other
 * strange stuff defined by policies.
 * This string always exclude \0 characters and ignore them! This is how MUA acts,
 * and we also store a flag about bad characters.
 * Mime string iterators are always const, so the underlying storage should not
 * be modified externally.
 */
template<class T=char, class Allocator = std::allocator<T>,
		class Functor = fu2::function_view<UChar32(UChar32)>> class basic_mime_string;

using mime_string = basic_mime_string<char>;
using mime_pool_string = basic_mime_string<char, mempool_allocator<char>>;

/* Helpers for type safe flags */
enum class mime_string_flags : std::uint8_t {
	MIME_STRING_DEFAULT = 0,
	MIME_STRING_SEEN_ZEROES = 0x1 << 0,
	MIME_STRING_SEEN_INVALID = 0x1 << 1,
};

constexpr mime_string_flags operator |(mime_string_flags lhs, mime_string_flags rhs)
{
	using ut = std::underlying_type<mime_string_flags>::type;
	return static_cast<mime_string_flags>(static_cast<ut>(lhs) | static_cast<ut>(rhs));
}

constexpr mime_string_flags operator &(mime_string_flags lhs, mime_string_flags rhs)
{
	using ut = std::underlying_type<mime_string_flags>::type;
	return static_cast<mime_string_flags>(static_cast<ut>(lhs) & static_cast<ut>(rhs));
}

constexpr bool operator !(mime_string_flags fl)
{
	return fl == mime_string_flags::MIME_STRING_DEFAULT;
}

// Codepoint iterator base class
template<typename Container, bool Raw = false>
struct iterator_base
{
	template<typename, typename, typename>
	friend class basic_mime_string;

public:
	using value_type = typename Container::value_type;
	using difference_type = typename Container::difference_type;
	using codepoint_type = typename Container::codepoint_type;
	using reference_type = codepoint_type;
	using iterator_category = std::bidirectional_iterator_tag;

	bool operator==(const iterator_base &it) const noexcept
	{
		return idx == it.idx;
	}

	bool operator!=(const iterator_base &it) const noexcept
	{
		return idx != it.idx;
	}

	iterator_base(difference_type index, Container *instance) noexcept:
			idx(index), cont_instance(instance) {}
	iterator_base() noexcept = default;
	iterator_base(const iterator_base &) noexcept = default;

	iterator_base &operator=(const iterator_base &) noexcept = default;

	Container *get_instance() const noexcept
	{
		return cont_instance;
	}

	codepoint_type get_value() const noexcept {
		auto i = idx;
		codepoint_type uc;
		U8_NEXT_UNSAFE(cont_instance->data(), i, uc);
		return uc;
	}

protected:
	difference_type		idx;
	Container*			cont_instance = nullptr;
protected:
	void advance(difference_type n) noexcept {
		if (n > 0) {
			U8_FWD_N_UNSAFE(cont_instance->data(), idx, n);
		}
		else if (n < 0) {
			U8_BACK_N_UNSAFE(cont_instance->data(), idx, (-n));
		}
	}
	void increment() noexcept {
		codepoint_type uc;
		U8_NEXT_UNSAFE(cont_instance->data(), idx, uc);
	}

	void decrement() noexcept {
		codepoint_type uc;
		U8_PREV_UNSAFE(cont_instance->data(), idx, uc);
	}
};

// Partial spec for raw Byte-based iterator base
template<typename Container>
struct iterator_base<Container, true>
{
	template<typename, typename, typename>
	friend class basic_string;

public:
	using value_type = typename Container::value_type;
	using difference_type = typename Container::difference_type;
	using reference_type = value_type;
	using iterator_category = std::bidirectional_iterator_tag;

	bool operator==( const iterator_base& it ) const noexcept { return idx == it.idx; }
	bool operator!=( const iterator_base& it ) const noexcept { return idx != it.idx; }

	iterator_base(difference_type index, Container *instance) noexcept:
			idx(index), cont_instance(instance) {}

	iterator_base() noexcept = default;
	iterator_base( const iterator_base& ) noexcept = default;
	iterator_base& operator=( const iterator_base& ) noexcept = default;
	Container* get_instance() const noexcept { return cont_instance; }

	value_type get_value() const noexcept { return cont_instance->get_storage().at(idx); }
protected:
	difference_type		idx;
	Container*			cont_instance = nullptr;

protected:

	//! Advance the iterator n times (negative values allowed!)
	void advance( difference_type n ) noexcept {
		idx += n;
	}

	void increment() noexcept { idx ++; }
	void decrement() noexcept { idx --; }
};

template<typename Container, bool Raw> struct iterator;
template<typename Container, bool Raw> struct const_iterator;

template<typename Container, bool Raw = false>
struct iterator : iterator_base<Container, Raw> {
	iterator(typename iterator_base<Container, Raw>::difference_type index, Container *instance) noexcept:
			iterator_base<Container, Raw>(index, instance)
	{
	}
	iterator() noexcept = default;
	iterator(const iterator &) noexcept = default;

	iterator &operator=(const iterator &) noexcept = default;
	/* Disallow creating from const_iterator */
	iterator(const const_iterator<Container, Raw> &) = delete;

	/* Prefix */
	iterator &operator++() noexcept
	{
		this->increment();
		return *this;
	}

	/* Postfix */
	iterator operator++(int) noexcept
	{
		iterator tmp{this->idx, this->cont_instance};
		this->increment();
		return tmp;
	}

	/* Prefix */
	iterator &operator--() noexcept
	{
		this->decrement();
		return *this;
	}

	/* Postfix */
	iterator operator--(int) noexcept
	{
		iterator tmp{this->idx, this->cont_instance};
		this->decrement();
		return tmp;
	}

	iterator operator+(typename iterator_base<Container, Raw>::difference_type n) const noexcept
	{
		iterator it{*this};
		it.advance(n);
		return it;
	}

	iterator &operator+=(typename iterator_base<Container, Raw>::difference_type n) noexcept
	{
		this->advance(n);
		return *this;
	}

	iterator operator-(typename iterator_base<Container, Raw>::difference_type n) const noexcept
	{
		iterator it{*this};
		it.advance(-n);
		return it;
	}

	iterator &operator-=(typename iterator_base<Container, Raw>::difference_type n) noexcept
	{
		this->advance(-n);
		return *this;
	}

	typename iterator::reference_type operator*() const noexcept
	{
		return this->get_value();
	}
};

template<class CharT, class Allocator, class Functor>
class basic_mime_string : private Allocator {
public:
	using storage_type = std::basic_string<CharT, std::char_traits<CharT>, Allocator>;
	using view_type = std::basic_string_view<CharT, std::char_traits<CharT>>;
	using filter_type = Functor;
	using codepoint_type = UChar32;
	using value_type = CharT;
	using difference_type = std::ptrdiff_t;
	using iterator = rspamd::mime::iterator<basic_mime_string, false>;
	using raw_iterator = rspamd::mime::iterator<basic_mime_string, true>;
	/* Ctors */
	basic_mime_string() noexcept : Allocator() {}
	explicit basic_mime_string(const Allocator& alloc) noexcept : Allocator(alloc) {}
	explicit basic_mime_string(filter_type &&filt, const Allocator& alloc = Allocator()) noexcept :
		Allocator(alloc), filter_func(std::move(filt)) {}

	basic_mime_string(const CharT* str, std::size_t sz, const Allocator& alloc = Allocator()) noexcept :
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
	/* Explicit move ctor */
	basic_mime_string(basic_mime_string &&other) noexcept {
		*this = std::move(other);
	}


	/**
	 * Creates a string with a filter function. It is calee responsibility to
	 * ensure that the filter functor survives long enough to work with a string
	 * @param str
	 * @param sz
	 * @param filt
	 * @param alloc
	 */
	basic_mime_string(const CharT* str, std::size_t sz,
					  filter_type &&filt,
					  const Allocator& alloc = Allocator()) noexcept :
			Allocator(alloc),
			filter_func(std::move(filt))
	{
		append_c_string_filtered(str, sz);
	}

	basic_mime_string(const storage_type &st,
					  filter_type &&filt,
					  const Allocator& alloc = Allocator()) noexcept :
			basic_mime_string(st.data(), st.size(), std::move(filt), alloc) {}
	basic_mime_string(const view_type &st,
					  filter_type &&filt,
					  const Allocator& alloc = Allocator()) noexcept :
			basic_mime_string(st.data(), st.size(), std::move(filt), alloc) {}

	/* It seems some libc++ implementations still perform copy, this might fix them */
	basic_mime_string& operator=(basic_mime_string &&other) {
		storage = std::move(other.storage);
		filter_func = std::move(other.filter_func);

		return *this;
	}

	constexpr auto size() const noexcept -> std::size_t {
		return storage.size();
	}

	constexpr auto data() const noexcept -> const CharT* {
		return storage.data();
	}

	constexpr auto has_zeroes() const noexcept -> bool {
		return !!(flags & mime_string_flags::MIME_STRING_SEEN_ZEROES);
	}

	constexpr auto has_invalid() const noexcept -> bool {
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
	 auto assign_copy(const view_type &other) {
		storage.clear();

		if (filter_func) {
			append_c_string_filtered(other.data(), other.size());
		}
		else {
			append_c_string_unfiltered(other.data(), other.size());
		}
	}
	auto assign_copy(const storage_type &other) {
		storage.clear();

		if (filter_func) {
			append_c_string_filtered(other.data(), other.size());
		}
		else {
			append_c_string_unfiltered(other.data(), other.size());
		}
	}
	auto assign_copy(const basic_mime_string &other) {
		storage.clear();

		if (filter_func) {
			append_c_string_filtered(other.data(), other.size());
		}
		else {
			append_c_string_unfiltered(other.data(), other.size());
		}
	}

	/* Mutators */
	auto append(const CharT* str, std::size_t size) -> std::size_t {
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

	auto ltrim(const view_type &what) -> void
	{
		auto it = std::find_if(storage.begin(), storage.end(),
				[&what](CharT c) {
					return !std::any_of(what.begin(), what.end(), [&c](CharT sc) { return sc == c; });
				});
		storage.erase(storage.begin(), it);
	}

	auto rtrim(const view_type &what) -> void
	{
		auto it = std::find_if(storage.rbegin(), storage.rend(),
				[&what](CharT c) {
					return !std::any_of(what.begin(), what.end(), [&c](CharT sc) { return sc == c; });
				});
		storage.erase(it.base(), storage.end());
	}

	auto trim(const view_type &what) -> void {
		ltrim(what);
		rtrim(what);
	}

	/* Comparison */
	auto operator ==(const basic_mime_string &other) {
		return other.storage == storage;
	}
	auto operator ==(const storage_type &other) {
		return other == storage;
	}
	auto operator ==(const view_type &other) {
		return other == storage;
	}
	auto operator ==(const CharT* other) {
		if (other == NULL) {
			return false;
		}
		auto olen = strlen(other);
		if (storage.size() == olen) {
			return memcmp(storage.data(), other, olen) == 0;
		}

		return false;
	}

	/* Iterators */
	inline auto begin() noexcept -> iterator
	{
		return {0, this};
	}

	inline auto raw_begin() noexcept -> raw_iterator
	{
		return {0, this};
	}

	inline auto end() noexcept -> iterator
	{
		return {(difference_type) size(), this};
	}

	inline auto raw_end() noexcept -> raw_iterator
	{
		return {(difference_type) size(), this};
	}

	/* Utility */
	inline auto get_storage() const noexcept -> const storage_type &
	{
		return storage;
	}

	inline auto as_view() const noexcept -> view_type {
		return view_type{storage};
	}

	constexpr CharT operator[](std::size_t pos) const noexcept {
		return storage[pos];
	}
	constexpr CharT at(std::size_t pos) const {
		return storage.at(pos);
	}
	constexpr bool empty() const noexcept {
		return storage.empty();
	}


	/* For doctest stringify */
	friend std::ostream& operator<< (std::ostream& os, const CharT& value) {
		os << value.storage;
		return os;
	}
private:
	mime_string_flags flags = mime_string_flags::MIME_STRING_DEFAULT;
	storage_type storage;
	filter_type filter_func;

	auto append_c_string_unfiltered(const CharT* str, std::size_t len) -> std::size_t {
		/* This is fast path */
		const auto *p = str;
		const auto *end = str + len;
		std::int32_t err_offset; // We have to use int32_t here as old libicu is brain-damaged
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

	auto append_c_string_filtered(const CharT* str, std::size_t len) -> std::size_t {
		std::int32_t i = 0; // We have to use int32_t here as old libicu is brain-damaged
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
					std::int32_t o = 0;
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
