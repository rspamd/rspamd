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

#ifndef RSPAMD_LOCAL_SHARED_PTR_HXX
#define RSPAMD_LOCAL_SHARED_PTR_HXX

#pragma once

#include <memory>
#include <algorithm> // for std::swap
#include <cstddef> // for std::size_t
#include <functional> // for std::less

/*
 * Smart pointers with no atomic refcounts to speed up Rspamd which is
 * apparently single threaded
 */
namespace rspamd {

template <class T>
class local_weak_ptr {
	typedef T element_type;

};

template <class T>
class local_shared_ptr {
public:
	typedef T element_type;
	typedef local_weak_ptr<T> weak_type;

	// Simplified comparing to libc++, no custom deleter and no rebind here
	// constructors:
	constexpr local_shared_ptr() noexcept : px(nullptr), cnt(nullptr) {}

	template<class Y, typename std::enable_if<
	        std::is_convertible<Y*, element_type*>::value, bool>::type = true>
	explicit local_shared_ptr(Y* p) : px(p), cnt(new local_shared_ptr::control) {
		cnt->add_shared();
	}

	local_shared_ptr(const local_shared_ptr& r) noexcept : px(r.px), cnt(r.cnt) {
		if (cnt) {
			cnt->add_shared();
		}
	}
	local_shared_ptr(local_shared_ptr&& r) noexcept : px(r.px), cnt(r.cnt) {
		r.px = nullptr;
		r.cnt = nullptr;
	}
	template<class Y> explicit local_shared_ptr(const local_weak_ptr<Y>& r);
	local_shared_ptr(nullptr_t) : local_shared_ptr() { }

	~local_shared_ptr() {
		if (cnt) {
			if (cnt->release_shared() <= 0) {
				delete px;
				px = nullptr;

				if (cnt->release_weak() <= 0) {
					delete cnt;
				}
			}
		}
	}

	// assignment:
	local_shared_ptr& operator=(const local_shared_ptr& r) noexcept {
		local_shared_ptr(r).swap(*this);
		return *this;
	}
	local_shared_ptr& operator=(local_shared_ptr&& r) noexcept {
		local_shared_ptr(std::move(r)).swap(*this);
		return *this;
	}

	// Mutators
	void swap(local_shared_ptr& r) noexcept {
		std::swap(this->cnt, r.cnt);
		std::swap(this->px, r.px);
	}
	void reset() noexcept {
		local_shared_ptr().swap(*this);
	}

	// Observers:
	T* get() const noexcept {
		return px;
	}

	T& operator*() const noexcept {
		return *px;
	}
	T* operator->() const noexcept {
		return px;
	}
	long use_count() const noexcept {
		if (cnt) {
			return cnt->shared_count();
		}

		return 0;
	}
	bool unique() const noexcept {
		return use_count() == 1;
	}

	explicit operator bool() const noexcept {
		return px != nullptr;
	}

	template<class Y, typename std::enable_if<
			std::is_convertible<Y*, element_type*>::value, bool>::type = true>
	auto operator ==(const local_shared_ptr<Y> &other) const -> bool {
		return px == other.px;
	}

	template<class Y, typename std::enable_if<
			std::is_convertible<Y*, element_type*>::value, bool>::type = true>
	auto operator <(const local_shared_ptr<Y> &other) const -> auto {
		return *px < *other.px;
	}

private:
	class control {
	public:
		using refcount_t = int;

		constexpr auto add_shared() -> refcount_t {
			return ++ref_shared;
		}
		constexpr auto release_shared() -> refcount_t {
			return --ref_shared;
		}
		constexpr auto release_weak() -> refcount_t {
			return --ref_weak;
		}
		constexpr auto shared_count() const -> refcount_t {
			return ref_shared;
		}
	private:
		refcount_t ref_weak = 0;
		refcount_t ref_shared = 0;
	};

	T *px; // contained pointer
	control *cnt;
};

}

#endif //RSPAMD_LOCAL_SHARED_PTR_HXX
