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

namespace detail {

class ref_cnt {
public:
	using refcount_t = int;

	constexpr auto add_shared() -> refcount_t {
		return ++ref_shared;
	}
	constexpr auto add_weak() -> refcount_t {
		return ++ref_weak;
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
	constexpr auto weak_count() const -> refcount_t {
		return ref_weak;
	}
	virtual ~ref_cnt() {}
	virtual void dispose() = 0;
private:
	refcount_t ref_weak = 0;
	refcount_t ref_shared = 1;
};

template <class T>
class obj_and_refcnt : public ref_cnt {
private:
	typedef typename std::aligned_storage<sizeof(T), std::alignment_of<T>::value>::type storage_type;
	storage_type storage;
	bool initialized;
	virtual void dispose() override {
		if (initialized) {
			T *p = reinterpret_cast<T *>(&storage);
			p->~T();
			initialized = false;
		}
	}
public:
	template <typename... Args>
	explicit obj_and_refcnt(Args&&... args) : initialized(true)
	{
		new(&storage) T(std::forward<Args>(args)...);
	}
	auto get(void) -> T* {
		if (initialized) {
			return reinterpret_cast<T *>(&storage);
		}

		return nullptr;
	}
	virtual ~obj_and_refcnt() = default;
};

template <class T, class D = typename std::default_delete<T>>
class ptr_and_refcnt : public ref_cnt {
private:
	T* ptr;
	D deleter;
	virtual void dispose() override {
		deleter(ptr);
		ptr = nullptr;
	}
public:
	explicit ptr_and_refcnt(T *_ptr, D &&d = std::default_delete<T>()) : ptr(_ptr),
			deleter(std::move(d)) {}
	virtual ~ptr_and_refcnt() = default;
};

}

template <class T> class local_weak_ptr;

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
	explicit local_shared_ptr(Y* p) : px(p), cnt(new detail::ptr_and_refcnt(p))
	{
	}

	// custom deleter
	template<class Y, class D, typename std::enable_if<
			std::is_convertible<Y*, element_type*>::value, bool>::type = true>
	explicit local_shared_ptr(Y* p, D &&d) : px(p), cnt(new detail::ptr_and_refcnt(p, std::forward<D>(d)))
	{
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
	template<class Y> explicit local_shared_ptr(const local_weak_ptr<Y>& r) : px(r.px), cnt(r.cnt) {
		if (cnt) {
			cnt->add_shared();
		}
	}
	local_shared_ptr(std::nullptr_t) : local_shared_ptr() { }

	~local_shared_ptr() {
		if (cnt) {
			if (cnt->release_shared() <= 0) {
				cnt->dispose();

				if (cnt->weak_count() == 0) {
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
	T *px; // contained pointer
	detail::ref_cnt *cnt;

	template<class _T, class ... Args>
	friend local_shared_ptr<_T> local_make_shared(Args && ... args);
	friend class local_weak_ptr<T>;
};

template<class T, class ... Args>
local_shared_ptr<T> local_make_shared(Args && ... args)
{
	local_shared_ptr<T> ptr;
	auto tmp_object = new detail::obj_and_refcnt<T>(std::forward<Args>(args)...);
	ptr.px = tmp_object->get();
	ptr.cnt = tmp_object;

	return ptr;
}

template<class T>
class local_weak_ptr
{
public:
	typedef T element_type;

	// constructors
	constexpr local_weak_ptr() noexcept : px(nullptr), cnt(nullptr) {}
	template<class Y, typename std::enable_if<
			std::is_convertible<Y*, element_type*>::value, bool>::type = true>
	local_weak_ptr(local_shared_ptr<Y> const& r) noexcept : px(r.px),cnt(r.cnt) {
		if (cnt) {
			cnt->add_weak();
		}
	}

	local_weak_ptr(local_weak_ptr const& r) noexcept : px(r.px),cnt(r.cnt) {
		if (cnt) {
			cnt->add_weak();
		}
	}
	local_weak_ptr(local_weak_ptr && r) noexcept : px(r.px), cnt(r.cnt) {
		r.px = nullptr;
		r.cnt = nullptr;
	}

	~local_weak_ptr()
	{
		if (cnt) {
			if (cnt->release_weak() <= 0 && cnt->shared_count() == 0) {
				delete cnt;
			}
		}
	}

	// assignment
	local_weak_ptr& operator=(local_weak_ptr const& r) noexcept {
		local_weak_ptr(r).swap(*this);
		return *this;
	}
	local_weak_ptr& operator=(local_shared_ptr<T> const& r) noexcept {
		local_weak_ptr(r).swap(*this);
		return *this;
	}

	template<class Y, typename std::enable_if<
			std::is_convertible<Y*, element_type*>::value, bool>::type = true>
	local_weak_ptr& operator=(local_weak_ptr<Y> const& r) noexcept {
		local_weak_ptr(r).swap(*this);
		return *this;
	}
	local_weak_ptr& operator=(local_weak_ptr&& r) noexcept {
		local_weak_ptr(std::move(r)).swap(*this);
		return *this;
	}

	// modifiers
	void swap(local_weak_ptr& r) noexcept {
		std::swap(this->cnt, r.cnt);
		std::swap(this->px, r.px);
	}
	void reset() noexcept {
		local_weak_ptr().swap(*this);
	}

	// observers
	long use_count() const noexcept {
		if (cnt) {
			return cnt->shared_count();
		}
		return 0;
	}
	bool expired() const noexcept {
		if (cnt) {
			return cnt->shared_count() == 0;
		}

		return true;
	}

	local_shared_ptr<T> lock() const noexcept {
		local_shared_ptr<T> tmp;
		tmp.cnt = cnt;

		if (cnt) {
			cnt->add_shared();
			tmp.px = px;
		}

		return tmp;
	}
private:
	element_type* px;
	detail::ref_cnt *cnt;
};


}

/* Hashing stuff */
namespace std {
template <class T>
struct hash<rspamd::local_shared_ptr<T>> {
	inline auto operator()(const rspamd::local_shared_ptr<T> &p) const -> auto {
		if (!p) {
			throw std::logic_error("no hash for dangling pointer");
		}
		return hash<T>()(*p.get());
	}
};
template <class T>
struct hash<rspamd::local_weak_ptr<T>> {
	inline auto operator()(const rspamd::local_weak_ptr<T> &p) const -> auto {
		if (!p) {
			throw std::logic_error("no hash for dangling pointer");
		}
		return hash<T>()(*p.get());
	}
};

template<class T>
inline void swap(rspamd::local_shared_ptr<T> &x, rspamd::local_shared_ptr<T> &y) noexcept
{
	x.swap(y);
}

template<class T>
inline void swap(rspamd::local_weak_ptr<T> &x, rspamd::local_weak_ptr<T> &y) noexcept
{
	x.swap(y);
}

}

#endif //RSPAMD_LOCAL_SHARED_PTR_HXX
