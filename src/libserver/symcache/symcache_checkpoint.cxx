/*
 * Copyright 2026 Vsevolod Stakhov
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 */
#include "symcache_checkpoint.hxx"
#include "symcache_item.hxx"
#include "libserver/task.h"
#include "libserver/scan_finalization.h"
#include "libserver/multistage.h"
#include "libmime/scan_result.h"
#include <functional>

namespace rspamd::symcache {
namespace {
auto mutable_field(ucl_object_t *obj, const char *key) -> ucl_object_t *
{
	return const_cast<ucl_object_t *>(ucl_object_lookup(obj, key));
}

auto integer(const ucl_object_t *obj, std::int64_t min, std::int64_t max) -> bool
{
	return obj && ucl_object_type(obj) == UCL_INT && ucl_object_toint(obj) >= min && ucl_object_toint(obj) <= max;
}

auto cstring(const ucl_object_t *obj, std::size_t limit, bool empty = false) -> const char *
{
	if (!obj || ucl_object_type(obj) != UCL_STRING || obj->len > limit || (!empty && obj->len == 0)) {
		return nullptr;
	}

	auto *s = ucl_object_tostring(obj);
	return strlen(s) == obj->len ? s : nullptr;
}

/* Count before copying: reject duplicate keys, cycles, exotic UCL values,
 * non-finite numbers and oversized/deep values, including empty containers. */
auto measure(const ucl_object_t *obj, std::size_t &bytes, unsigned int &nodes, unsigned int depth = 0) -> bool
{
	if (!obj || obj->next || depth > 16 || ++nodes > 4096 || obj->keylen > 256 ||
		(obj->keylen && memchr(obj->key, '\0', obj->keylen))) {
		return false;
	}

	bytes += 32 + obj->keylen;

	switch (ucl_object_type(obj)) {
	case UCL_OBJECT:
	case UCL_ARRAY: {
		ucl_object_iter_t it = nullptr;
		const ucl_object_t *child;

		while ((child = ucl_object_iterate(obj, &it, true))) {
			if (!measure(child, bytes, nodes, depth + 1)) {
				return false;
			}
		}

		break;
	}

	case UCL_STRING:
		if (obj->len > checkpoint_store::max_bytes) {
			return false;
		}

		bytes += obj->len;
		break;
	case UCL_FLOAT:
		if (!std::isfinite(ucl_object_todouble(obj))) {
			return false;
		}

		break;
	case UCL_INT:
	case UCL_BOOLEAN:
	case UCL_NULL:
		break;
	default:
		return false;
	}

	return bytes <= checkpoint_store::max_bytes;
}

/* Copy only measured JSON values. libucl's general copier retains container
 * lengths before appending children and uses strdup for owned string values. */
auto copy_value(const ucl_object_t *obj) -> ucl_object_t *
{
	switch (ucl_object_type(obj)) {
	case UCL_OBJECT:
	case UCL_ARRAY: {
		auto *out = ucl_object_typed_new(ucl_object_type(obj));
		ucl_object_iter_t it = nullptr;
		const ucl_object_t *child;

		while ((child = ucl_object_iterate(obj, &it, true))) {
			if (ucl_object_type(obj) == UCL_ARRAY) {
				ucl_array_append(out, copy_value(child));
			}
			else {
				ucl_object_insert_key(out, copy_value(child), child->key, child->keylen, true);
			}
		}

		return out;
	}

	case UCL_STRING:
		return ucl_object_fromlstring(ucl_object_tostring(obj), obj->len);
	case UCL_INT:
		return ucl_object_fromint(ucl_object_toint(obj));
	case UCL_FLOAT:
		return ucl_object_fromdouble(ucl_object_todouble(obj));
	case UCL_BOOLEAN:
		return ucl_object_frombool(ucl_object_toboolean(obj));
	default:
		return ucl_object_typed_new(UCL_NULL);
	}
}

auto current_name(struct rspamd_task *task) -> const char *
{
	if (!task->symcache_runtime) {
		return nullptr;
	}

	auto *dyn = rspamd_symcache_get_cur_item(task);
	return dyn ? rspamd_symcache_dyn_item_name(task, dyn) : nullptr;
}

auto prerequisites(const cache_item &item, const symcache &cache, const std::function<bool(const cache_item &)> &test)
	-> bool
{
	for (const auto &[id, dep]: item.deps) {
		if (!dep.item) {
			return false;
		}

		auto *producer = cache.get_item_by_id(dep.item->id, true);

		if (!producer || !test(*producer)) {
			return false;
		}
	}

	return true;
}

auto validate_operations(const ucl_object_t *ops, std::size_t &total) -> bool
{
	if (!ops || ucl_object_type(ops) != UCL_ARRAY || (total += ops->len) > checkpoint_store::max_operations) {
		return false;
	}

	for (unsigned int i = 0; i < ops->len; i++) {
		auto *op = ucl_array_find_index(ops, i);

		if (ucl_object_type(op) != UCL_OBJECT) {
			return false;
		}

		auto *option = ucl_object_lookup(op, "option");

		if (auto *ref = ucl_object_lookup(op, "insert")) {
			if (op->len != 2 || !integer(ref, 0, std::int64_t(i) - 1) ||
				!ucl_object_lookup(ucl_array_find_index(ops, ucl_object_toint(ref)), "symbol") || !option ||
				ucl_object_type(option) != UCL_STRING) {
				return false;
			}
		}
		else {
			auto *weight = ucl_object_lookup(op, "weight");

			if (op->len != 5 || !cstring(ucl_object_lookup(op, "symbol"), 256) || !weight ||
				(ucl_object_type(weight) != UCL_FLOAT && ucl_object_type(weight) != UCL_INT) ||
				!std::isfinite(ucl_object_todouble(weight)) ||
				!integer(ucl_object_lookup(op, "flags"), 0,
						 RSPAMD_SYMBOL_INSERT_SINGLE | RSPAMD_SYMBOL_INSERT_ENFORCE) ||
				!integer(ucl_object_lookup(op, "target"), 0, 1) || !option ||
				(ucl_object_type(option) != UCL_NULL && !cstring(option, checkpoint_store::max_bytes, true))) {
				return false;
			}
		}
	}

	return true;
}
}// namespace

auto checkpoint_store::get(struct rspamd_task *task, bool create) -> checkpoint_store *
{
	if (!task->symcache_checkpoint && create) {
		task->symcache_checkpoint = new checkpoint_store;
		rspamd_mempool_add_destructor(
			task->task_pool,
			[](void *p) {
				delete static_cast<checkpoint_store *>(p);
			},
			task->symcache_checkpoint);
	}

	return static_cast<checkpoint_store *>(task->symcache_checkpoint);
}

auto checkpoint_store::reserve(std::size_t size) -> bool
{
	if (!valid || size > max_bytes - bytes || ++operations > max_operations) {
		valid = false;
		return false;
	}

	bytes += size;
	return true;
}

auto checkpoint_store::start(const cache_item &item) -> void
{
	if (!valid || imported || checks.size() >= max_checks || !reserve(item.symbol.size() + 256)) {
		valid = false;
		return;
	}

	check c;
	c.data.reset(ucl_object_typed_new(UCL_OBJECT));
	ucl_object_insert_key(c.data.get(), ucl_object_fromint(item.replay_version), "version", 0, true);
	ucl_object_insert_key(c.data.get(), ucl_object_fromint(item.effective_inputs), "inputs", 0, true);
	ucl_object_insert_key(c.data.get(), ucl_object_typed_new(UCL_ARRAY), "ops", 0, true);
	ucl_object_insert_key(c.data.get(), ucl_object_typed_new(UCL_OBJECT), "facts", 0, true);
	checks.emplace(item.symbol, std::move(c));
}

auto checkpoint_store::finish(const cache_item &item) -> void
{
	if (auto it = checks.find(item.symbol); it != checks.end()) {
		it->second.complete = true;
	}
}

auto checkpoint_store::discard(const cache_item &item) -> void
{
	if (auto it = checks.find(item.symbol); it != checks.end()) {
		it->second.valid = false;
	}
}

auto checkpoint_store::current(struct rspamd_task *task) -> check *
{
	if (!valid || imported) {
		return nullptr;
	}

	auto *name = current_name(task);

	if (!name) {
		/* An unowned asynchronous write makes attribution ambiguous. */
		valid = false;
		return nullptr;
	}

	auto it = checks.find(name);

	if (it == checks.end() || !it->second.valid) {
		return nullptr;
	}

	if (it->second.complete) {
		it->second.valid = false;
		return nullptr;
	}

	return &it->second;
}

auto checkpoint_store::insert_begin(struct rspamd_task *task, const char *symbol, double weight, const char *option,
									unsigned int flags, struct rspamd_scan_result *result) -> void
{
	if (insertion_depth++ != 0) {
		/* Reentrant result predicates are outside the pure producer contract. */
		valid = false;
		return;
	}

	auto *c = current(task);

	if (!c) {
		return;
	}

	if ((result && result->name) || !symbol || !*symbol || strlen(symbol) > 256 || !std::isfinite(weight) ||
		(flags & ~(RSPAMD_SYMBOL_INSERT_SINGLE | RSPAMD_SYMBOL_INSERT_ENFORCE))) {
		c->valid = false;
		return;
	}

	if (!reserve(256 + strlen(symbol) + (option ? strlen(option) : 0))) {
		return;
	}

	auto *op = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(op, ucl_object_fromstring(symbol), "symbol", 0, true);
	ucl_object_insert_key(op, ucl_object_fromdouble(weight), "weight", 0, true);
	ucl_object_insert_key(op, ucl_object_fromint(flags), "flags", 0, true);
	ucl_object_insert_key(op, ucl_object_fromint(result ? 1 : 0), "target", 0, true);
	ucl_object_insert_key(op, option ? ucl_object_fromstring(option) : ucl_object_typed_new(UCL_NULL), "option", 0,
						  true);
	ucl_array_append(mutable_field(c->data.get(), "ops"), op);
}

auto checkpoint_store::insert_end(struct rspamd_task *task, struct rspamd_symbol_result *result) -> void
{
	if (insertion_depth == 0 || --insertion_depth != 0) {
		return;
	}

	if (auto *c = current(task)) {
		if (!result) {
			/* Lua only supplies subsequent options when insertion succeeds. We
			 * cannot recover those options when early settings suppressed it. */
			c->valid = false;
		}
		else {
			c->insertions[result] = ucl_object_lookup(c->data.get(), "ops")->len - 1;
		}
	}
}

auto checkpoint_store::add_option(struct rspamd_task *task, struct rspamd_symbol_result *result, const char *option,
								  std::size_t len) -> void
{
	if (insertion_depth != 0 || !result || !option) {
		return;
	}

	auto *c = current(task);

	if (!c) {
		return;
	}

	auto ref = c->insertions.find(result);

	if (ref == c->insertions.end()) {
		c->valid = false;
		return;
	}

	if (len > max_bytes || !reserve(128 + len)) {
		valid = false;
		return;
	}

	auto *op = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(op, ucl_object_fromint(ref->second), "insert", 0, true);
	ucl_object_insert_key(op, ucl_object_fromlstring(option, len), "option", 0, true);
	ucl_array_append(mutable_field(c->data.get(), "ops"), op);
}

auto checkpoint_store::set_fact(struct rspamd_task *task, const char *key, const ucl_object_t *value) -> bool
{
	auto *name = current_name(task);

	if (!name || !key || !*key || strlen(key) > 256 || !value) {
		valid = false;
		return false;
	}

	auto &live = facts[name];

	if (!live) {
		live.reset(ucl_object_typed_new(UCL_OBJECT));
	}

	if (!rspamd_symcache_is_checkpoint(task)) {
		/* An ordinary scan only lends the value to dependents: nothing measures,
		 * journals or exports it, so a reference replaces the deep copies. */
		ucl_object_replace_key(live.get(), ucl_object_ref(const_cast<ucl_object_t *>(value)), key, 0, true);
		return true;
	}

	std::size_t size = 0;
	unsigned int nodes = 0;

	if (!measure(value, size, nodes)) {
		/* An unportable value makes this producer run again at EOM; the other
		 * checks keep their records. */
		invalidate(task);
		return false;
	}

	if (!reserve(size + strlen(key))) {
		return false;
	}

	ucl_object_replace_key(live.get(), copy_value(value), key, 0, true);

	if (auto *c = current(task)) {
		ucl_object_replace_key(mutable_field(c->data.get(), "facts"), copy_value(value), key, 0, true);
	}

	return true;
}

auto checkpoint_store::invalidate(struct rspamd_task *task) -> void
{
	if (!valid || imported) {
		return;
	}

	auto *name = current_name(task);

	if (!name) {
		/* An unowned write cannot be attributed to a check: nothing is portable */
		valid = false;
		return;
	}

	if (auto it = checks.find(name); it != checks.end()) {
		it->second.valid = false;
	}
	/* A producer without a journal entry was never portable, so there is
	 * nothing to poison: its EOM run repeats the write. */
}

auto checkpoint_store::get_fact(const char *producer, const char *key) const -> const ucl_object_t *
{
	auto it = facts.find(producer);
	return it != facts.end() ? ucl_object_lookup(it->second.get(), key) : nullptr;
}

auto checkpoint_store::export_record(struct rspamd_task *task, const char *binding) const -> ucl_object_t *
{
	if (!valid || imported || insertion_depth != 0) {
		return nullptr;
	}

	auto &cache = *reinterpret_cast<symcache *>(task->cfg->cache);
	ankerl::unordered_dense::map<std::string, bool> eligible;
	std::function<bool(const cache_item &)> visit = [&](const cache_item &item) {
		if (auto it = eligible.find(item.symbol); it != eligible.end()) {
			return it->second;
		}

		eligible[item.symbol] = false;
		auto it = checks.find(item.symbol);

		if (it == checks.end() || !it->second.complete || !it->second.valid || !prerequisites(item, cache, visit)) {
			return false;
		}

		eligible[item.symbol] = true;
		return true;
	};
	checkpoint_ucl_ptr record{ucl_object_typed_new(UCL_OBJECT)};
	ucl_object_insert_key(record.get(), ucl_object_fromint(1), "format", 0, true);
	ucl_object_insert_key(record.get(), ucl_object_fromstring(binding), "binding", 0, true);
	ucl_object_insert_key(record.get(), ucl_object_fromstring(task->cfg->checksum ? task->cfg->checksum : ""),
						  "configuration", 0, true);
	auto *out = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(record.get(), out, "checks", 0, true);

	for (const auto &[name, c]: checks) {
		auto *item = cache.get_item_by_name(name, false);

		if (item && visit(*item)) {
			ucl_object_insert_key(out, copy_value(c.data.get()), name.c_str(), 0, true);
		}
	}

	if (out->len == 0) {
		/* Nothing portable survived: an empty record would only cost a replay */
		return nullptr;
	}

	std::size_t size = 0;
	unsigned int nodes = 0;
	return measure(record.get(), size, nodes) ? record.release() : nullptr;
}

auto checkpoint_store::import_record(struct rspamd_task *task, const ucl_object_t *record, const char *binding) -> bool
{
	std::size_t size = 0, nops = 0;
	unsigned int nodes = 0;

	if (!checks.empty() || !facts.empty() || imported || !measure(record, size, nodes) ||
		ucl_object_type(record) != UCL_OBJECT || record->len != 4 ||
		!integer(ucl_object_lookup(record, "format"), 1, 1)) {
		return false;
	}

	auto *record_binding = cstring(ucl_object_lookup(record, "binding"), 1024);
	auto *config = cstring(ucl_object_lookup(record, "configuration"), 1024, true);
	auto *entries = ucl_object_lookup(record, "checks");

	if (!record_binding || strcmp(binding, record_binding) != 0 || !config ||
		strcmp(config, task->cfg->checksum ? task->cfg->checksum : "") != 0 || !entries ||
		ucl_object_type(entries) != UCL_OBJECT || entries->len > max_checks) {
		return false;
	}

	auto &cache = *reinterpret_cast<symcache *>(task->cfg->cache);
	ucl_object_iter_t it = nullptr;
	const ucl_object_t *entry;

	while ((entry = ucl_object_iterate(entries, &it, true))) {
		auto *name = ucl_object_key(entry);

		if (!name || !*name || entry->keylen > 256 || strlen(name) != entry->keylen) {
			return false;
		}

		auto *item = cache.get_item_by_name(name, false);
		auto *stored_facts = ucl_object_lookup(entry, "facts");

		if (!item || item->is_virtual() || !item->replay_version ||
			(item->effective_inputs & RSPAMD_SYMCACHE_INPUT_EOM) || ucl_object_type(entry) != UCL_OBJECT ||
			entry->len != 4 ||
			!integer(ucl_object_lookup(entry, "version"), item->replay_version, item->replay_version) ||
			!integer(ucl_object_lookup(entry, "inputs"), item->effective_inputs, item->effective_inputs) ||
			!stored_facts || ucl_object_type(stored_facts) != UCL_OBJECT ||
			!validate_operations(ucl_object_lookup(entry, "ops"), nops) ||
			!prerequisites(*item, cache, [&](const cache_item &dep) {
				return ucl_object_lookup(entries, dep.symbol.c_str()) != nullptr;
			})) {
			return false;
		}
	}

	/* Commit only after validating every entry. Import never inserts results or
	 * marks dynamic items complete; the ordinary scheduler owns those steps. */
	it = nullptr;

	while ((entry = ucl_object_iterate(entries, &it, true))) {
		check c;
		c.data.reset(copy_value(entry));
		c.complete = true;
		checks.emplace(ucl_object_key(entry), std::move(c));
	}

	imported = true;
	bytes = size;
	return true;
}

auto checkpoint_store::replay(struct rspamd_task *task, const cache_item &item) -> bool
{
	if (!imported) {
		return false;
	}

	auto it = checks.find(item.symbol);

	if (it == checks.end()) {
		return false;
	}

	auto c = std::move(it->second);
	checks.erase(it); /* Consume once, including fallback after a changed prerequisite. */

	if (!prerequisites(item, *reinterpret_cast<symcache *>(task->cfg->cache), [&](const cache_item &dep) {
			return replayed.contains(dep.symbol);
		})) {
		rspamd_multistage_count(task->worker, RSPAMD_MULTISTAGE_PRODUCER_FALLBACK);
		return false;
	}

	auto *saved_facts = ucl_object_lookup(c.data.get(), "facts");

	/* Validate and restore explicitly exported state before inserting any
	 * results. Rejection consumes the record and runs the producer normally. */
	if (!item.restore_replay(task, saved_facts)) {
		rspamd_multistage_count(task->worker, RSPAMD_MULTISTAGE_PRODUCER_FALLBACK);
		return false;
	}

	auto *ops = ucl_object_lookup(c.data.get(), "ops");
	std::vector<rspamd_symbol_result *> inserted(ops->len, nullptr);

	for (unsigned int i = 0; i < ops->len; i++) {
		auto *op = ucl_array_find_index(ops, i);
		auto *option = ucl_object_lookup(op, "option");

		if (auto *ref = ucl_object_lookup(op, "insert")) {
			rspamd_task_add_result_option(task, inserted[ucl_object_toint(ref)], ucl_object_tostring(option),
										  option->len);
		}
		else {
			inserted[i] = rspamd_task_insert_result_full(
				task, ucl_object_tostring(ucl_object_lookup(op, "symbol")),
				ucl_object_todouble(ucl_object_lookup(op, "weight")),
				ucl_object_type(option) == UCL_NULL ? nullptr : ucl_object_tostring(option),
				static_cast<rspamd_symbol_insert_flags>(ucl_object_toint(ucl_object_lookup(op, "flags"))),
				ucl_object_toint(ucl_object_lookup(op, "target")) == 0 ? nullptr : task->result);
		}
	}

	facts[item.symbol].reset(copy_value(saved_facts));
	replayed.insert(item.symbol);
	rspamd_multistage_count(task->worker, RSPAMD_MULTISTAGE_PRODUCER_REPLAYED);
	return true;
}
}// namespace rspamd::symcache

using rspamd::symcache::checkpoint_store;

gboolean rspamd_symcache_is_checkpoint(struct rspamd_task *task)
{
	return task->symcache_runtime &&
		   static_cast<rspamd::symcache::symcache_runtime *>(task->symcache_runtime)->is_checkpoint();
}

ucl_object_t *rspamd_symcache_export_checkpoint(struct rspamd_task *task, const char *binding)
{
	if (!task || task->early_result || !binding || !*binding || strlen(binding) > 1024 || !task->s ||
		rspamd_session_blocked(task->s) || rspamd_session_events_pending(task->s) || task->err ||
		!task->symcache_runtime ||
		!static_cast<rspamd::symcache::symcache_runtime *>(task->symcache_runtime)->can_export_checkpoint()) {
		return nullptr;
	}

	return checkpoint_store::get(task, true)->export_record(task, binding);
}

gboolean rspamd_symcache_import_checkpoint(struct rspamd_task *task, const ucl_object_t *record, const char *binding)
{
	if (!task || !task->cfg || !task->cfg->cache || !binding || !*binding || strlen(binding) > 1024 ||
		task->processed_stages != 0 || !task->s || rspamd_session_blocked(task->s) ||
		rspamd_session_events_pending(task->s)) {
		return FALSE;
	}

	if (!task->symcache_runtime) {
		rspamd::symcache::symcache_runtime::create(task,
												   *reinterpret_cast<rspamd::symcache::symcache *>(task->cfg->cache));
	}

	if (!static_cast<rspamd::symcache::symcache_runtime *>(task->symcache_runtime)->can_import_checkpoint()) {
		return FALSE;
	}

	return checkpoint_store::get(task, true)->import_record(task, record, binding);
}

gboolean rspamd_symcache_set_check_fact(struct rspamd_task *task, const char *key, const ucl_object_t *value)
{
	return task && !task->early_result && checkpoint_store::get(task, true)->set_fact(task, key, value);
}

const ucl_object_t *rspamd_symcache_get_check_fact(struct rspamd_task *task, const char *producer, const char *key)
{
	auto *store = task ? checkpoint_store::get(task) : nullptr;
	return store && producer && key ? store->get_fact(producer, key) : nullptr;
}

void rspamd_symcache_checkpoint_insert_begin(struct rspamd_task *task, const char *symbol, double weight,
											 const char *option, unsigned int flags, struct rspamd_scan_result *result)
{
	if (auto *store = checkpoint_store::get(task); store && rspamd_symcache_is_checkpoint(task)) {
		store->insert_begin(task, symbol, weight, option, flags, result);
	}
}

void rspamd_symcache_checkpoint_insert_end(struct rspamd_task *task, struct rspamd_symbol_result *result)
{
	if (auto *store = checkpoint_store::get(task); store && rspamd_symcache_is_checkpoint(task)) {
		store->insert_end(task, result);
	}
}

void rspamd_symcache_checkpoint_option(struct rspamd_task *task, struct rspamd_symbol_result *result,
									   const char *option, gsize len)
{
	if (auto *store = checkpoint_store::get(task); store && rspamd_symcache_is_checkpoint(task)) {
		store->add_option(task, result, option, len);
	}
}

void rspamd_symcache_checkpoint_invalidate(struct rspamd_task *task)
{
	if (task->early_result) {
		rspamd_task_terminal_observer_error(task);
	}

	if (auto *store = checkpoint_store::get(task); store && rspamd_symcache_is_checkpoint(task)) {
		store->invalidate(task);
	}
}
