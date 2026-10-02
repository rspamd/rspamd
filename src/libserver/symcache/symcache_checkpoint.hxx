/*
 * Copyright 2026 Vsevolod Stakhov
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 */
#ifndef RSPAMD_SYMCACHE_CHECKPOINT_HXX
#define RSPAMD_SYMCACHE_CHECKPOINT_HXX

#include "symcache_internal.hxx"
#include "symcache_checkpoint.h"
#include "libutil/cxx/ucl_util.hxx"

struct rspamd_symbol_result;
namespace rspamd::symcache {
struct cache_item;
class symcache;

using checkpoint_ucl_ptr = rspamd::ucl::owning_object;

/* Lazily allocated per task. Ordinary scans do not allocate a journal. */
class checkpoint_store {
	struct check {
		checkpoint_ucl_ptr data;
		bool complete = false;
		bool valid = true;
		ankerl::unordered_dense::map<const rspamd_symbol_result *, unsigned int> insertions;
	};
	ankerl::unordered_dense::map<std::string, check> checks;
	ankerl::unordered_dense::map<std::string, checkpoint_ucl_ptr> facts;
	ankerl::unordered_dense::set<std::string> replayed;
	bool imported = false;
	bool valid = true;
	unsigned int insertion_depth = 0;
	std::size_t bytes = 0;
	std::size_t operations = 0;

	auto current(struct rspamd_task *task) -> check *;
	auto reserve(std::size_t size) -> bool;

public:
	static constexpr std::size_t max_bytes = 64 * 1024;
	static constexpr std::size_t max_operations = 1024;
	static constexpr std::size_t max_checks = 128;
	static auto get(struct rspamd_task *task, bool create = false) -> checkpoint_store *;
	auto has_import() const -> bool
	{
		return imported;
	}

	auto start(const cache_item &item) -> void;
	auto finish(const cache_item &item) -> void;
	/* A non-portable write poisons the currently executing check only; a write
	 * that cannot be attributed to a check discards the whole journal. */
	auto invalidate(struct rspamd_task *task) -> void;

	auto discard(const cache_item &item) -> void;
	auto insert_begin(struct rspamd_task *task, const char *symbol, double weight,
					  const char *option, unsigned int flags, struct rspamd_scan_result *result) -> void;
	auto insert_end(struct rspamd_task *task, struct rspamd_symbol_result *result) -> void;
	auto add_option(struct rspamd_task *task, struct rspamd_symbol_result *result,
					const char *option, std::size_t len) -> void;
	auto set_fact(struct rspamd_task *task, const char *key, const ucl_object_t *value) -> bool;
	auto get_fact(const char *producer, const char *key) const -> const ucl_object_t *;
	auto export_record(struct rspamd_task *task, const char *binding) const -> ucl_object_t *;
	auto import_record(struct rspamd_task *task, const ucl_object_t *record, const char *binding) -> bool;
	auto replay(struct rspamd_task *task, const cache_item &item) -> bool;
};
}// namespace rspamd::symcache
#endif
