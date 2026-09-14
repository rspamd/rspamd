/*
 * Copyright 2026 Vsevolod Stakhov
 * Licensed under the Apache License, Version 2.0.
 */
#include "multistage.h"
#include "multipart_response.hxx"
#include "libutil/cxx/ucl_util.hxx"
#include "libutil/str_util.h"
#include "task.h"
#include "protocol.h"
#include "http/http_message.h"
#include "http/http_private.h"
#include "cryptobox.h"
#include "scan_finalization.h"
#include "symcache/symcache_checkpoint.h"
#include "lua/lua_common.h"
#include <algorithm>
#include <array>
#include <cmath>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace {
using rspamd::ucl::owning_object;
using string_ptr = std::unique_ptr<rspamd_fstring_t, decltype(&rspamd_fstring_free)>;

constexpr double max_age = 300.0;
constexpr double max_data_age = 30.0;
constexpr double default_timeout = 2.0;
constexpr double max_timeout = 30.0;
constexpr size_t signature_length = rspamd_cryptobox_HASHBYTES * 2;
constexpr size_t wire_prefix_length = signature_length + 1; /* Hex MAC and '.' */
constexpr unsigned int max_nodes = 16384;
constexpr unsigned int max_depth = 24;
constexpr size_t max_key_length = 256;

auto multistage_options(struct rspamd_config *cfg) -> const ucl_object_t *
{
	return cfg->cfg_ucl_obj ? ucl_object_lookup(cfg->cfg_ucl_obj, "multistage") : nullptr;
}

auto shared_key(struct rspamd_config *cfg) -> const ucl_object_t *
{
	auto *value = ucl_object_lookup(multistage_options(cfg), "key");

	if (!value || ucl_object_type(value) != UCL_STRING || value->len < 32 || value->len > 64) {
		return nullptr;
	}

	return value;
}

auto string_field(const ucl_object_t *obj, const char *name) -> const char *
{
	auto *value = ucl_object_lookup(obj, name);

	if (!value || ucl_object_type(value) != UCL_STRING || strlen(ucl_object_tostring(value)) != value->len) {
		return nullptr;
	}

	return ucl_object_tostring(value);
}

bool string_field_equals(const ucl_object_t *obj, const char *name, std::string_view expected)
{
	auto *value = ucl_object_lookup(obj, name);
	return value && ucl_object_type(value) == UCL_STRING &&
		   std::string_view{ucl_object_tostring(value), value->len} == expected;
}

auto smtp_reason(const ucl_object_t *obj) -> const char *
{
	auto *reason = string_field(obj, "reason");

	/* Leave room for "554 5.7.1 " and CRLF in a 512-byte SMTP reply. */
	if (!reason || !*reason || strlen(reason) > 500) {
		return nullptr;
	}

	for (auto *p = reason; *p; p++) {
		if (g_ascii_iscntrl(*p)) {
			return nullptr;
		}
	}

	return reason;
}

auto hex_digest(const unsigned char *data, size_t len) -> std::string
{
	std::string out(len * 2, '0');
	rspamd_encode_hex_buf(data, len, out.data(), out.size());

	return out;
}

auto compute_mac(struct rspamd_config *cfg, const char *kind, const char *data, size_t len) -> std::string
{
	rspamd_cryptobox_hash_state_t state;
	std::array<unsigned char, rspamd_cryptobox_HASHBYTES> digest;
	auto *secret = shared_key(cfg);
	rspamd_cryptobox_hash_init(&state, reinterpret_cast<const unsigned char *>(ucl_object_tostring(secret)),
							   secret->len);
	constexpr char domain[] = "rspamd-multistage-v1";
	rspamd_cryptobox_hash_update(&state, reinterpret_cast<const unsigned char *>(domain), sizeof(domain));
	rspamd_cryptobox_hash_update(&state, reinterpret_cast<const unsigned char *>(kind), strlen(kind) + 1);
	rspamd_cryptobox_hash_update(&state, reinterpret_cast<const unsigned char *>(data), len);
	rspamd_cryptobox_hash_final(&state, digest.data());
	return hex_digest(digest.data(), digest.size());
}

/* Canonical typed values: object keys sorted, array order preserved. */
bool hash_value(rspamd_cryptobox_hash_state_t *state, const ucl_object_t *obj, unsigned int &nodes, size_t &bytes,
				unsigned int depth = 0)
{
	if (++nodes > max_nodes || depth > max_depth) {
		return false;
	}

	auto feed = [&](const void *p, size_t len) {
		rspamd_cryptobox_hash_update(state, static_cast<const unsigned char *>(p), len);
	};
	unsigned char type = obj ? ucl_object_type(obj) : UCL_NULL;
	feed(&type, 1);

	if (type == UCL_OBJECT || type == UCL_ARRAY) {
		if (obj->len > max_nodes - nodes) {
			return false;
		}

		std::vector<const ucl_object_t *> values;
		ucl_object_iter_t it = nullptr;

		while (auto *value = ucl_object_iterate(obj, &it, true)) {
			values.push_back(value);
		}

		if (type == UCL_OBJECT) {
			std::sort(values.begin(), values.end(), [](auto *a, auto *b) {
				return strcmp(ucl_object_key(a), ucl_object_key(b)) < 0;
			});
		}

		for (auto *value: values) {
			if (type == UCL_OBJECT) {
				auto len = strlen(ucl_object_key(value)) + 1;

				if (len > max_key_length + 1 || (bytes += len) > RSPAMD_MULTISTAGE_MAX_WIRE) {
					return false;
				}

				feed(ucl_object_key(value), len);
			}

			if (!hash_value(state, value, nodes, bytes, depth + 1)) {
				return false;
			}
		}

		unsigned char end = 255;
		feed(&end, 1);
	}
	else if (type != UCL_NULL) {
		if (type == UCL_STRING && (bytes += obj->len) > RSPAMD_MULTISTAGE_MAX_WIRE) {
			return false;
		}

		size_t len;
		auto *json = ucl_object_emit_len(obj, UCL_EMIT_JSON_COMPACT, &len);
		feed(json, len);
		free(json);
		unsigned char end = 0;
		feed(&end, 1);
	}

	return true;
}

auto is_fresh(const ucl_object_t *obj) -> bool
{
	auto *issued = ucl_object_lookup(obj, "issued");

	if (!issued || (ucl_object_type(issued) != UCL_FLOAT && ucl_object_type(issued) != UCL_INT)) {
		return false;
	}

	auto age = ev_time() - ucl_object_todouble(issued);
	return std::isfinite(age) && age >= -5 && age <= max_age;
}
}// namespace

gboolean rspamd_multistage_enabled(struct rspamd_config *cfg)
{
	return shared_key(cfg) != nullptr;
}

gboolean rspamd_multistage_validate(struct rspamd_config *cfg)
{
	auto *opts = multistage_options(cfg);

	if (!opts) {
		return TRUE;
	}

	if (ucl_object_type(opts) != UCL_OBJECT || !shared_key(cfg)) {
		return FALSE;
	}

	if (auto *value = ucl_object_lookup(opts, "timeout")) {
		auto timeout = ucl_object_todouble(value);

		if ((ucl_object_type(value) != UCL_FLOAT && ucl_object_type(value) != UCL_INT &&
			 ucl_object_type(value) != UCL_TIME) ||
			!std::isfinite(timeout) || timeout <= 0 || timeout > max_timeout) {
			return FALSE;
		}
	}

	if (auto *policies = ucl_object_lookup(opts, "policies")) {
		if (ucl_object_type(policies) != UCL_ARRAY || policies->len > 128) {
			return FALSE;
		}

		ucl_object_iter_t it = nullptr;

		while (auto *policy = ucl_object_iterate(policies, &it, true)) {
			auto *name = string_field(policy, "name");
			auto *symbol = string_field(policy, "symbol");
			auto *action = string_field(policy, "action");
			auto *reason = smtp_reason(policy);

			if (!name || !*name || strlen(name) > 128 || !symbol || !*symbol || strlen(symbol) > 256 || !action ||
				(strcmp(action, "reject") != 0 && strcmp(action, "soft reject") != 0) || !reason) {
				return FALSE;
			}
		}
	}

	auto *L = RSPAMD_LUA_CFG_STATE(cfg);
	auto top = lua_gettop(L);

	if (cfg->multistage_policy_ref > 0) {
		luaL_unref(L, LUA_REGISTRYINDEX, cfg->multistage_policy_ref);
		cfg->multistage_policy_ref = 0;
	}

	if (!rspamd_lua_require_function(L, "lua_multistage_policy", "compile")) {
		msg_err_config("cannot load DATA policy compiler");
		lua_settop(L, top);
		return FALSE;
	}

	auto **pcfg = static_cast<struct rspamd_config **>(lua_newuserdata(L, sizeof(cfg)));
	*pcfg = cfg;
	rspamd_lua_setclass(L, rspamd_config_classname, -1);
	ucl_object_push_lua(L, opts, true);

	if (lua_pcall(L, 2, 2, 0) != 0 || !lua_isfunction(L, -2)) {
		msg_err_config("cannot compile DATA policies: %s", lua_tostring(L, -1));
		lua_settop(L, top);
		return FALSE;
	}

	lua_pop(L, 1);
	cfg->multistage_policy_ref = luaL_ref(L, LUA_REGISTRYINDEX);
	lua_settop(L, top);
	return TRUE;
}

double rspamd_multistage_timeout(struct rspamd_config *cfg)
{
	auto *value = ucl_object_lookup(multistage_options(cfg), "timeout");
	auto timeout = value ? ucl_object_todouble(value) : default_timeout;
	return std::isfinite(timeout) && timeout > 0 && timeout <= max_timeout ? timeout : default_timeout;
}

rspamd_fstring_t *rspamd_multistage_seal(struct rspamd_config *cfg, const char *kind, const ucl_object_t *payload)
{
	if (!shared_key(cfg)) {
		return nullptr;
	}

	size_t len;
	auto *json = ucl_object_emit_len(payload, UCL_EMIT_JSON_COMPACT, &len);

	if (len > RSPAMD_MULTISTAGE_MAX_WIRE - wire_prefix_length) {
		free(json);
		return nullptr;
	}

	auto signature = compute_mac(cfg, kind, reinterpret_cast<char *>(json), len);
	auto *out = rspamd_fstring_new_init(signature.data(), signature.size());
	out = rspamd_fstring_append(out, ".", 1);
	out = rspamd_fstring_append(out, reinterpret_cast<const char *>(json), len);
	free(json);
	return out;
}

ucl_object_t *rspamd_multistage_open(struct rspamd_config *cfg, const char *kind, const char *wire, gsize len)
{
	if (!shared_key(cfg) || !wire || len <= wire_prefix_length || len > RSPAMD_MULTISTAGE_MAX_WIRE ||
		wire[signature_length] != '.') {
		return nullptr;
	}

	auto *json = wire + wire_prefix_length;
	auto json_length = len - wire_prefix_length;
	auto signature = compute_mac(cfg, kind, json, json_length);

	if (rspamd_cryptobox_memcmp(wire, signature.data(), signature_length) != 0) {
		return nullptr;
	}

	auto *parser = ucl_parser_new(UCL_PARSER_SAFE_FLAGS);
	ucl_parser_limits limits{};
	limits.max_depth = max_depth;
	limits.max_nodes = max_nodes;
	limits.max_key_length = max_key_length;
	limits.max_string_length = RSPAMD_MULTISTAGE_MAX_WIRE;
	limits.max_alloc = 4 * 1024 * 1024;
	ucl_parser_set_limits(parser, &limits);
	ucl_object_t *out = nullptr;

	if (ucl_parser_add_chunk(parser, reinterpret_cast<const unsigned char *>(json), json_length)) {
		out = ucl_parser_get_object(parser);
	}

	ucl_parser_free(parser);

	if (out && (ucl_object_type(out) != UCL_OBJECT || ucl_object_toint(ucl_object_lookup(out, "version")) != 1 ||
				!is_fresh(out))) {
		ucl_object_unref(out);
		out = nullptr;
	}

	return out;
}

enum rspamd_multistage_decision rspamd_multistage_check_reply(struct rspamd_config *cfg, const char *wire, gsize len,
															  const char *id, const rspamd_fstring_t *binding,
															  rspamd_fstring_t **record, rspamd_fstring_t **reason)
{
	*record = nullptr;
	*reason = nullptr;
	owning_object reply{rspamd_multistage_open(cfg, "data-response", wire, len)};

	if (!reply || !binding || !string_field_equals(reply.get(), "id", id) ||
		!string_field_equals(reply.get(), "binding", {binding->str, binding->len})) {
		return RSPAMD_MULTISTAGE_CONTINUE;
	}

	auto reject = string_field_equals(reply.get(), "decision", "reject");
	auto tempfail = string_field_equals(reply.get(), "decision", "soft reject");

	if (reject || tempfail) {
		auto *terminal = ucl_object_lookup(reply.get(), "terminal");

		if (string_field_equals(terminal, "action", reject ? "reject" : "soft reject")) {
			if (auto *text = smtp_reason(terminal)) {
				*reason = rspamd_fstring_new_init(text, strlen(text));
			}
		}

		return reject ? RSPAMD_MULTISTAGE_REJECT : RSPAMD_MULTISTAGE_TEMPFAIL;
	}

	if (string_field_equals(reply.get(), "decision", "continue") && ucl_object_lookup(reply.get(), "record")) {
		*record = rspamd_fstring_new_init(wire, len);
	}

	return RSPAMD_MULTISTAGE_CONTINUE;
}

rspamd_fstring_t *rspamd_multistage_binding(const ucl_object_t *metadata, const char *id)
{
	rspamd_cryptobox_hash_state_t state;
	std::array<unsigned char, rspamd_cryptobox_HASHBYTES> digest;
	rspamd_cryptobox_hash_init(&state, nullptr, 0);
	rspamd_cryptobox_hash_update(&state, reinterpret_cast<const unsigned char *>(id), strlen(id) + 1);
	unsigned int nodes = 0;
	size_t bytes = 0;

	for (auto *name: {"from", "rcpt", "ip", "helo", "hostname", "user", "settings_id", "mail_esmtp_args",
					  "rcpt_esmtp_args", "headers", "tls", "mta", "queue_id"}) {
		if (!hash_value(&state, ucl_object_lookup(metadata, name), nodes, bytes)) {
			return nullptr;
		}
	}

	rspamd_cryptobox_hash_final(&state, digest.data());
	auto out = hex_digest(digest.data(), digest.size());
	return rspamd_fstring_new_init(out.data(), out.size());
}

struct rspamd_http_message *rspamd_multistage_data_request(struct rspamd_config *cfg, const ucl_object_t *metadata,
														   const char *id)
{
	owning_object payload{ucl_object_typed_new(UCL_OBJECT)};
	ucl_object_insert_key(payload.get(), ucl_object_fromint(1), "version", 0, true);
	ucl_object_insert_key(payload.get(), ucl_object_fromdouble(ev_time()), "issued", 0, true);
	ucl_object_insert_key(payload.get(), ucl_object_fromstring(id), "id", 0, true);
	ucl_object_insert_key(payload.get(), ucl_object_ref(metadata), "metadata", 0, true);
	auto *wire = rspamd_multistage_seal(cfg, "data-request", payload.get());

	if (!wire) {
		return nullptr;
	}

	auto *msg = rspamd_http_new_message(HTTP_REQUEST);
	msg->method = HTTP_POST;
	msg->url = rspamd_fstring_assign(msg->url, "/checkdata", 10);
	rspamd_http_message_set_body_from_fstring_steal(msg, wire);
	return msg;
}

gboolean rspamd_multistage_attach_record(struct rspamd_http_message *msg, ucl_object_t *metadata,
										 const rspamd_fstring_t *record)
{
	gsize len;
	auto *data = rspamd_http_message_get_body(msg, &len);

	if (!data || !len) {
		/* Ordinary empty EOM remains a v2 scan. */
		return FALSE;
	}

	ucl_object_insert_key(metadata, ucl_object_fromlstring(record->str, record->len), "early_record", 0, true);
	rspamd_fstring_t *json = nullptr;
	rspamd_ucl_emit_fstring(metadata, UCL_EMIT_JSON_COMPACT, &json);
	string_ptr json_owner{json, &rspamd_fstring_free};

	rspamd::http::multipart_response multipart;
	multipart.add_part("metadata", "application/json", {json->str, json->len});
	multipart.add_part("message", "", {data, len});
	multipart.prepare_iov();

	/* Copy the message once, while the original HTTP body is still alive. */
	auto *body = rspamd_fstring_sized_new(multipart.body_total_len());

	for (size_t i = 0; i < multipart.body_iov_count(); i++) {
		const auto &part = multipart.body_iov()[i];
		body = rspamd_fstring_append(body, static_cast<const char *>(part.iov_base), part.iov_len);
	}

	rspamd_http_message_set_body_from_fstring_steal(msg, body);
	msg->url = rspamd_fstring_assign(msg->url, "/checkv3", 8);
	rspamd_http_message_remove_header(msg, "Content-Type");
	auto content_type = multipart.content_type();
	rspamd_http_message_add_header(msg, "Content-Type", content_type.c_str());
	return TRUE;
}

gboolean rspamd_multistage_import(struct rspamd_task *task)
{
	auto *wire = ucl_object_lookup(task->meta, "early_record");

	if (!wire || ucl_object_type(wire) != UCL_STRING) {
		return FALSE;
	}

	owning_object payload{rspamd_multistage_open(task->cfg, "data-response", ucl_object_tostring(wire), wire->len)};

	if (!payload) {
		return FALSE;
	}

	auto *id = string_field(payload.get(), "id");
	auto *decision = string_field(payload.get(), "decision");
	auto *binding = string_field(payload.get(), "binding");

	if (!id || strlen(id) != RSPAMD_MULTISTAGE_ID_LEN || !decision || strcmp(decision, "continue") != 0 || !binding) {
		return FALSE;
	}

	string_ptr expected{rspamd_multistage_binding(task->meta, id), &rspamd_fstring_free};

	if (!expected || !string_field_equals(payload.get(), "binding", {expected->str, expected->len})) {
		return FALSE;
	}

	return rspamd_symcache_import_checkpoint(task, ucl_object_lookup(payload.get(), "record"), binding);
}

namespace {
struct data_scan {
	owning_object request{nullptr};
	owning_object record{nullptr};
	string_ptr binding{nullptr, &rspamd_fstring_free};
	string_ptr reply{nullptr, &rspamd_fstring_free};
	rspamd_multistage_done done;
	void *ud;
	bool running = false;
	bool finished = false;
	bool timed_out = false;
};

auto recorded_symbol(const ucl_object_t *record, const char *symbol) -> bool
{
	auto *checks = ucl_object_lookup(record, "checks");
	ucl_object_iter_t it = nullptr;

	while (auto *check = ucl_object_iterate(checks, &it, true)) {
		auto *ops = ucl_object_lookup(check, "ops");
		ucl_object_iter_t op_it = nullptr;

		while (auto *op = ucl_object_iterate(ops, &op_it, true)) {
			auto *name = string_field(op, "symbol");

			if (name && strcmp(name, symbol) == 0) {
				return true;
			}
		}
	}

	return false;
}

void apply_policy(struct rspamd_task *task, data_scan *scan)
{
	auto *policies = ucl_object_lookup(multistage_options(task->cfg), "policies");

	if (!policies || ucl_object_type(policies) != UCL_ARRAY || task->cfg->multistage_policy_ref <= 0) {
		return;
	}

	auto *L = RSPAMD_LUA_CFG_STATE(task->cfg);
	auto top = lua_gettop(L);
	lua_rawgeti(L, LUA_REGISTRYINDEX, task->cfg->multistage_policy_ref);
	rspamd_lua_task_push(L, task);
	lua_createtable(L, policies->len, 0);
	ucl_object_iter_t it = nullptr;
	unsigned int index = 0;

	while (auto *policy = ucl_object_iterate(policies, &it, true)) {
		auto *symbol = string_field(policy, "symbol");
		auto *result = symbol ? rspamd_task_find_symbol_result(task, symbol, nullptr) : nullptr;
		lua_pushboolean(L, result && !(result->flags & RSPAMD_SYMBOL_RESULT_IGNORED) &&
							   recorded_symbol(scan->record.get(), symbol));
		lua_rawseti(L, -2, ++index);
	}

	if (lua_pcall(L, 2, 2, 0) != 0) {
		msg_err_task("cannot select DATA policy: %s", lua_tostring(L, -1));
		lua_settop(L, top);
		return;
	}

	if (lua_type(L, -2) == LUA_TNUMBER) {
		auto selected = lua_tointeger(L, -2);
		auto *policy = selected > 0 && selected <= policies->len ? ucl_array_find_index(policies, selected - 1) : nullptr;

		if (policy) {
			rspamd_task_begin_early_result_full(task, string_field(policy, "action"), string_field(policy, "name"),
												string_field(policy, "reason"), string_field(scan->request.get(), "id"),
												lua_tostring(L, -1));
		}
	}

	lua_settop(L, top);
}

auto process_data_scan(struct rspamd_task *task, data_scan *scan) -> rspamd_symcache_checkpoint_result
{
	if (task->early_result) {
		return rspamd_task_process_early_result(task, scan->timed_out);
	}

	if (scan->timed_out) {
		rspamd_session_cleanup(task->s, true);
		return rspamd_session_events_pending(task->s) ? RSPAMD_SYMCACHE_CHECKPOINT_PENDING
													  : RSPAMD_SYMCACHE_CHECKPOINT_COMPLETE;
	}

	auto result = rspamd_symcache_process_checkpoint(task, task->cfg->cache, RSPAMD_SYMCACHE_INPUT_ENVELOPE);

	if (result == RSPAMD_SYMCACHE_CHECKPOINT_COMPLETE) {
		std::string binding(scan->binding->str, scan->binding->len);
		scan->record.reset(rspamd_symcache_export_checkpoint(task, binding.c_str()));

		if (scan->record) {
			apply_policy(task, scan);
		}
	}

	/* A matching policy freezes the decision before terminal observers run. */
	if (task->early_result) {
		return rspamd_task_process_early_result(task, scan->timed_out);
	}

	return result;
}

auto make_data_reply(struct rspamd_task *task, const data_scan *scan, rspamd_symcache_checkpoint_result result)
	-> rspamd_fstring_t *
{
	owning_object payload{ucl_object_typed_new(UCL_OBJECT)};
	ucl_object_insert_key(payload.get(), ucl_object_fromint(1), "version", 0, true);
	ucl_object_insert_key(payload.get(), ucl_object_ref(ucl_object_lookup(scan->request.get(), "issued")), "issued", 0,
						  true);
	ucl_object_insert_key(payload.get(), ucl_object_ref(ucl_object_lookup(scan->request.get(), "id")), "id", 0, true);
	ucl_object_insert_key(payload.get(), ucl_object_fromlstring(scan->binding->str, scan->binding->len), "binding", 0,
						  true);

	if (auto *terminal = rspamd_task_get_terminal_event(task)) {
		ucl_object_insert_key(payload.get(), ucl_object_copy(ucl_object_lookup(terminal, "action")), "decision", 0,
							  true);
		ucl_object_insert_key(payload.get(), ucl_object_ref(terminal), "terminal", 0, true);
	}
	else {
		ucl_object_insert_key(payload.get(), ucl_object_fromstring("continue"), "decision", 0, true);

		if (!scan->timed_out && result == RSPAMD_SYMCACHE_CHECKPOINT_COMPLETE && scan->record) {
			ucl_object_insert_key(payload.get(), ucl_object_ref(scan->record.get()), "record", 0, true);
		}
	}

	return rspamd_multistage_seal(task->cfg, "data-response", payload.get());
}

gboolean data_scan_finish(void *ud)
{
	auto *task = static_cast<rspamd_task *>(ud);
	auto *scan = static_cast<data_scan *>(task->multistage);

	if (scan->running || rspamd_session_blocked(task->s)) {
		return FALSE;
	}

	if (scan->finished) {
		return TRUE;
	}

	scan->running = true;
	auto result = process_data_scan(task, scan);

	if (result == RSPAMD_SYMCACHE_CHECKPOINT_PENDING) {
		scan->running = false;
		return FALSE;
	}

	scan->reply.reset(make_data_reply(task, scan, result));
	scan->finished = true;
	ev_timer_stop(task->event_loop, &task->timeout_ev);
	scan->done(task, scan->reply.get(), scan->ud);
	scan->running = false;
	return TRUE;
}

void data_scan_timeout(EV_P_ ev_timer *timer, int revents)
{
	auto *task = static_cast<rspamd_task *>(timer->data);
	static_cast<data_scan *>(task->multistage)->timed_out = true;
	data_scan_finish(task);
}
}// namespace

gboolean rspamd_multistage_start(struct rspamd_task *task, struct rspamd_http_message *msg, rspamd_multistage_done done,
								 void *ud)
{
	gsize len;
	auto *wire = rspamd_http_message_get_body(msg, &len);
	owning_object request{rspamd_multistage_open(task->cfg, "data-request", wire, len)};
	auto *id = string_field(request.get(), "id");
	auto *metadata = ucl_object_lookup(request.get(), "metadata");

	if (msg->method != HTTP_POST || !request || !id || strlen(id) != RSPAMD_MULTISTAGE_ID_LEN || !metadata ||
		ucl_object_type(metadata) != UCL_OBJECT ||
		ev_time() - ucl_object_todouble(ucl_object_lookup(request.get(), "issued")) > max_data_age) {
		g_set_error(&task->err, g_quark_from_static_string("multistage"), 403, "invalid or unavailable DATA request");
		task->protocol_flags |= RSPAMD_TASK_PROTOCOL_FLAG_VERBATIM_ERR_CODE;
		return FALSE;
	}

	task->cmd = CMD_CHECK_V2;
	task->meta = ucl_object_ref(metadata);

	if (!rspamd_protocol_handle_metadata(task, task->meta)) {
		return FALSE;
	}

	if (!task->from_envelope || !task->rcpt_envelope || (task->flags & RSPAMD_TASK_FLAG_BROKEN_HEADERS)) {
		g_set_error(&task->err, g_quark_from_static_string("multistage"), 400, "incomplete DATA envelope");
		return FALSE;
	}

	string_ptr binding{rspamd_multistage_binding(metadata, id), &rspamd_fstring_free};

	if (!binding) {
		g_set_error(&task->err, g_quark_from_static_string("multistage"), 400, "DATA envelope exceeds limits");
		return FALSE;
	}

	auto *scan = new data_scan;
	scan->binding = std::move(binding);
	scan->request = std::move(request);
	scan->done = done;
	scan->ud = ud;
	task->multistage = scan;

	rspamd_mempool_add_destructor(
		task->task_pool,
		[](void *p) {
			delete static_cast<data_scan *>(p);
		},
		scan);

	task->s = rspamd_task_create_session(task, task->task_pool, data_scan_finish, nullptr,
										 (event_finalizer_t) rspamd_task_free);

	task->timeout_ev.data = task;
	ev_timer_init(&task->timeout_ev, data_scan_timeout, rspamd_multistage_timeout(task->cfg), 0);
	ev_timer_start(task->event_loop, &task->timeout_ev);

	data_scan_finish(task);

	return TRUE;
}

const rspamd_fstring_t *rspamd_multistage_reply(struct rspamd_task *task)
{
	return task->multistage ? static_cast<data_scan *>(task->multistage)->reply.get() : nullptr;
}
