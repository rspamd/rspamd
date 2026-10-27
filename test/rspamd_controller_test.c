/*
 * Copyright 2026 Vsevolod Stakhov
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
/*
 * Compile the controller in C to exercise its private handlers directly,
 * without exporting test hooks or starting a worker. LeakSanitizer checks the
 * allocations left behind after each request and all fixture teardown.
 */
#include "../src/controller.c"

worker_t *workers[] = {&controller_worker, NULL};

struct passwordless_case {
	const char *url;
	gboolean privileged;
};

static struct rspamd_http_message *
query_request(const char *url)
{
	struct rspamd_http_message *msg = rspamd_http_new_message(HTTP_REQUEST);
	msg->url = rspamd_fstring_append(msg->url, url, strlen(url));
	return msg;
}

static rspamd_inet_addr_t *
query_peer(void)
{
	rspamd_inet_addr_t *addr = NULL;
	const char *ip = "198.51.100.1";

	g_assert_true(rspamd_parse_inet_address(&addr, ip, strlen(ip),
											RSPAMD_INET_ADDRESS_PARSE_NO_UNIX));
	return addr;
}

static void
passwordless_query(gconstpointer ud)
{
	const struct passwordless_case *test = ud;
	struct rspamd_controller_worker_ctx ctx = {0};
	struct rspamd_controller_session session = {0};
	struct rspamd_http_connection_entry entry = {0};

	/* TCP, no secure_ip map: reach the passwordless branch after query parsing.
	 * Read access must remain read-only when an enable password is configured. */
	ctx.enable_password = test->privileged ? NULL : "configured-enable-password";
	session.ctx = &ctx;
	session.from_addr = query_peer();
	entry.ud = &session;

	for (unsigned int i = 0; i < 128; i++) {
		struct rspamd_http_message *msg = query_request(test->url);

		g_assert_true(rspamd_controller_check_password(&entry, &session, msg,
													   test->privileged));
		g_assert_cmpint(session.is_read_only, ==, !test->privileged);
		rspamd_http_message_unref(msg);
	}

	rspamd_inet_address_free(session.from_addr);
}

static int
check_query_headers(struct rspamd_http_connection_entry *entry,
					struct rspamd_http_message *msg, struct module_ctx *ctx)
{
	static const struct {
		const char *name;
		const char *value;
	} expected[] = {
		{"Flag", "17"},
		{"Hash", "abc+def"},
		{"Empty", ""},
		{"Dup", "new"},
	};

	/* The query table has already been released when the handler runs.
	 * These headers must therefore own copies of the decoded values. */
	for (unsigned int i = 0; i < G_N_ELEMENTS(expected); i++) {
		const rspamd_ftok_t *value = rspamd_http_message_find_header(msg, expected[i].name);

		g_assert_nonnull(value);
		g_assert_cmpuint(value->len, ==, strlen(expected[i].value));
		g_assert_cmpmem(value->begin, value->len,
						expected[i].value, strlen(expected[i].value));
	}

	return 17;
}

static void
custom_query(void)
{
	struct rspamd_controller_worker_ctx ctx = {0};
	struct rspamd_controller_session session = {0};
	struct rspamd_http_connection_entry entry = {0};
	struct rspamd_custom_controller_command command = {0};

	/* Authenticate using a header to isolate custom-command ownership from
	 * the separate passwordless-authentication regression. */
	ctx.password = "test-password";
	ctx.custom_commands = g_hash_table_new(rspamd_strcase_hash, rspamd_strcase_equal);
	command.handler = check_query_headers;
	g_hash_table_insert(ctx.custom_commands, "/query-test", &command);
	session.ctx = &ctx;
	session.from_addr = query_peer();
	entry.ud = &session;

	for (unsigned int i = 0; i < 128; i++) {
		struct rspamd_http_message *msg = query_request(
			"/query-test?%46lag=17&hash=abc%2Bdef&empty=&dup=old&dup=new");

		rspamd_http_message_add_header(msg, "Password", ctx.password);
		g_assert_cmpint(rspamd_controller_handle_custom(&entry, msg), ==, 17);
		rspamd_http_message_unref(msg);
	}

	rspamd_inet_address_free(session.from_addr);
	g_hash_table_unref(ctx.custom_commands);
}

int main(int argc, char **argv)
{
	static const struct passwordless_case cases[] = {
		{"/auth", FALSE},
		{"/auth?unused=value&empty=", FALSE},
		{"/saveactions", TRUE},
		{"/saveactions?unused=value&empty=", TRUE},
	};

	g_test_init(&argc, &argv, NULL);
	g_test_add_data_func("/controller/query/passwordless-read-empty", &cases[0], passwordless_query);
	g_test_add_data_func("/controller/query/passwordless-read-values", &cases[1], passwordless_query);
	g_test_add_data_func("/controller/query/passwordless-write-empty", &cases[2], passwordless_query);
	g_test_add_data_func("/controller/query/passwordless-write-values", &cases[3], passwordless_query);
	g_test_add_func("/controller/query/custom-command", custom_query);

	return g_test_run();
}
