/* Copyright (c) 2013, Vsevolod Stakhov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *       * Redistributions of source code must retain the above copyright
 *         notice, this list of conditions and the following disclaimer.
 *       * Redistributions in binary form must reproduce the above copyright
 *         notice, this list of conditions and the following disclaimer in the
 *         documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED ''AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "../src/config.h"
#include "../src/rcl/rcl.h"
#include "../src/main.h"
#include "tests.h"

const gchar *rcl_test_valid[] = {
		/* Json like */
		"{"
		"\"key1\": value;"
		"\"key1\": value2;"
		"\"key1\": \"value;\""
		"}\n",
		/* Nginx like */
		"section1 { param1 = value; param2 = value, "
		"section3 {param = value; param2 = value, param3 = [\"value1\", value2, 100500]}}\n"
		"section2 { param1 = {key = value}, param1 = [\"key\"]}",
		/* Numbers */
		"key = 1s\n"
		"key2 = 1min\n"
		"key3 = 1kb\n"
		"key4 = 5M\n"
		"key5 = 10mS\n"
		"key6 = 10y\n",
		/* Strings */
		"key = \"some string\";"
		"key1 = /some/path;"
		"key3 = 111some,"
		"key4: s1,"
		"\"key5\": \"\\n\\r123\"",
		/* Macros */
		"section1 {key = value; section {\n"
		"param = \"value\";\n"
        "param2 = value\n"
        "array = [          1, 1mb, test]}\n"
        ".includes \"./test.cfg\"}",
		NULL
};

static const gchar test_pubkey[] = ""
"-----BEGIN PUBLIC KEY-----\n"
"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDlhk2u5nbTVgEskmS+qZcAj339\n"
"bLwEK/TXdd0G3d4BVKpF712frw+YwetRdmRRYL5EdjiF01Bv3s6QmsThAJX/li/c\n"
"Q15YFxhvq9DZ0qJmL7e1NzORo6m/WLRK9wxWA+PXSvSUKrlZ3kt9ygD4z5QZ3/td\n"
"qil9VM6Mz7P1HJ0KywIDAQAB\n"
"-----END PUBLIC KEY-----\n";

void
rspamd_rcl_test_func (void)
{
	struct rspamd_cl_parser *parser, *parser2;
	rspamd_cl_object_t *obj;
	const gchar **cur;
	guchar *emitted;
	GError *err = NULL;
	struct timespec start, end;
	gdouble seconds;

	cur = rcl_test_valid;
	while (*cur != NULL) {
		parser = rspamd_cl_parser_new (RSPAMD_CL_FLAG_KEY_LOWERCASE);
		rspamd_cl_pubkey_add (parser, test_pubkey, sizeof (test_pubkey) - 1, &err);
		g_assert_no_error (err);
		g_assert (parser != NULL);
		rspamd_cl_parser_add_chunk (parser, *cur, strlen (*cur), &err);
		g_assert_no_error (err);
		obj = rspamd_cl_parser_get_object (parser, &err);
		g_assert_no_error (err);
		/* Test config emitting */
		emitted = rspamd_cl_object_emit (obj, RSPAMD_CL_EMIT_CONFIG);
		g_assert (emitted != NULL);
		msg_debug ("got config output: %s", emitted);
		parser2 = rspamd_cl_parser_new (RSPAMD_CL_FLAG_KEY_LOWERCASE);
		g_assert (parser2 != NULL);
		rspamd_cl_parser_add_chunk (parser2, emitted, strlen (emitted), &err);
		g_assert_no_error (err);
		rspamd_cl_parser_free (parser2);
		g_free (emitted);
		/* Test json emitted */
		emitted = rspamd_cl_object_emit (obj, RSPAMD_CL_EMIT_JSON);
		g_assert (emitted != NULL);
		msg_debug ("got json output: %s", emitted);
		parser2 = rspamd_cl_parser_new (RSPAMD_CL_FLAG_KEY_LOWERCASE);
		g_assert (parser2 != NULL);
		rspamd_cl_parser_add_chunk (parser2, emitted, strlen (emitted), &err);
		g_assert_no_error (err);
		rspamd_cl_parser_free (parser2);
		g_free (emitted);
		/* Compact json */
		emitted = rspamd_cl_object_emit (obj, RSPAMD_CL_EMIT_JSON_COMPACT);
		g_assert (emitted != NULL);
		msg_debug ("got json compacted output: %s", emitted);
		parser2 = rspamd_cl_parser_new (RSPAMD_CL_FLAG_KEY_LOWERCASE);
		g_assert (parser2 != NULL);
		rspamd_cl_parser_add_chunk (parser2, emitted, strlen (emitted), &err);
		g_assert_no_error (err);
		rspamd_cl_parser_free (parser2);
		g_free (emitted);

		/* Cleanup */
		rspamd_cl_parser_free (parser);
		rspamd_cl_obj_unref (obj);
		cur ++;
	}

	/* Load a big json */
	parser = rspamd_cl_parser_new (RSPAMD_CL_FLAG_KEY_LOWERCASE);
	clock_gettime (CLOCK_MONOTONIC, &start);
	rspamd_cl_parser_add_file (parser, "./rcl_test.json", &err);
	g_assert_no_error (err);
	obj = rspamd_cl_parser_get_object (parser, &err);
	g_assert_no_error (err);
	clock_gettime (CLOCK_MONOTONIC, &end);
	seconds = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1000000000.;
	msg_info ("parsed json in %.4f seconds", seconds);
	/* Test config emitting */
	clock_gettime (CLOCK_MONOTONIC, &start);
	emitted = rspamd_cl_object_emit (obj, RSPAMD_CL_EMIT_CONFIG);
	g_assert (emitted != NULL);
	clock_gettime (CLOCK_MONOTONIC, &end);
	seconds = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1000000000.;
	msg_info ("emitted object in %.4f seconds", seconds);
	rspamd_cl_parser_free (parser);
	rspamd_cl_obj_unref (obj);
}
