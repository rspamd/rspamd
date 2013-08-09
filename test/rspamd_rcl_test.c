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
#include "tests.h"

const gchar *rcl_test_valid[] = {
		/* Json like */
		"{"
		"\"key1\": value;"
		"\"key1\": value2;"
		"\"key1\": \"value;\""
		"}\n",
		/* Nginx like */
		"section1 { param1 = value; param2 = value, param3 = [\"value1\", 100500]}\n"
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
		NULL
};

void
rspamd_rcl_test_func (void)
{
	struct rspamd_cl_parser *parser;
	rspamd_cl_object_t *obj;
	const gchar **cur;
	GError *err = NULL;

	cur = rcl_test_valid;
	while (*cur != NULL) {
		parser = rspamd_cl_parser_new ();
		g_assert (parser != NULL);
		rspamd_cl_parser_add_chunk (parser, *cur, strlen (*cur), &err);
		g_assert_no_error (err);
		cur ++;
	}

}
