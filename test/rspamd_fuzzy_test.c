#include "../src/config.h"
#include "../src/main.h"
#include "../src/fuzzy.h"
#include "tests.h"

static char *s1 = "This is sample test text.\r\n"
				  "abcdefghijklmnopqrstuvwx.\r\n"
				  "abcdefghijklmnopqrstuvwx.\r\n"
				  "abcdefghijklmnopqrstuvwx.\r\n"
				  "abcdefghijklmnopqrstuvwx.\r\n"
				  "abcdefghijklmnopqrstuvwx.\r\n"
				  "abcdefghijklmnopqrstuvwx.\r\n"
				  "abcdefghijklmnopqrstuvwx.\r\n"
				  "abcdefghijklmnopqrstuvwx.\r\n";
static char *s2 = "This is sample test text.\r\n"
				  "abcdefghijklmnopqrstuvwx.\r\n"
				  "abcdefghijklmnopzrstuvwx.\r\n"
				  "abcdefghijklmnopqrstuvwx.\r\n"
				  "abcdefghijklmnopqrstuvwx.\r\n"
				  "abcdefghijklmnopqrstuvwx.\r\n"
				  "abcdefghijklmnopqrstuvwx.\r\n"
				  "abcdefghijklmnopqrstuvwx.\r\n"
				  "abcdefghijklmnopqrstuvwx.\r\n";
static char *s3 = "";
static char *s4 = "abcdefghijklmn\r\n";
static char *s5 = "This is sample test text.\r\n"
				  "abcdefghijklmnopqrstuvwx.\r\n"
				  "abcdefghijklmnopzrstuvwx.\r\n"
				  "abcdefghijklmnopqrstuvwx.\r\n"
				  "abcdefghijklmnopqrstuvwx.\r\n"
				  "abcdefghijklmnopqrstuvwx.\r\n"
				  "abcdefghijklmnopqrstuvwx.\r\n"
				  "abcdefghijklmnopqrstuvwx.\r\n"
				  "abcdefghijklmnopqrstuvwx.\r\n";

void 
rspamd_fuzzy_test_func ()
{
	memory_pool_t *pool;
	fuzzy_hash_t *h1, *h2, *h3, *h4, *h5;
	f_str_t f1, f2, f3, f4, f5;
	int diff1, diff2;

	pool = memory_pool_new (1024);
	f1.begin = s1;
	f1.len = strlen (s1);
	f2.begin = s2;
	f2.len = strlen (s2);
	f3.begin = s3;
	f3.len = strlen (s3);
	f4.begin = s4;
	f4.len = strlen (s4);
	f5.begin = s5;
	f5.len = strlen (s5);

	h1 = fuzzy_init (&f1, pool);
	h2 = fuzzy_init (&f2, pool);
	h3 = fuzzy_init (&f3, pool);
	h4 = fuzzy_init (&f4, pool);
	h5 = fuzzy_init (&f5, pool);

	diff1 = fuzzy_compare_hashes (h3, h4) + fuzzy_compare_hashes (h2, h4);
	diff2 = fuzzy_compare_hashes (h2, h5);
	msg_debug ("rspamd_fuzzy_test_func: s1, s2 difference between strings is %d", fuzzy_compare_hashes (h1, h2));
	msg_debug ("rspamd_fuzzy_test_func: s1, s3 difference between strings is %d", fuzzy_compare_hashes (h1, h3));
	msg_debug ("rspamd_fuzzy_test_func: s3, s4 difference between strings is %d", fuzzy_compare_hashes (h3, h4));
	msg_debug ("rspamd_fuzzy_test_func: s2, s4 difference between strings is %d", fuzzy_compare_hashes (h2, h4));
	msg_debug ("rspamd_fuzzy_test_func: s2, s5 difference between strings is %d", diff2);
	
	/* Identical strings */
	if (diff2 != 100) {
		msg_err ("hash difference is %d", diff2);
		g_assert (diff2 == 100);
	}

	memory_pool_delete (pool);
}
