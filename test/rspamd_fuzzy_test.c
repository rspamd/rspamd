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

void 
rspamd_fuzzy_test_func ()
{
	memory_pool_t *pool;
	fuzzy_hash_t *h1, *h2;
	f_str_t f1, f2;

	pool = memory_pool_new (1024);
	f1.begin = s1;
	f1.len = strlen (s1);
	f2.begin = s2;
	f2.len = strlen (s2);

	h1 = fuzzy_init (&f1, pool);
	h2 = fuzzy_init (&f2, pool);

	msg_info ("rspamd_fuzzy_test_func: difference between strings is %d", fuzzy_compare_hashes (h1, h2));

	memory_pool_delete (pool);
}
