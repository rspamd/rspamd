#include "../src/config.h"
#include "../src/main.h"
#include "../src/cfg_file.h"
#include "../src/expressions.h"

rspamd_hash_t *counters = NULL;

int 
main (int argc, char **argv)
{
	memory_pool_t *pool;
	struct expression *cur;
	char *line, *outstr;
	int r, s;
	char buf[BUFSIZ];

	pool = memory_pool_new (memory_pool_get_size ());
	
	line = fgets (buf, sizeof (buf), stdin);
	while (line) {
		s = strlen (line);
		if (buf[s - 1] == '\n') {
			buf[s - 1] = '\0';
		}
		if (buf[s - 2] == '\r') {
			buf[s - 2] = '\0';
		}

		r = 0;
		cur = parse_expression (pool, line);
		s = strlen (line) * 4;
		outstr = memory_pool_alloc (pool, s);
		while (cur) {
			if (cur->type == EXPR_REGEXP) {
				r += snprintf (outstr + r, s - r, "OP:%s ", (char *)cur->content.operand);
			} else if (cur->type == EXPR_STR) {
				r += snprintf (outstr + r, s - r, "S:%s ", (char *)cur->content.operand);

			} else if (cur->type == EXPR_FUNCTION) {
				r += snprintf (outstr + r, s - r, "F:%s ", ((struct expression_function *)cur->content.operand)->name);
			}
			else {
				r += snprintf (outstr + r, s - r, "O:%c ", cur->content.operation);
			}
			cur = cur->next;
		}
		printf ("Parsed expression: '%s' -> '%s'\n", line, outstr);
		line = fgets (buf, sizeof (buf), stdin);
	}

	memory_pool_delete (pool);

	return 0;
}
