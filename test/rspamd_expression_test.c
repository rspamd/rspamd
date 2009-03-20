#include "../src/config.h"
#include "../src/main.h"
#include "../src/cfg_file.h"
#include "../src/expressions.h"
#include "tests.h"

/* Vector of test expressions */
char *test_expressions[] = {
	"(A&B|!C)&!(D|E)",
	"/test&!/&!/\\/|/",
	"header_exists(f(b(aaa)))|header=/bbb/",
	NULL
}; 

void 
rspamd_expression_test_func ()
{
	memory_pool_t *pool;
	struct expression *cur;
	struct expression_argument *arg;
	char **line, *outstr;
	int r, s;
	GList *cur_arg;

	pool = memory_pool_new (1024);
	
	line = test_expressions;
	while (*line) {
		r = 0;
		cur = parse_expression (pool, *line);
		s = strlen (*line) * 4;
		outstr = memory_pool_alloc (pool, s);
		while (cur) {
			if (cur->type == EXPR_REGEXP) {
				r += snprintf (outstr + r, s - r, "OP:%s ", (char *)cur->content.operand);
			} else if (cur->type == EXPR_STR) {
				r += snprintf (outstr + r, s - r, "S:%s ", (char *)cur->content.operand);

			} else if (cur->type == EXPR_FUNCTION) {
				r += snprintf (outstr + r, s - r, "F:%s ", ((struct expression_function *)cur->content.operand)->name);
				cur_arg = ((struct expression_function *)cur->content.operand)->args;
				while (cur_arg) {
					arg = cur_arg->data;
					if (arg->type == EXPRESSION_ARGUMENT_NORMAL) {
						r += snprintf (outstr + r, s - r, "A:%s ", (char *)arg->data);
					}
					else {
						r += snprintf (outstr + r, s - r, "AF:%s ", ((struct expression_function *)arg->data)->name);
					}
					cur_arg = g_list_next (cur_arg);
				}
			}
			else {
				r += snprintf (outstr + r, s - r, "O:%c ", cur->content.operation);
			}
			cur = cur->next;
		}
		msg_debug ("Parsed expression: '%s' -> '%s'", *line, outstr);
		line ++;
	}

	memory_pool_delete (pool);
}
