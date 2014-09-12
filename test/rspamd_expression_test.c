#include "config.h"
#include "main.h"
#include "cfg_file.h"
#include "expressions.h"
#include "tests.h"

/* Vector of test expressions */
char *test_expressions[] = {
	"(A&B|!C)&!(D|E)",
	"/test&!/&!/\\/|/",
	"header_exists(f(b(aaa)))|header=/bbb/",
	"!(header_exists(X-Mailer, /aaa,/) | header_exists(User-Agent)) & Received=/cp-out\\d+\\.libero\\.it/H & Message-Id=/<[\\da-f]{12}\\.[\\da-f]{16}@/H",
	NULL
}; 

void 
rspamd_expression_test_func ()
{
	rspamd_mempool_t *pool;
	struct expression *cur;
	struct expression_argument *arg;
	char **line, *outstr;
	int r, s;
	GList *cur_arg;

	pool = rspamd_mempool_new (1024);
	
	line = test_expressions;
	while (*line) {
		r = 0;
		cur = parse_expression (pool, *line);
		s = strlen (*line) * 4;
		outstr = rspamd_mempool_alloc (pool, s);
		while (cur) {
			if (cur->type == EXPR_REGEXP) {
				r += rspamd_snprintf (outstr + r, s - r, "OP:%s ", (char *)cur->content.operand);
			} else if (cur->type == EXPR_STR) {
				r += rspamd_snprintf (outstr + r, s - r, "S:%s ", (char *)cur->content.operand);

			} else if (cur->type == EXPR_FUNCTION) {
				r += rspamd_snprintf (outstr + r, s - r, "F:%s ", ((struct expression_function *)cur->content.operand)->name);
				cur_arg = ((struct expression_function *)cur->content.operand)->args;
				while (cur_arg) {
					arg = cur_arg->data;
					if (arg->type == EXPRESSION_ARGUMENT_NORMAL) {
						r += rspamd_snprintf (outstr + r, s - r, "A:%s ", (char *)arg->data);
					}
					else {
						r += rspamd_snprintf (outstr + r, s - r, "AF:%p ", arg->data);
					}
					cur_arg = g_list_next (cur_arg);
				}
			}
			else {
				r += rspamd_snprintf (outstr + r, s - r, "O:%c ", cur->content.operation);
			}
			cur = cur->next;
		}
		msg_debug ("Parsed expression: '%s' -> '%s'", *line, outstr);
		line ++;
	}

	rspamd_mempool_delete (pool);
}
