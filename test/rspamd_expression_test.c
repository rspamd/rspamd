#include <sys/types.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/param.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <syslog.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "../src/config.h"
#include "../src/main.h"
#include "../src/cfg_file.h"
#include "tests.h"

/* Vector of test expressions */
char *test_expressions[] = {
	"(A&B|!C)&!(D|E)",
	"/test&!/&!/\\/|/",
	NULL
}; 

void 
rspamd_expression_test_func ()
{
	memory_pool_t *pool;
	struct expression *cur;
	char **line, *outstr;
	int r, s;

	pool = memory_pool_new (1024);
	
	line = test_expressions;
	while (*line) {
		r = 0;
		cur = parse_expression (pool, *line);
		s = strlen (*line) + 1;
		outstr = memory_pool_alloc (pool, s);
		while (cur) {
			if (cur->type == EXPR_OPERAND) {
				r += snprintf (outstr + r, s - r, "%s", (char *)cur->content.operand);
			}
			else {
				r += snprintf (outstr + r, s - r, "%c", cur->content.operation);
			}
			cur = cur->next;
		}
		msg_debug ("Parsed expression: '%s' -> '%s'", *line, outstr);
		line ++;
	}

	memory_pool_delete (pool);
}
