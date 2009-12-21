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

#include <gmime/gmime.h>

#include "../src/config.h"
#if !defined(HAVE_OWN_QUEUE_H) && defined(HAVE_SYS_QUEUE_H)
#include <sys/queue.h>
#endif
#ifdef HAVE_OWN_QUEUE_H
#include "../src/queue.h"
#endif

#include "../src/main.h"
#include "../src/cfg_file.h"
#include "../src/url.h"
#include "../src/util.h"
#include "../src/message.h"

rspamd_hash_t *counters = NULL;

int
main (int argc, char **argv)
{
	struct worker_task task;
	struct uri *url;
	char *buf = NULL;
	size_t pos = 0, size = 65535;
	GList *cur;
	
	g_mem_set_vtable(glib_mem_profiler_table);
	g_mime_init (0);
	bzero (&task, sizeof (struct worker_task));
	task.task_pool = memory_pool_new (memory_pool_get_size ());
	
	/* Preallocate buffer */
	buf = g_malloc (size);

	while (!feof (stdin)) {
		*(buf + pos) = getchar ();
		pos ++;
		if (pos == size) {
			size *= 2;
			buf = g_realloc (buf, size);
		}
	}
	
	task.cfg = memory_pool_alloc0 (task.task_pool, sizeof (struct config_file));

	task.msg = memory_pool_alloc (task.task_pool, sizeof (f_str_t));
	task.msg->begin = buf;
	task.msg->len = pos;
	process_message (&task);
	
	cur = task.urls;
	while (cur) {
		url = cur->data;
		printf ("%s\n", struri (url));
		cur = g_list_next (cur);
	}
	
	return 0;
}
