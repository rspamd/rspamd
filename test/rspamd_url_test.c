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


#include "../config.h"
#include "../main.h"
#include "../cfg_file.h"
#include "../url.h"
#include "tests.h"

const char *test_text = "This is test file with http://TesT%45.com/././ url";
const char *test_html = "<some_tag>This is test file with <a href=\"http://microsoft.com\">http://TesT%45.com/././ url</a></some_tag>";

/* Function for using in glib test suite */
void
rspamd_url_test_func ()
{
	GByteArray *text, *html;
	struct worker_task task;
	struct uri *url;
	int i = 0;

	text = g_byte_array_new();
	text->data = (gchar *)test_text;
	text->len = strlen (test_text);
	html = g_byte_array_new();
	html->data = (gchar *)test_html;
	html->len = strlen (test_html);
	bzero (&task, sizeof (task));
	TAILQ_INIT (&task.urls);
	
	g_test_timer_start ();
	g_test_message ("* Testing text URL regexp parser *");
	g_test_message ("Passing string: %s", test_text);
	url_parse_text (&task, text);

	TAILQ_FOREACH (url, &task.urls, next) {
		g_test_message ("Found url: %s, hostname: %s, data: %s", struri (url), url->host, url->data);
		i ++;
	}

	while (!TAILQ_EMPTY (&task.urls)) {
		url = TAILQ_FIRST (&task.urls);
		TAILQ_REMOVE (&task.urls, url, next);
		g_free (url->string);
		g_free (url);
	}
	g_assert (i == 1);

	g_test_message ("Time elapsed: %.2f", g_test_timer_elapsed ());

	i = 0;
	g_test_timer_start ();
	g_test_message ("* Testing html URL regexp parser *");
	g_test_message ("Passing string: %s", test_html);
	url_parse_html (&task, html);

	TAILQ_FOREACH (url, &task.urls, next) {
		g_test_message ("Found url: %s, hostname: %s, data: %s", struri (url), url->host, url->data);
		i ++;
	}

	while (!TAILQ_EMPTY (&task.urls)) {
		url = TAILQ_FIRST (&task.urls);
		TAILQ_REMOVE (&task.urls, url, next);
		g_free (url->string);
		g_free (url);
	}
	g_assert (i == 2);
	g_test_message ("Time elapsed: %.2f", g_test_timer_elapsed ());
}
