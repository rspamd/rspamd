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

const char *test_text =
"www.schemeless.ru\n"
"www.schemeless.rus\n"
" as ftp.schemeless.ru dasd \n"
"ftp12.schemeless.ru\n"
"ftpsearch.schemeless.ru\n"
"schemeless.ru\n"
"www.schemeless.microsoft\n"
"1.2.3.4\n"
"1.2.3.4/a\n"
"1.2.3\n"
"1.2.3.4.5\n"
"www.schemeless.ru,\n"
"www.schemeless.ru.\n"
"http://www.schemed.ru.\n"
"http://www.schemed.ru.\n"
"http://www.bolinfest.com/targetalert/'\n"
"http://www.bolinfest.com/targetalert/'';\n"
"https://www.schemed.ru.\n"
"ufps://www.schemed.ru.\n"
"http://ported.ru:8080\n"
"http://ported.ru:8080\n"
"http://1.2.3.4\n"
"http://1.2.3.4:80\n"
"1.2.3.4:80\n"
"www.a9.com\n"
"www.a-9.com\n"
"http://www.schemed.ru/a.txt:\n"
"http://www.schemed.ru/a.txt'\n"
"http://www.schemed.ru/a.txt\"\n"
"http://www.schemed.ru/a.txt>\n"
"http://www.schemed.ru/a=3&b=4\n"
"http://spam.ru/bad=user@domain.com\n"
"http://spam.ru/bad=user@domain.com\n"
"http://spam.ru user@domain.com\n"
"http://a.foto.radikal.ru/0604/de7793c6ca62.jpg\n"
"http://a.foto.radikal.ru/0604/de7793c6ca62.jpg\n"
"schemeless.gz\n"
"schemeless.jp\n"
"schemeless.ua\n"
"schemeless.gz/a\n"
"mysql.so\n"
"http://mysql.so\n"
"3com.com\n"
"lj-user.livejournal.com\n"
"http://lj-user.livejournal.com\n"
"http://vsem.ru?action;\n";
const char *test_html = "<some_tag>This is test file with <a href=\"http://microsoft.com\">http://TesT.com/././?%45%46%20 url</a></some_tag>";

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
	g_test_message ("Testing text URL regexp parser");
	msg_debug ("Passing string: %s", test_text);
	url_parse_text (&task, text);

	TAILQ_FOREACH (url, &task.urls, next) {
		msg_debug ("Found url: %s, hostname: %s, data: %s", struri (url), url->host, url->data);
		i ++;
	}

	while (!TAILQ_EMPTY (&task.urls)) {
		url = TAILQ_FIRST (&task.urls);
		TAILQ_REMOVE (&task.urls, url, next);
		g_free (url->string);
		g_free (url);
	}
	g_assert (i == 39);

	msg_debug ("Time elapsed: %.2f", g_test_timer_elapsed ());
	i = 0;
	g_test_timer_start ();
	g_test_message ("Testing html URL regexp parser");
	msg_debug ("Passing string: %s", test_html);
	url_parse_html (&task, html);

	TAILQ_FOREACH (url, &task.urls, next) {
		msg_debug ("Found url: %s, hostname: %s, data: %s", struri (url), url->host, url->data);
		i ++;
	}

	while (!TAILQ_EMPTY (&task.urls)) {
		url = TAILQ_FIRST (&task.urls);
		TAILQ_REMOVE (&task.urls, url, next);
		g_free (url->string);
		g_free (url);
	}
	g_assert (i == 1);
	msg_debug ("Time elapsed: %.2f", g_test_timer_elapsed ());
}
