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
#include <event.h>

#include "../config.h"
#include "../main.h"
#include "../cfg_file.h"
#include "../memcached.h"
#include "tests.h"

u_char *buf = "test";

static void 
memcached_callback (memcached_ctx_t *ctx, memc_error_t error, void *data)
{
	struct timeval tv;

	switch (ctx->op) {
		case CMD_CONNECT:
			g_assert (error == OK);
			msg_debug ("Connect ok");
			memc_set (ctx, ctx->param, 60);
			break;
		case CMD_READ:
			g_assert (error == OK);
			g_assert (!strcmp(ctx->param->buf, buf));
			msg_debug ("Read ok");
			memc_close_ctx (ctx);
			tv.tv_sec = 0;
			tv.tv_usec = 0;
			event_loopexit (&tv);
			break;
		case CMD_WRITE:
			g_assert (error == OK);
			msg_debug ("Write ok");
			ctx->param->buf = g_malloc (sizeof (buf));
			bzero (ctx->param->buf, sizeof (buf));
			memc_get (ctx, ctx->param);
			break;
	}
}
			
void
rspamd_memcached_test_func ()
{
	memcached_ctx_t *ctx;
	memcached_param_t *param;
	struct in_addr addr;

	ctx = g_malloc (sizeof (memcached_ctx_t));
	param = g_malloc (sizeof (memcached_param_t));
	bzero (ctx, sizeof (memcached_ctx_t));
	bzero (param, sizeof (memcached_param_t));

	event_init ();

	ctx->callback = memcached_callback;
	ctx->callback_data = (void *)param;
	ctx->protocol = TCP_TEXT;
	inet_aton ("127.0.0.1", &addr);
	memcpy (&ctx->addr, &addr, sizeof (struct in_addr));
	ctx->port = htons (11211);
	ctx->timeout.tv_sec = 1;
	ctx->timeout.tv_usec = 0;
	ctx->sock = -1;
	ctx->options = MEMC_OPT_DEBUG;
	strlcpy (param->key, buf, sizeof (param->key));
	param->buf = buf;
	param->bufsize = strlen (buf);
	ctx->param = param;
	g_assert (memc_init_ctx (ctx) != -1);

	event_loop (0);
}

