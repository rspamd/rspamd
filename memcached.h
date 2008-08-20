#ifndef MEMCACHED_H
#define MEMCACHED_H

#include <sys/types.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <time.h>

#define MAXKEYLEN 250

#define MEMC_OPT_DEBUG 0x1

struct event;

typedef enum memc_error {
	OK,
	BAD_COMMAND,
	CLIENT_ERROR,
	SERVER_ERROR,
	SERVER_TIMEOUT,
	NOT_EXISTS,
	EXISTS,
	WRONG_LENGTH
} memc_error_t;

/* XXX: Only UDP_TEXT is supported at present */
typedef enum memc_proto {
	UDP_TEXT,
	TCP_TEXT,
	UDP_BIN,
	TCP_BIN
} memc_proto_t;

typedef enum memc_op {
	CMD_NULL,
	CMD_CONNECT,
	CMD_READ,
	CMD_WRITE,
	CMD_DELETE,
} memc_opt_t;

typedef struct memcached_param_s {
	char key[MAXKEYLEN];
	u_char *buf;
	size_t bufsize;
	size_t bufpos;
	int expire;
} memcached_param_t;


/* Port must be in network byte order */
typedef struct memcached_ctx_s {
	memc_proto_t protocol;
	struct in_addr addr;
	uint16_t port;
	int sock;
	struct timeval timeout;
	/* Counter that is used for memcached operations in network byte order */
	uint16_t count;
	/* Flag that signalize that this memcached is alive */
	short alive;
	/* Options that can be specified for memcached connection */
	short options;
	/* Current operation */
	memc_opt_t op;
	/* Event structure */
	struct event mem_ev;
	/* Current command */
	const char *cmd;
	/* Current param */
	memcached_param_t *param;
	/* Callback for current operation */
	void (*callback) (struct memcached_ctx_s *ctx, memc_error_t error, void *data);
	/* Data for callback function */
	void *callback_data;
} memcached_ctx_t;

typedef void (*memcached_callback_t) (memcached_ctx_t *ctx, memc_error_t error, void *data);

/* 
 * Initialize connection to memcached server:
 * addr, port and timeout fields in ctx must be filled with valid values
 * Return:
 * 0 - success
 * -1 - error (error is stored in errno)
 */
int memc_init_ctx (memcached_ctx_t *ctx);
int memc_init_ctx_mirror (memcached_ctx_t *ctx, size_t memcached_num);
/*
 * Memcached function for getting, setting, adding values to memcached server
 * ctx - valid memcached context
 * key - key to extract (max 250 characters as it specified in memcached API)
 * buf, elemsize, nelem - allocated buffer of length nelem structures each of elemsize 
 * 			  that would contain extracted data (NOT NULL TERMINATED)
 * Return:
 * memc_error_t
 * nelem is changed according to actual number of extracted data
 *
 * "set" means "store this data".  
 *
 * "add" means "store this data, but only if the server *doesn't* already
 * hold data for this key".  

 * "replace" means "store this data, but only if the server *does*
 * already hold data for this key".

 * "append" means "add this data to an existing key after existing data".

 * "prepend" means "add this data to an existing key before existing data".
 */
#define memc_get(ctx, param) memc_read(ctx, "get", param)
#define memc_set(ctx, param, expire) memc_write(ctx, "set", param, expire)
#define memc_add(ctx, param, expire) memc_write(ctx, "add", param, expire)
#define memc_replace(ctx, param, expire) memc_write(ctx, "replace", param, expire)
#define memc_append(ctx, param, expire) memc_write(ctx, "append", param, expire)
#define memc_prepend(ctx, param, expire) memc_write(ctx, "prepend", param, expire)

/* Functions that works with mirror of memcached servers */
#define memc_get_mirror(ctx, num, param) memc_read_mirror(ctx, num, "get", param)
#define memc_set_mirror(ctx, num, param, expire) memc_write_mirror(ctx, num, "set", param, expire)
#define memc_add_mirror(ctx, num, param, expire) memc_write_mirror(ctx, num, "add", param, expire)
#define memc_replace_mirror(ctx, num, param, expire) memc_write_mirror(ctx, num, "replace", param, expire)
#define memc_append_mirror(ctx, num, param, expire) memc_write_mirror(ctx, num, "append", param, expire)
#define memc_prepend_mirror(ctx, num, param, expire) memc_write_mirror(ctx, num, "prepend", param, expire)


memc_error_t memc_read (memcached_ctx_t *ctx, const char *cmd, memcached_param_t *param);
memc_error_t memc_write (memcached_ctx_t *ctx, const char *cmd, memcached_param_t *param, int expire);
memc_error_t memc_delete (memcached_ctx_t *ctx, memcached_param_t *params);

memc_error_t memc_write_mirror (memcached_ctx_t *ctx, size_t memcached_num, const char *cmd, memcached_param_t *param, int expire);
memc_error_t memc_read_mirror (memcached_ctx_t *ctx, size_t memcached_num, const char *cmd, memcached_param_t *param);
memc_error_t memc_delete_mirror (memcached_ctx_t *ctx, size_t memcached_num, const char *cmd, memcached_param_t *param);

/* Return symbolic name of memcached error*/
const char * memc_strerror (memc_error_t err);

/* Destroy socket from ctx */
int memc_close_ctx (memcached_ctx_t *ctx);
int memc_close_ctx_mirror (memcached_ctx_t *ctx, size_t memcached_num);

#endif
