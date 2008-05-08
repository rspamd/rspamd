#ifndef MEMCACHED_H
#define MEMCACHED_H

#include <sys/types.h>
#include <netinet/in.h>

#define MAXKEYLEN 250

#define MEMC_OPT_DEBUG 0x1

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

/* Port must be in network byte order */
typedef struct memcached_ctx_s {
	memc_proto_t protocol;
	struct in_addr addr;
	uint16_t port;
	int sock;
	int timeout;
	/* Counter that is used for memcached operations in network byte order */
	uint16_t count;
	/* Flag that signalize that this memcached is alive */
	short alive;
	/* Options that can be specified for memcached connection */
	short options;
} memcached_ctx_t;

typedef struct memcached_param_s {
	char key[MAXKEYLEN];
	u_char *buf;
	size_t bufsize;
} memcached_param_t;

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
#define memc_get(ctx, params, nelem) memc_read(ctx, "get", params, nelem)
#define memc_set(ctx, params, nelem, expire) memc_write(ctx, "set", params, nelem, expire)
#define memc_add(ctx, params, nelem, expire) memc_write(ctx, "add", params, nelem, expire)
#define memc_replace(ctx, params, nelem, expire) memc_write(ctx, "replace", params, nelem, expire)
#define memc_append(ctx, params, nelem, expire) memc_write(ctx, "append", params, nelem, expire)
#define memc_prepend(ctx, params, nelem, expire) memc_write(ctx, "prepend", params, nelem, expire)

/* Functions that works with mirror of memcached servers */
#define memc_get_mirror(ctx, num, params, nelem) memc_read_mirror(ctx, num, "get", params, nelem)
#define memc_set_mirror(ctx, num, params, nelem, expire) memc_write_mirror(ctx, num, "set", params, nelem, expire)
#define memc_add_mirror(ctx, num, params, nelem, expire) memc_write_mirror(ctx, num, "add", params, nelem, expire)
#define memc_replace_mirror(ctx, num, params, nelem, expire) memc_write_mirror(ctx, num, "replace", params, nelem, expire)
#define memc_append_mirror(ctx, num, params, nelem, expire) memc_write_mirror(ctx, num, "append", params, nelem, expire)
#define memc_prepend_mirror(ctx, num, params, nelem, expire) memc_write_mirror(ctx, num, "prepend", params, nelem, expire)


memc_error_t memc_read (memcached_ctx_t *ctx, const char *cmd, memcached_param_t *params, size_t *nelem);
memc_error_t memc_write (memcached_ctx_t *ctx, const char *cmd, memcached_param_t *params, size_t *nelem, int expire);
memc_error_t memc_delete (memcached_ctx_t *ctx, memcached_param_t *params, size_t *nelem);

memc_error_t memc_write_mirror (memcached_ctx_t *ctx, size_t memcached_num, const char *cmd, memcached_param_t *params, size_t *nelem, int expire);
memc_error_t memc_read_mirror (memcached_ctx_t *ctx, size_t memcached_num, const char *cmd, memcached_param_t *params, size_t *nelem);
memc_error_t memc_delete_mirror (memcached_ctx_t *ctx, size_t memcached_num, const char *cmd, memcached_param_t *params, size_t *nelem);

/* Return symbolic name of memcached error*/
const char * memc_strerror (memc_error_t err);

/* Destroy socket from ctx */
int memc_close_ctx (memcached_ctx_t *ctx);
int memc_close_ctx_mirror (memcached_ctx_t *ctx, size_t memcached_num);

#endif
