/*
 * Copyright (c) 2013-2014, Vsevolod Stakhov
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *	 * Redistributions of source code must retain the above copyright
 *	   notice, this list of conditions and the following disclaimer.
 *	 * Redistributions in binary form must reproduce the above copyright
 *	   notice, this list of conditions and the following disclaimer in the
 *	   documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY AUTHOR ''AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef RDNS_H
#define RDNS_H

#include <sys/types.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#ifdef  __cplusplus
extern "C" {
#endif

struct rdns_reply;
struct rdns_request;
struct rdns_io_channel;

typedef void (*dns_callback_type) (struct rdns_reply *reply, void *arg);

enum rdns_request_type {
	RDNS_REQUEST_INVALID = -1,
	RDNS_REQUEST_A = 1,
	RDNS_REQUEST_NS = 2,
	RDNS_REQUEST_SOA = 6,
	RDNS_REQUEST_PTR = 12,
	RDNS_REQUEST_MX = 15,
	RDNS_REQUEST_TXT = 16,
	RDNS_REQUEST_SRV = 33,
	RDNS_REQUEST_SPF = 99,
	RDNS_REQUEST_AAAA = 28,
	RDNS_REQUEST_TLSA = 52,
	RDNS_REQUEST_ANY = 255
};

union rdns_reply_element_un {
	struct {
		struct in_addr addr;
	} a;
	struct {
		struct in6_addr addr;
	} aaa;
	struct {
		char *name;
	} ptr;
	struct {
		char *name;
	} ns;
	struct {
		char *name;
		uint16_t priority;
	} mx;
	struct {
		char *data;
	} txt;
	struct {
		uint16_t priority;
		uint16_t weight;
		uint16_t port;
		char *target;
	} srv;
	struct {
		char *mname;
		char *admin;
		uint32_t serial;
		int32_t refresh;
		int32_t retry;
		int32_t expire;
		uint32_t minimum;
	} soa;
	struct {
		uint8_t usage;
		uint8_t selector;
		uint8_t match_type;
		uint16_t datalen;
		uint8_t *data;
	} tlsa;
};

struct rdns_reply_entry {
	union rdns_reply_element_un content;
	enum rdns_request_type type;
	int32_t ttl;
	struct rdns_reply_entry *prev, *next;
};


enum dns_rcode {
	RDNS_RC_INVALID = -1,
	RDNS_RC_NOERROR	= 0,
	RDNS_RC_FORMERR	= 1,
	RDNS_RC_SERVFAIL	= 2,
	RDNS_RC_NXDOMAIN	= 3,
	RDNS_RC_NOTIMP	= 4,
	RDNS_RC_REFUSED	= 5,
	RDNS_RC_YXDOMAIN	= 6,
	RDNS_RC_YXRRSET	= 7,
	RDNS_RC_NXRRSET	= 8,
	RDNS_RC_NOTAUTH	= 9,
	RDNS_RC_NOTZONE	= 10,
	RDNS_RC_TIMEOUT = 11,
	RDNS_RC_NETERR = 12,
	RDNS_RC_NOREC = 13
};

struct rdns_reply {
	struct rdns_request *request;
	struct rdns_resolver *resolver;
	struct rdns_reply_entry *entries;
	const char *requested_name;
	enum dns_rcode code;
	bool authenticated;
};

typedef void (*rdns_periodic_callback)(void *user_data);

struct rdns_async_context {
	void *data;
	void* (*add_read)(void *priv_data, int fd, void *user_data);
	void (*del_read)(void *priv_data, void *ev_data);
	void* (*add_write)(void *priv_data, int fd, void *user_data);
	void (*del_write)(void *priv_data, void *ev_data);
	void* (*add_timer)(void *priv_data, double after, void *user_data);
	void (*repeat_timer)(void *priv_data, void *ev_data);
	void (*del_timer)(void *priv_data, void *ev_data);
	void* (*add_periodic)(void *priv_data, double after,
		rdns_periodic_callback cb, void *user_data);
	void (*del_periodic)(void *priv_data, void *ev_data);
	void (*cleanup)(void *priv_data);
};

struct rdns_upstream_elt {
	void *server;
	void *lib_data;
};

struct rdns_upstream_context {
	void *data;
	struct rdns_upstream_elt* (*select)(const char *name,
			size_t len, void *ups_data);
	struct rdns_upstream_elt* (*select_retransmit)(const char *name, size_t len,
												   struct rdns_upstream_elt* prev_elt,
												   void *ups_data);
	unsigned int (*count)(void *ups_data);
	void (*ok)(struct rdns_upstream_elt *elt, void *ups_data);
	void (*fail)(struct rdns_upstream_elt *elt, void *ups_data, const char *reason);
};

/**
 * Type of rdns plugin
 */
enum rdns_plugin_type {
	RDNS_PLUGIN_CURVE = 0
};

typedef ssize_t (*rdns_network_send_callback) (struct rdns_request *req, void *plugin_data,
											   struct sockaddr *saddr, socklen_t slen);
typedef ssize_t (*rdns_network_recv_callback) (struct rdns_io_channel *ioc, void *buf,
											   size_t len, void *plugin_data,
											   struct rdns_request **req_out,
											   struct sockaddr *saddr, socklen_t slen);
typedef void (*rdns_network_finish_callback) (struct rdns_request *req, void *plugin_data);
typedef void (*rdns_plugin_dtor_callback) (struct rdns_resolver *resolver, void *plugin_data);

struct rdns_plugin {
	enum rdns_plugin_type type;
	union {
		struct {
			rdns_network_send_callback send_cb;
			rdns_network_recv_callback recv_cb;
			rdns_network_finish_callback finish_cb;
		} curve_plugin;
	} cb;
	rdns_plugin_dtor_callback dtor;
	void *data;
};

/*
 * RDNS logger types
 */
/*
 * These types are somehow compatible with glib
 */
enum rdns_log_level {
	  RDNS_LOG_ERROR = 1 << 3,
	  RDNS_LOG_WARNING = 1 << 4,
	  RDNS_LOG_INFO = 1 << 6,
	  RDNS_LOG_DEBUG = 1 << 7
};
typedef void (*rdns_log_function) (
									void *log_data, //!< opaque data pointer
									enum rdns_log_level level, //!< level of message
									const char *function, //!< calling function
									const char *format, //!< format
									va_list args //!< set of arguments
									);

struct rdns_request_name {
	char *name;
	enum rdns_request_type type;
	unsigned int len;
};

#define MAX_FAKE_NAME 1000

/*
 * RDNS API
 */

enum rdns_resolver_flags {
	RDNS_RESOLVER_DEFAULT,
	RDNS_RESOLVER_NOIDN = (1u << 0u),
};

/**
 * Create DNS resolver structure
 */
struct rdns_resolver *rdns_resolver_new (int flags);

/**
 * Bind resolver to specified async context
 * @param ctx
 */
void rdns_resolver_async_bind (struct rdns_resolver *resolver,
		struct rdns_async_context *ctx);

/**
 * Enable stub dnssec resolver
 * @param resolver
 */
void rdns_resolver_set_dnssec (struct rdns_resolver *resolver, bool enabled);

/**
 * Add new DNS server definition to the resolver
 * @param resolver resolver object
 * @param name name of DNS server (should be ipv4 or ipv6 address)
 * @param priority priority (can be 0 for fair round-robin)
 * @param io_cnt a number of sockets that are simultaneously opened to this server
 * @return opaque pointer that could be used to select upstream
 */
void* rdns_resolver_add_server (struct rdns_resolver *resolver,
		const char *name, unsigned int port,
		int priority, unsigned int io_cnt);


/**
 * Load nameservers definition from resolv.conf file
 * @param resolver resolver object
 * @param path path to resolv.conf file (/etc/resolv.conf typically)
 * @return true if resolv.conf has been parsed
 */
bool rdns_resolver_parse_resolv_conf (struct rdns_resolver *resolver,
		const char *path);

typedef bool (*rdns_resolv_conf_cb) (struct rdns_resolver *resolver,
		const char *name, unsigned int port,
		int priority, unsigned int io_cnt, void *ud);
/**
 * Parse nameservers calling the specified callback for each nameserver
 * @param resolve resolver object
 * @param path path to resolv.conf file (/etc/resolv.conf typically)
 * @param cb callback to call
 * @param ud userdata for callback
 * @return true if resolv.conf has been parsed
 */
bool rdns_resolver_parse_resolv_conf_cb (struct rdns_resolver *resolver,
		const char *path, rdns_resolv_conf_cb cb, void *ud);

/**
 * Set an external logger function to log messages from the resolver
 * @param resolver resolver object
 * @param logger logger callback
 * @param log_data opaque data
 */
void rdns_resolver_set_logger (struct rdns_resolver *resolver,
		rdns_log_function logger, void *log_data);

/**
 * Set log level for an internal logger (stderr one)
 * @param resolver resolver object
 * @param level desired log level
 */
void rdns_resolver_set_log_level (struct rdns_resolver *resolver,
		enum rdns_log_level level);

/**
 * Set upstream library for selecting DNS upstreams
 * @param resolver resolver object
 * @param ups_ctx upstream functions
 * @param ups_data opaque data
 */
void rdns_resolver_set_upstream_lib (struct rdns_resolver *resolver,
		struct rdns_upstream_context *ups_ctx,
		void *ups_data);

/**
 * Set maximum number of dns requests to be sent to a socket to be refreshed
 * @param resolver resolver object
 * @param max_ioc_uses unsigned count of socket usage limit
 * @param check_time specifies how often to check for sockets and refresh them
 */
void rdns_resolver_set_max_io_uses (struct rdns_resolver *resolver,
		uint64_t max_ioc_uses, double check_time);

/**
 * Register new plugin for rdns resolver
 * @param resolver
 * @param plugin
 */
void rdns_resolver_register_plugin (struct rdns_resolver *resolver,
		struct rdns_plugin *plugin);

/**
 * Add a fake reply for a specified name
 * @param resolver
 * @param type
 * @param name (must not be larger than MAX_FAKE_NAME)
 * @param reply
 */
void rdns_resolver_set_fake_reply (struct rdns_resolver *resolver,
								   const char *name,
								   enum rdns_request_type type,
								   enum dns_rcode rcode,
								   struct rdns_reply_entry *reply);

/**
 * Init DNS resolver
 * @param resolver
 * @return
 */
bool rdns_resolver_init (struct rdns_resolver *resolver);

/**
 * Decrease refcount for a resolver and free it if refcount is 0
 * @param resolver
 */
void rdns_resolver_release (struct rdns_resolver *resolver);

/**
 * Make a DNS request
 * @param resolver resolver object
 * @param cb callback to call on resolve completing
 * @param ud user data for callback
 * @param timeout timeout in seconds
 * @param repeats how much time to retransmit query
 * @param queries how much RR queries to send
 * @param ... -> queries in format: <query_type>[,type_argument[,type_argument...]]
 * @return opaque request object or NULL
 */
struct rdns_request* rdns_make_request_full (
		struct rdns_resolver *resolver,
		dns_callback_type cb,
		void *cbdata,
		double timeout,
		unsigned int repeats,
		unsigned int queries,
		...
		);

/**
 * Get textual presentation of DNS error code
 */
const char *rdns_strerror (enum dns_rcode rcode);

/**
 * Get textual presentation of DNS request type
 */
const char *rdns_strtype (enum rdns_request_type type);

/**
 * Parse string and return request type
 * @param str
 * @return
 */
enum rdns_request_type rdns_type_fromstr (const char *str);

/**
 * Returns string representing request type
 * @param rcode
 * @return
 */
const char *
rdns_str_from_type (enum rdns_request_type rcode);

/**
 * Parse string and return error code
 * @param str
 * @return
 */
enum dns_rcode rdns_rcode_fromstr (const char *str);

/**
 * Increase refcount for a request
 * @param req
 * @return
 */
struct rdns_request* rdns_request_retain (struct rdns_request *req);

/**
 * Decrease refcount for a request and free it if refcount is 0
 * @param req
 */
void rdns_request_release (struct rdns_request *req);

/**
 * Check whether a request contains `type` request
 * @param req request object
 * @param type check for a specified type
 * @return true if `type` has been requested
 */
bool rdns_request_has_type (struct rdns_request *req, enum rdns_request_type type);

/**
 * Return requested name for a request
 * @param req request object
 * @return requested name as it was passed to `rdns_make_request`
 */
const struct rdns_request_name* rdns_request_get_name (struct rdns_request *req,
		unsigned int *count);

/**
 * Return a DNS server name associated with the request
 * @param req request object
 * @return name of a DNS server
 */
const char* rdns_request_get_server (struct rdns_request *req);


/**
 * Return PTR string for a request (ipv4 or ipv6) addresses
 * @param str string representation of IP address
 * @return name to resolve or NULL if `str` is not an IP address; caller must free result when it is unused
 */
char * rdns_generate_ptr_from_str (const char *str);

/**
 * Format DNS name of the packet punycoding if needed
 * @param req request
 * @param name name string
 * @param namelen length of name
 */
bool rdns_format_dns_name (struct rdns_resolver *resolver,
		const char *name, size_t namelen,
		char **out, size_t *outlen);

/*
 * Private functions used by async libraries as callbacks
 */

void rdns_process_read (int fd, void *arg);
void rdns_process_timer (void *arg);
void rdns_process_retransmit (int fd, void *arg);

#ifdef  __cplusplus
}
#endif

#endif
