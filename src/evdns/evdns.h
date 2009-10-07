/*
 * Copyright (c) 2000-2007 Niels Provos <provos@citi.umich.edu>
 * Copyright (c) 2007-2009 Niels Provos and Nick Mathewson
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#ifndef _EVDNS_H_
#define _EVDNS_H_

#include "../config.h" 

/** Error codes 0-5 are as described in RFC 1035. */
#define DNS_ERR_NONE 0
/** The name server was unable to interpret the query */
#define DNS_ERR_FORMAT 1
/** The name server was unable to process this query due to a problem with the
 * name server */
#define DNS_ERR_SERVERFAILED 2
/** The domain name does not exist */
#define DNS_ERR_NOTEXIST 3
/** The name server does not support the requested kind of query */
#define DNS_ERR_NOTIMPL 4
/** The name server refuses to reform the specified operation for policy
 * reasons */
#define DNS_ERR_REFUSED 5
/** The reply was truncated or ill-formatted */
#define DNS_ERR_TRUNCATED 65
/** An unknown error occurred */
#define DNS_ERR_UNKNOWN 66
/** Communication with the server timed out */
#define DNS_ERR_TIMEOUT 67
/** The request was canceled because the DNS subsystem was shut down. */
#define DNS_ERR_SHUTDOWN 68
/** The request was canceled via a call to evdns_cancel_request */
#define DNS_ERR_CANCEL 69

#define DNS_IPv4_A 1
#define DNS_PTR 2
#define DNS_IPv6_AAAA 3
#define DNS_TXT 4

#define DNS_QUERY_NO_SEARCH 1

#define DNS_OPTION_SEARCH 1
#define DNS_OPTION_NAMESERVERS 2
#define DNS_OPTION_MISC 4
#define DNS_OPTIONS_ALL 7

/**
 * The callback that contains the results from a lookup.
 * - type is either DNS_IPv4_A or DNS_PTR or DNS_IPv6_AAAA
 * - count contains the number of addresses of form type
 * - ttl is the number of seconds the resolution may be cached for.
 * - addresses needs to be cast according to type
 */
typedef void (*evdns_callback_type) (int result, char type, int count, int ttl, void *addresses, void *arg);

struct evdns_base;
struct event_base;

/**
  Initialize the asynchronous DNS library.

  This function initializes support for non-blocking name resolution by
  calling evdns_resolv_conf_parse() on UNIX and
  evdns_config_windows_nameservers() on Windows.

  @param event_base the event base to associate the dns client with
  @param initialize_nameservers 1 if resolve.conf processing should occur
  @return 0 if successful, or -1 if an error occurred
  @see evdns_base_free()
 */
struct evdns_base * evdns_base_new(struct event_base *event_base, int initialize_nameservers);


/**
  Shut down the asynchronous DNS resolver and terminate all active requests.

  If the 'fail_requests' option is enabled, all active requests will return
  an empty result with the error flag set to DNS_ERR_SHUTDOWN. Otherwise,
  the requests will be silently discarded.

  @param evdns_base the evdns base to free
  @param fail_requests if zero, active requests will be aborted; if non-zero,
		active requests will return DNS_ERR_SHUTDOWN.
  @see evdns_base_new()
 */
void evdns_base_free(struct evdns_base *base, int fail_requests);

/**
  Convert a DNS error code to a string.

  @param err the DNS error code
  @return a string containing an explanation of the error code
*/
const char *evdns_err_to_string(int err);


/**
  Add a nameserver.

  The address should be an IPv4 address in network byte order.
  The type of address is chosen so that it matches in_addr.s_addr.

  @param base the evdns_base to which to add the name server
  @param address an IP address in network byte order
  @return 0 if successful, or -1 if an error occurred
  @see evdns_base_nameserver_ip_add()
 */
int evdns_base_nameserver_add(struct evdns_base *base,
                              unsigned long int address);

/**
  Get the number of configured nameservers.

  This returns the number of configured nameservers (not necessarily the
  number of running nameservers).  This is useful for double-checking
  whether our calls to the various nameserver configuration functions
  have been successful.

  @param base the evdns_base to which to apply this operation
  @return the number of configured nameservers
  @see evdns_base_nameserver_add()
 */
int evdns_base_count_nameservers(struct evdns_base *base);

/**
  Remove all configured nameservers, and suspend all pending resolves.

  Resolves will not necessarily be re-attempted until evdns_resume() is called.

  @param base the evdns_base to which to apply this operation
  @return 0 if successful, or -1 if an error occurred
  @see evdns_base_resume()
 */
int evdns_base_clear_nameservers_and_suspend(struct evdns_base *base);


/**
  Resume normal operation and continue any suspended resolve requests.

  Re-attempt resolves left in limbo after an earlier call to
  evdns_clear_nameservers_and_suspend().

  @param base the evdns_base to which to apply this operation
  @return 0 if successful, or -1 if an error occurred
  @see evdns_base_clear_nameservers_and_suspend()
 */
int evdns_base_resume(struct evdns_base *base);

/**
  Add a nameserver.

  This function parses a n IPv4 or IPv6 address from a string and adds it as a
  nameserver.  It supports the following formats:
  - [IPv6Address]:port
  - [IPv6Address]
  - IPv6Address
  - IPv4Address:port
  - IPv4Address

  If no port is specified, it defaults to 53.

  @param base the evdns_base to which to apply this operation
  @return 0 if successful, or -1 if an error occurred
  @see evdns_base_nameserver_add()
 */
int evdns_base_nameserver_ip_add(struct evdns_base *base,
                                 const char *ip_as_string);

struct evdns_request;

/**
  Lookup an A record for a given name.

  @param base the evdns_base to which to apply this operation
  @param name a DNS hostname
  @param flags either 0, or DNS_QUERY_NO_SEARCH to disable searching for this query.
  @param callback a callback function to invoke when the request is completed
  @param ptr an argument to pass to the callback function
  @return an evdns_request object if successful, or NULL if an error occurred.
  @see evdns_resolve_ipv6(), evdns_resolve_reverse(), evdns_resolve_reverse_ipv6(), evdns_cancel_request()
 */
struct evdns_request *evdns_base_resolve_ipv4(struct evdns_base *base, const char *name, int flags, evdns_callback_type callback, void *ptr);

/**
  Lookup an AAAA record for a given name.

  @param base the evdns_base to which to apply this operation
  @param name a DNS hostname
  @param flags either 0, or DNS_QUERY_NO_SEARCH to disable searching for this query.
  @param callback a callback function to invoke when the request is completed
  @param ptr an argument to pass to the callback function
  @return an evdns_request object if successful, or NULL if an error occurred.
  @see evdns_resolve_ipv4(), evdns_resolve_reverse(), evdns_resolve_reverse_ipv6(), evdns_cancel_request()
 */
struct evdns_request *evdns_base_resolve_ipv6(struct evdns_base *base, const char *name, int flags, evdns_callback_type callback, void *ptr);

struct in_addr;
struct in6_addr;

/**
  Lookup a PTR record for a given IP address.

  @param base the evdns_base to which to apply this operation
  @param in an IPv4 address
  @param flags either 0, or DNS_QUERY_NO_SEARCH to disable searching for this query.
  @param callback a callback function to invoke when the request is completed
  @param ptr an argument to pass to the callback function
  @return an evdns_request object if successful, or NULL if an error occurred.
  @see evdns_resolve_reverse_ipv6(), evdns_cancel_request()
 */
struct evdns_request *evdns_base_resolve_reverse(struct evdns_base *base, const struct in_addr *in, int flags, evdns_callback_type callback, void *ptr);


/**
  Lookup a PTR record for a given IPv6 address.

  @param base the evdns_base to which to apply this operation
  @param in an IPv6 address
  @param flags either 0, or DNS_QUERY_NO_SEARCH to disable searching for this query.
  @param callback a callback function to invoke when the request is completed
  @param ptr an argument to pass to the callback function
  @return an evdns_request object if successful, or NULL if an error occurred.
  @see evdns_resolve_reverse_ipv6(), evdns_cancel_request()
 */
struct evdns_request *evdns_base_resolve_reverse_ipv6(struct evdns_base *base, const struct in6_addr *in, int flags, evdns_callback_type callback, void *ptr);

/**
  Cancels a pending DNS resolution request.

  @param base the evdns_base that was used to make the request
  @param req the evdns_request that was returned by calling a resolve function
  @see evdns_base_resolve_ip4(), evdns_base_resolve_ipv6, evdns_base_resolve_reverse
*/
void evdns_cancel_request(struct evdns_base *base, struct evdns_request *req);

/**
  Set the value of a configuration option.

  The currently available configuration options are:

    ndots, timeout, max-timeouts, max-inflight, attempts, randomize-case,
    bind-to.

  The option name needs to end with a colon.

  @param base the evdns_base to which to apply this operation
  @param option the name of the configuration option to be modified
  @param val the value to be set
  @param flags either 0 | DNS_OPTION_SEARCH | DNS_OPTION_MISC
  @return 0 if successful, or -1 if an error occurred
 */
int evdns_base_set_option(struct evdns_base *base, const char *option, const char *val, int flags);


/**
  Parse a resolv.conf file.

  The 'flags' parameter determines what information is parsed from the
  resolv.conf file. See the man page for resolv.conf for the format of this
  file.

  The following directives are not parsed from the file: sortlist, rotate,
  no-check-names, inet6, debug.

  If this function encounters an error, the possible return values are: 1 =
  failed to open file, 2 = failed to stat file, 3 = file too large, 4 = out of
  memory, 5 = short read from file, 6 = no nameservers listed in the file

  @param base the evdns_base to which to apply this operation
  @param flags any of DNS_OPTION_NAMESERVERS|DNS_OPTION_SEARCH|DNS_OPTION_MISC|
         DNS_OPTIONS_ALL
  @param filename the path to the resolv.conf file
  @return 0 if successful, or various positive error codes if an error
          occurred (see above)
  @see resolv.conf(3), evdns_config_windows_nameservers()
 */
int evdns_base_resolv_conf_parse(struct evdns_base *base, int flags, const char *const filename);


/**
  Obtain nameserver information using the Windows API.

  Attempt to configure a set of nameservers based on platform settings on
  a win32 host.  Preferentially tries to use GetNetworkParams; if that fails,
  looks in the registry.

  @return 0 if successful, or -1 if an error occurred
  @see evdns_resolv_conf_parse()
 */
#ifdef WIN32
int evdns_base_config_windows_nameservers(struct evdns_base *);
#define EVDNS_BASE_CONFIG_WINDOWS_NAMESERVERS_IMPLEMENTED
#endif


/**
  Clear the list of search domains.
 */
void evdns_base_search_clear(struct evdns_base *base);


/**
  Add a domain to the list of search domains

  @param domain the domain to be added to the search list
 */
void evdns_base_search_add(struct evdns_base *base, const char *domain);


/**
  Set the 'ndots' parameter for searches.

  Sets the number of dots which, when found in a name, causes
  the first query to be without any search domain.

  @param ndots the new ndots parameter
 */
void evdns_base_search_ndots_set(struct evdns_base *base, const int ndots);

/**
  A callback that is invoked when a log message is generated

  @param is_warning indicates if the log message is a 'warning'
  @param msg the content of the log message
 */
typedef void (*evdns_debug_log_fn_type)(int is_warning, const char *msg);


/**
  Set the callback function to handle log messages.

  @param fn the callback to be invoked when a log message is generated
 */
void evdns_set_log_fn(evdns_debug_log_fn_type fn);

/**
   Set a callback that will be invoked to generate transaction IDs.  By
   default, we pick transaction IDs based on the current clock time, which
   is bad for security.

   @param fn the new callback, or NULL to use the default.
 */
void evdns_set_transaction_id_fn(uint16_t (*fn)(void));

/**
   Set a callback used to generate random bytes.  By default, we use
   the same function as passed to evdns_set_transaction_id_fn to generate
   bytes two at a time.  If a function is provided here, it's also used
   to generate transaction IDs.
*/
void evdns_set_random_bytes_fn(void (*fn)(char *, size_t));

#define DNS_NO_SEARCH 1

/*
 * Functions used to implement a DNS server.
 */

struct evdns_server_request;
struct evdns_server_question;

/**
   A callback to implement a DNS server.  The callback function receives a DNS
   request.  It should then optionally add a number of answers to the reply
   using the evdns_server_request_add_*_reply functions, before calling either
   evdns_server_request_respond to send the reply back, or
   evdns_server_request_drop to decline to answer the request.

   @param req A newly received request
   @param user_data A pointer that was passed to
      evdns_add_server_port_with_base().
 */
typedef void (*evdns_request_callback_fn_type)(struct evdns_server_request *, void *);
#define EVDNS_ANSWER_SECTION 0
#define EVDNS_AUTHORITY_SECTION 1
#define EVDNS_ADDITIONAL_SECTION 2

#define EVDNS_TYPE_A	   1
#define EVDNS_TYPE_NS	   2
#define EVDNS_TYPE_CNAME   5
#define EVDNS_TYPE_SOA	   6
#define EVDNS_TYPE_PTR	  12
#define EVDNS_TYPE_MX	  15
#define EVDNS_TYPE_TXT	  16
#define EVDNS_TYPE_AAAA	  28

#define EVDNS_QTYPE_AXFR 252
#define EVDNS_QTYPE_ALL	 255

#define EVDNS_CLASS_INET   1

/* flags that can be set in answers; as part of the err parameter */
#define EVDNS_FLAGS_AA	0x400
#define EVDNS_FLAGS_RD	0x080

/** Create a new DNS server port.

    @param base The event base to handle events for the server port.
    @param socket A UDP socket to accept DNS requests.
    @param is_tcp Always 0 for now.
    @param callback A function to invoke whenever we get a DNS request
      on the socket.
    @param user_data Data to pass to the callback.
    @return an evdns_server_port structure for this server port.
 */
struct evdns_server_port *evdns_add_server_port_with_base(struct event_base *base, int socket, int is_tcp, evdns_request_callback_fn_type callback, void *user_data);
/** Close down a DNS server port, and free associated structures. */
void evdns_close_server_port(struct evdns_server_port *port);

/** Sets some flags in a reply we're building.
    Allows setting of the AA or RD flags
 */
void evdns_server_request_set_flags(struct evdns_server_request *req, int flags);

/* Functions to add an answer to an in-progress DNS reply.
 */
int evdns_server_request_add_reply(struct evdns_server_request *req, int section, const char *name, int type, int dns_class, int ttl, int datalen, int is_name, const char *data);
int evdns_server_request_add_a_reply(struct evdns_server_request *req, const char *name, int n, void *addrs, int ttl);
int evdns_server_request_add_aaaa_reply(struct evdns_server_request *req, const char *name, int n, void *addrs, int ttl);
int evdns_server_request_add_ptr_reply(struct evdns_server_request *req, struct in_addr *in, const char *inaddr_name, const char *hostname, int ttl);
int evdns_server_request_add_cname_reply(struct evdns_server_request *req, const char *name, const char *cname, int ttl);

/**
   Send back a response to a DNS request, and free the request structure.
*/
int evdns_server_request_respond(struct evdns_server_request *req, int err);
/**
   Free a DNS request without sending back a reply.
*/
int evdns_server_request_drop(struct evdns_server_request *req);
struct sockaddr;
/**
    Get the address that made a DNS request.
 */
int evdns_server_request_get_requesting_addr(struct evdns_server_request *_req, struct sockaddr *sa, int addr_len);

/*
 * Structures used to implement a DNS server.
 */

struct evdns_server_request {
	int flags;
	int nquestions;
	struct evdns_server_question **questions;
};
struct evdns_server_question {
	int type;
#ifdef __cplusplus
	int dns_question_class;
#else
	/* You should refer to this field as "dns_question_class".  The
	 * name "class" works in C for backward compatibility, and will be
	 * removed in a future version. (1.5 or later). */
	int class;
#define dns_question_class class
#endif
	char name[1];
};

/**
  Initialize the asynchronous DNS library.

  This function initializes support for non-blocking name resolution by
  calling evdns_resolv_conf_parse() on UNIX and
  evdns_config_windows_nameservers() on Windows.

  @deprecated This function is deprecated because it always uses the current
    event base, and is easily confused by multiple calls to event_init(), and
    so is not safe for multithreaded use.  Additionally, it allocates a global
    structure that only one thread can use. The replacement is
    evdns_base_new().

  @return 0 if successful, or -1 if an error occurred
  @see evdns_shutdown()
 */
int evdns_init(void);

/**
  Shut down the asynchronous DNS resolver and terminate all active requests.

  If the 'fail_requests' option is enabled, all active requests will return
  an empty result with the error flag set to DNS_ERR_SHUTDOWN. Otherwise,
  the requests will be silently discarded.

  @deprecated This function is deprecated because it does not allow the
    caller to specify which evdns_base it applies to.  The recommended
    function is evdns_base_shutdown().

  @param fail_requests if zero, active requests will be aborted; if non-zero,
		active requests will return DNS_ERR_SHUTDOWN.
  @see evdns_init()
 */
void evdns_shutdown(int fail_requests);

/**
  Add a nameserver.

  The address should be an IPv4 address in network byte order.
  The type of address is chosen so that it matches in_addr.s_addr.

  @deprecated This function is deprecated because it does not allow the
    caller to specify which evdns_base it applies to.  The recommended
    function is evdns_base_nameserver_add().

  @param address an IP address in network byte order
  @return 0 if successful, or -1 if an error occurred
  @see evdns_nameserver_ip_add()
 */
int evdns_nameserver_add(unsigned long int address);

/**
  Get the number of configured nameservers.

  This returns the number of configured nameservers (not necessarily the
  number of running nameservers).  This is useful for double-checking
  whether our calls to the various nameserver configuration functions
  have been successful.

  @deprecated This function is deprecated because it does not allow the
    caller to specify which evdns_base it applies to.  The recommended
    function is evdns_base_count_nameservers().

  @return the number of configured nameservers
  @see evdns_nameserver_add()
 */
int evdns_count_nameservers(void);

/**
  Remove all configured nameservers, and suspend all pending resolves.

  Resolves will not necessarily be re-attempted until evdns_resume() is called.

  @deprecated This function is deprecated because it does not allow the
    caller to specify which evdns_base it applies to.  The recommended
    function is evdns_base_clear_nameservers_and_suspend().

  @return 0 if successful, or -1 if an error occurred
  @see evdns_resume()
 */
int evdns_clear_nameservers_and_suspend(void);

/**
  Resume normal operation and continue any suspended resolve requests.

  Re-attempt resolves left in limbo after an earlier call to
  evdns_clear_nameservers_and_suspend().

  @deprecated This function is deprecated because it does not allow the
    caller to specify which evdns_base it applies to.  The recommended
    function is evdns_base_resume().

  @return 0 if successful, or -1 if an error occurred
  @see evdns_clear_nameservers_and_suspend()
 */
int evdns_resume(void);

/**
  Add a nameserver.

  This wraps the evdns_nameserver_add() function by parsing a string as an IP
  address and adds it as a nameserver.

  @deprecated This function is deprecated because it does not allow the
    caller to specify which evdns_base it applies to.  The recommended
    function is evdns_base_nameserver_ip_add().

  @return 0 if successful, or -1 if an error occurred
  @see evdns_nameserver_add()
 */
int evdns_nameserver_ip_add(const char *ip_as_string);

/**
  Lookup an A record for a given name.

  @deprecated This function is deprecated because it does not allow the
    caller to specify which evdns_base it applies to.  The recommended
    function is evdns_base_resolve_ipv4().

  @param name a DNS hostname
  @param flags either 0, or DNS_QUERY_NO_SEARCH to disable searching for this query.
  @param callback a callback function to invoke when the request is completed
  @param ptr an argument to pass to the callback function
  @return 0 if successful, or -1 if an error occurred
  @see evdns_resolve_ipv6(), evdns_resolve_reverse(), evdns_resolve_reverse_ipv6()
 */
int evdns_resolve_ipv4(const char *name, int flags, evdns_callback_type callback, void *ptr);

/**
  Lookup an AAAA record for a given name.

  @param name a DNS hostname
  @param flags either 0, or DNS_QUERY_NO_SEARCH to disable searching for this query.
  @param callback a callback function to invoke when the request is completed
  @param ptr an argument to pass to the callback function
  @return 0 if successful, or -1 if an error occurred
  @see evdns_resolve_ipv4(), evdns_resolve_reverse(), evdns_resolve_reverse_ipv6()
 */
int evdns_resolve_ipv6(const char *name, int flags, evdns_callback_type callback, void *ptr);

struct in_addr;
struct in6_addr;

/**
  Lookup a PTR record for a given IP address.

  @deprecated This function is deprecated because it does not allow the
    caller to specify which evdns_base it applies to.  The recommended
    function is evdns_base_resolve_reverse().

  @param in an IPv4 address
  @param flags either 0, or DNS_QUERY_NO_SEARCH to disable searching for this query.
  @param callback a callback function to invoke when the request is completed
  @param ptr an argument to pass to the callback function
  @return 0 if successful, or -1 if an error occurred
  @see evdns_resolve_reverse_ipv6()
 */
int evdns_resolve_reverse(const struct in_addr *in, int flags, evdns_callback_type callback, void *ptr);

/**
  Lookup a PTR record for a given IPv6 address.

  @deprecated This function is deprecated because it does not allow the
    caller to specify which evdns_base it applies to.  The recommended
    function is evdns_base_resolve_reverse_ipv6().

  @param in an IPv6 address
  @param flags either 0, or DNS_QUERY_NO_SEARCH to disable searching for this query.
  @param callback a callback function to invoke when the request is completed
  @param ptr an argument to pass to the callback function
  @return 0 if successful, or -1 if an error occurred
  @see evdns_resolve_reverse_ipv6()
 */
int evdns_resolve_reverse_ipv6(const struct in6_addr *in, int flags, evdns_callback_type callback, void *ptr);

/**
  Lookup a TXT entry for a specified DNS name.
  @param name a DNS name
  @param flags either 0, or DNS_QUERY_NO_SEARCH to disable searching for this query.
  @param callback a callback function to invoke when the request is completed
  @param ptr an argument to pass to the callback function
  @return 0 if successful, or -1 if an error occurred
*/
int evdns_resolve_txt(const char *in, int flags, evdns_callback_type callback, void *ptr);


/**
  Set the value of a configuration option.

  The currently available configuration options are:

    ndots, timeout, max-timeouts, max-inflight, and attempts

  @deprecated This function is deprecated because it does not allow the
    caller to specify which evdns_base it applies to.  The recommended
    function is evdns_base_set_option().

  @param option the name of the configuration option to be modified
  @param val the value to be set
  @param flags either 0 | DNS_OPTION_SEARCH | DNS_OPTION_MISC
  @return 0 if successful, or -1 if an error occurred
 */
int evdns_set_option(const char *option, const char *val, int flags);

/**
  Parse a resolv.conf file.

  The 'flags' parameter determines what information is parsed from the
  resolv.conf file. See the man page for resolv.conf for the format of this
  file.

  The following directives are not parsed from the file: sortlist, rotate,
  no-check-names, inet6, debug.

  If this function encounters an error, the possible return values are: 1 =
  failed to open file, 2 = failed to stat file, 3 = file too large, 4 = out of
  memory, 5 = short read from file, 6 = no nameservers listed in the file

  @deprecated This function is deprecated because it does not allow the
    caller to specify which evdns_base it applies to.  The recommended
    function is evdns_base_resolv_conf_parse().

  @param flags any of DNS_OPTION_NAMESERVERS|DNS_OPTION_SEARCH|DNS_OPTION_MISC|
         DNS_OPTIONS_ALL
  @param filename the path to the resolv.conf file
  @return 0 if successful, or various positive error codes if an error
          occurred (see above)
  @see resolv.conf(3), evdns_config_windows_nameservers()
 */
int evdns_resolv_conf_parse(int flags, const char *const filename);

/**
  Clear the list of search domains.

  @deprecated This function is deprecated because it does not allow the
    caller to specify which evdns_base it applies to.  The recommended
    function is evdns_base_search_clear().
 */
void evdns_search_clear(void);

/**
  Add a domain to the list of search domains

  @deprecated This function is deprecated because it does not allow the
    caller to specify which evdns_base it applies to.  The recommended
    function is evdns_base_search_add().

  @param domain the domain to be added to the search list
 */
void evdns_search_add(const char *domain);

/**
  Set the 'ndots' parameter for searches.

  Sets the number of dots which, when found in a name, causes
  the first query to be without any search domain.

  @deprecated This function is deprecated because it does not allow the
    caller to specify which evdns_base it applies to.  The recommended
    function is evdns_base_search_ndots_set().

  @param ndots the new ndots parameter
 */
void evdns_search_ndots_set(const int ndots);

/**
   As evdns_server_new_with_base.

  @deprecated This function is deprecated because it does not allow the
    caller to specify which even_base it uses.  The recommended
    function is evdns_add_server_port_with_base().

*/
struct evdns_server_port *evdns_add_server_port(int socket, int is_tcp, evdns_request_callback_fn_type callback, void *user_data);


#endif /* _EVDNS_H_ */
