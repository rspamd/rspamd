#ifndef RSPAMD_DNS_H
#define RSPAMD_DNS_H

#include "config.h"
#include "mem_pool.h"
#include "events.h"
#include "upstream.h"

#define MAX_SERVERS 16

#define DNS_D_MAXLABEL	63	/* + 1 '\0' */
#define DNS_D_MAXNAME	255	/* + 1 '\0' */

#define MAX_ADDRS 1

struct rspamd_dns_reply;
struct config_file;

typedef void (*dns_callback_type) (struct rspamd_dns_reply *reply, gpointer arg);
/**
 * Implements DNS server
 */
struct rspamd_dns_server {
	struct upstream up;					/**< upstream structure						*/
	struct in_addr addr;				/**< address of DNS server					*/
	gchar *name;							/**< name of DNS server						*/
	gint sock;							/**< persistent socket						*/
	struct event ev;
};

#define DNS_K_TEA_KEY_SIZE	16

struct dns_k_tea {
	guint32 key[DNS_K_TEA_KEY_SIZE / sizeof (guint32)];
	guint cycles;
}; /* struct dns_k_tea */

struct dns_k_permutor {
	guint stepi, length, limit;
	guint shift, mask, rounds;

	struct dns_k_tea tea;
};

struct rspamd_dns_resolver {
	struct rspamd_dns_server servers[MAX_SERVERS];
	gint servers_num;					/**< number of DNS servers registered		*/
	GHashTable *requests;				/**< requests in flight						*/
	struct dns_k_permutor *permutor;	/**< permutor for randomizing request id	*/
	guint request_timeout;
	guint max_retransmits;
	guint max_errors;
	memory_pool_t *static_pool;			/**< permament pool (cfg_pool)				*/
	gboolean throttling;				/**< dns servers are busy					*/
	gboolean is_master_slave;			/**< if this is true, then select upstreams as master/slave */
	guint errors;						/**< resolver errors						*/
	struct timeval throttling_time;		/**< throttling time						*/
	struct event throttling_event;		/**< throttling event						*/
};

struct dns_header;
struct dns_query;

enum rspamd_request_type {
	DNS_REQUEST_A = 0,
	DNS_REQUEST_PTR,
	DNS_REQUEST_MX,
	DNS_REQUEST_TXT,
	DNS_REQUEST_SRV,
	DNS_REQUEST_SPF
};

struct rspamd_dns_request {
	memory_pool_t *pool;				/**< pool associated with request			*/
	struct rspamd_dns_resolver *resolver;
	struct rspamd_dns_server *server;
	dns_callback_type func;
	gpointer arg;
	struct event timer_event;
	struct event io_event;
	struct timeval tv;
	guint retransmits;
	guint16 id;
	struct rspamd_async_session *session;
	struct rspamd_dns_reply *reply;
	guint8 *packet;
	const gchar *requested_name;
	off_t pos;
	guint packet_len;
	gint sock;
	enum rspamd_request_type type;
	time_t time;
};



union rspamd_reply_element {
	struct {
		struct in_addr addr[MAX_ADDRS];
		guint16 addrcount;
	} a;
	struct {
		gchar *name;
	} ptr;
	struct {
		gchar *name;
		guint16 priority;
	} mx;
	struct {
		gchar *data;
	} txt;
	struct {
		gchar *data;
	} spf;
	struct {
		guint16 priority;
		guint16 weight;
		guint16 port;
		gchar *target;
	} srv;
};

enum dns_rcode {
	DNS_RC_NOERROR	= 0,
	DNS_RC_FORMERR	= 1,
	DNS_RC_SERVFAIL	= 2,
	DNS_RC_NXDOMAIN	= 3,
	DNS_RC_NOTIMP	= 4,
	DNS_RC_REFUSED	= 5,
	DNS_RC_YXDOMAIN	= 6,
	DNS_RC_YXRRSET	= 7,
	DNS_RC_NXRRSET	= 8,
	DNS_RC_NOTAUTH	= 9,
	DNS_RC_NOTZONE	= 10,
};
	
struct rspamd_dns_reply {
	enum rspamd_request_type type;
	struct rspamd_dns_request *request;
	enum dns_rcode code;
	GList *elements;
};

/* Internal DNS structs */

struct dns_header {
		guint qid:16;

#if BYTE_ORDER == BIG_ENDIAN
		guint qr:1;
		guint opcode:4;
		guint aa:1;
		guint tc:1;
		guint rd:1;

		guint ra:1;
		guint unused:3;
		guint rcode:4;
#else
		guint rd:1;
		guint tc:1;
		guint aa:1;
		guint opcode:4;
		guint qr:1;

		guint rcode:4;
		guint unused:3;
		guint ra:1;
#endif

		guint qdcount:16;
		guint ancount:16;
		guint nscount:16;
		guint arcount:16;
};

enum dns_section {
	DNS_S_QD		= 0x01,
#define DNS_S_QUESTION		DNS_S_QD

	DNS_S_AN		= 0x02,
#define DNS_S_ANSWER		DNS_S_AN

	DNS_S_NS		= 0x04,
#define DNS_S_AUTHORITY		DNS_S_NS

	DNS_S_AR		= 0x08,
#define DNS_S_ADDITIONAL	DNS_S_AR

	DNS_S_ALL		= 0x0f
}; /* enum dns_section */

enum dns_opcode {
	DNS_OP_QUERY	= 0,
	DNS_OP_IQUERY	= 1,
	DNS_OP_STATUS	= 2,
	DNS_OP_NOTIFY	= 4,
	DNS_OP_UPDATE	= 5,
}; /* dns_opcode */

enum dns_type {
	DNS_T_A		= 1,
	DNS_T_NS	= 2,
	DNS_T_CNAME	= 5,
	DNS_T_SOA	= 6,
	DNS_T_PTR	= 12,
	DNS_T_MX	= 15,
	DNS_T_TXT	= 16,
	DNS_T_AAAA	= 28,
	DNS_T_SRV	= 33,
	DNS_T_SSHFP	= 44,
	DNS_T_SPF	= 99,

	DNS_T_ALL	= 255
}; /* enum dns_type */

enum dns_class {
	DNS_C_IN	= 1,

	DNS_C_ANY	= 255
}; /* enum dns_class */

struct dns_query {
	gchar *qname;
	guint qtype:16;
	guint qclass:16;
};

/* Rspamd DNS API */

/*
 * Init DNS resolver, params are obtained from a config file or system file /etc/resolv.conf
 */
struct rspamd_dns_resolver *dns_resolver_init (struct config_file *cfg);

/*
 * Make a DNS request
 * @param resolver resolver object
 * @param session async session to register event
 * @param pool memory pool for storage
 * @param cb callback to call on resolve completing
 * @param ud user data for callback
 * @param type request type
 * @param ... string or ip address based on a request type
 * @return TRUE if request was sent.
 */
gboolean make_dns_request (struct rspamd_dns_resolver *resolver, 
		struct rspamd_async_session *session, memory_pool_t *pool, dns_callback_type cb, 
		gpointer ud, enum rspamd_request_type type, ...);

/*
 * Get textual presentation of DNS error code
 */
const gchar *dns_strerror (enum dns_rcode rcode);

/*
 * Get textual presentation of DNS request type
 */
const gchar *dns_strtype (enum rspamd_request_type type);

#endif
