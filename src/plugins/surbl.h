#ifndef RSPAMD_MODULE_SURBL
#define RSPAMD_MODULE_SURBL

#include "../config.h"
#include "../main.h"
#include "../modules.h"
#include "../cfg_file.h"
#include "../memcached.h"
#include "../trie.h"

#define DEFAULT_REDIRECTOR_PORT 8080
#define DEFAULT_SURBL_WEIGHT 10
#define DEFAULT_REDIRECTOR_CONNECT_TIMEOUT 1000
#define DEFAULT_REDIRECTOR_READ_TIMEOUT 5000
#define DEFAULT_SURBL_MAX_URLS 1000
#define DEFAULT_SURBL_URL_EXPIRE 86400
#define DEFAULT_SURBL_SYMBOL "SURBL_DNS"
#define DEFAULT_SURBL_SUFFIX "multi.surbl.org"
#define SURBL_OPTION_NOIP 1
#define MAX_LEVELS 10

struct redirector_upstream {
	struct upstream up;
	struct in_addr ina;
	guint16 port;
	gchar *name;
};

struct surbl_ctx {
	gint (*filter)(struct worker_task *task);
	guint16 weight;
	guint connect_timeout;
	guint read_timeout;
	guint max_urls;
	guint url_expire;
	GList *suffixes;
	GList *bits;
	gchar *metric;
	const gchar *tld2_file;
	const gchar *whitelist_file;
	gchar *redirector_symbol;
	GHashTable **exceptions;
	GHashTable *whitelist;
	GHashTable *redirector_hosts;
	rspamd_trie_t *redirector_trie;
	GPtrArray *redirector_ptrs;
	guint use_redirector;
	struct redirector_upstream *redirectors;
	guint32 redirectors_number;
	memory_pool_t *surbl_pool;
};

struct suffix_item {
	const gchar *suffix;
	const gchar *symbol;
	guint32 options;
};

struct dns_param {
	struct uri *url;
	struct worker_task *task;
	gchar *host_resolve;
	struct suffix_item *suffix;
};

struct redirector_param {
	struct uri *url;
	struct worker_task *task;
	struct redirector_upstream *redirector;
	enum {
		STATE_CONNECT,
		STATE_READ,
	} state;
	struct event ev;
	gint sock;
	GTree *tree;
	struct suffix_item *suffix;
};

struct memcached_param {
	struct uri *url;
	struct worker_task *task;
	memcached_ctx_t *ctx;
	GTree *tree;
	struct suffix_item *suffix;
};

struct surbl_bit_item {
	guint32 bit;
	const gchar *symbol;
};

#endif
