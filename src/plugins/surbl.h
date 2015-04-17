#ifndef RSPAMD_MODULE_SURBL
#define RSPAMD_MODULE_SURBL

#include "config.h"
#include "libutil/trie.h"
#include "main.h"

#define DEFAULT_REDIRECTOR_PORT 8080
#define DEFAULT_SURBL_WEIGHT 10
#define DEFAULT_REDIRECTOR_CONNECT_TIMEOUT 1.0
#define DEFAULT_REDIRECTOR_READ_TIMEOUT 5.0
#define DEFAULT_SURBL_MAX_URLS 1000
#define DEFAULT_SURBL_URL_EXPIRE 86400
#define DEFAULT_SURBL_SYMBOL "SURBL_DNS"
#define DEFAULT_SURBL_SUFFIX "multi.surbl.org"
#define SURBL_OPTION_NOIP 1
#define MAX_LEVELS 10

struct surbl_ctx {
	struct module_ctx ctx;
	guint16 weight;
	gdouble connect_timeout;
	gdouble read_timeout;
	guint max_urls;
	guint url_expire;
	GList *suffixes;
	gchar *metric;
	const gchar *tld2_file;
	const gchar *whitelist_file;
	const gchar *redirector_symbol;
	GHashTable **exceptions;
	GHashTable *whitelist;
	GHashTable *redirector_hosts;
	rspamd_trie_t *redirector_trie;
	GPtrArray *redirector_ptrs;
	guint use_redirector;
	struct upstream_list *redirectors;
	rspamd_mempool_t *surbl_pool;
};

struct suffix_item {
	const gchar *suffix;
	const gchar *symbol;
	guint32 options;
	GList *bits;
};

struct dns_param {
	struct rspamd_url *url;
	struct rspamd_task *task;
	gchar *host_resolve;
	struct suffix_item *suffix;
};

struct redirector_param {
	struct rspamd_url *url;
	struct rspamd_task *task;
	struct upstream *redirector;
	enum {
		STATE_CONNECT,
		STATE_READ
	} state;
	GString *buf;
	struct event ev;
	gint sock;
	GHashTable *tree;
	struct suffix_item *suffix;
};

struct surbl_bit_item {
	guint32 bit;
	gchar *symbol;
};

#endif
