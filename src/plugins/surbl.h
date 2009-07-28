#ifndef RSPAMD_MODULE_SURBL
#define RSPAMD_MODULE_SURBL

#include "../config.h"
#include "../main.h"
#include "../modules.h"
#include "../cfg_file.h"
#include "../memcached.h"

#define DEFAULT_REDIRECTOR_PORT 8080
#define DEFAULT_SURBL_WEIGHT 10
#define DEFAULT_REDIRECTOR_CONNECT_TIMEOUT 1000
#define DEFAULT_REDIRECTOR_READ_TIMEOUT 5000
#define DEFAULT_SURBL_MAX_URLS 1000
#define DEFAULT_SURBL_URL_EXPIRE 86400
#define DEFAULT_SURBL_SYMBOL "SURBL_DNS"
#define DEFAULT_SURBL_SUFFIX "multi.surbl.org"

struct surbl_ctx {
	int (*filter)(struct worker_task *task);
	struct in_addr redirector_addr;
	uint16_t redirector_port;
	uint16_t weight;
	unsigned int connect_timeout;
	unsigned int read_timeout;
	unsigned int max_urls;
	unsigned int url_expire;
	GList *suffixes;
	GList *bits;
	char *metric;
	const char *tld2_file;
	const char *whitelist_file;
	GHashTable *tld2;
	GHashTable *whitelist;
	GHashTable *redirector_hosts;
	unsigned use_redirector;
	memory_pool_t *surbl_pool;
    GRegex *extract_hoster_regexp;
	GRegex *extract_normal_regexp;
	GRegex *extract_numeric_regexp;
};

struct suffix_item {
	const char *suffix;
	const char *symbol;
};

struct dns_param {
	struct uri *url;
	struct worker_task *task;
	char *host_resolve;
	struct suffix_item *suffix;
};

struct redirector_param {
	struct uri *url;
	struct worker_task *task;
	enum {
		STATE_CONNECT,
		STATE_READ,
	} state;
	struct event ev;
	int sock;
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
	uint32_t bit;
	const char *symbol;
};

#endif
