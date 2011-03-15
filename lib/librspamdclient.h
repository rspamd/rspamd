#ifndef LIBRSPAMD_CLIENT_H
#define LIBRSPAMD_CLIENT_H

#include <glib.h>

/**
 * Struct for representing symbols
 */
struct rspamd_symbol {
	gchar *name;		    /**< name */
	gchar *description;		/**< description */
	double weight;			/**< weight */
	GList *options;			/**< List of options (as const gchar *) */
};

/**
 * Struct for representing metrics
 */
struct rspamd_metric {
	gchar *name;
	gchar *action;
	double score;
	double required_score;
	double reject_score;
	gboolean is_skipped;
	GHashTable *symbols;
};

struct rspamd_connection;
/**
 * Result of scan
 */
struct rspamd_result {
	struct rspamd_connection *conn;
	gboolean is_ok;
	GHashTable *metrics;
	GHashTable *headers;
};

/*
 * Init rspamd client library
 */
void rspamd_client_init (void);

/*
 * Add rspamd server
 */
gboolean rspamd_add_server (const gchar *host, guint16 port, guint16 controller_port, GError **err);

/*
 * Set timeouts (values in milliseconds)
 */
void rspamd_set_timeout (guint connect_timeout, guint read_timeout);

/*
 * Scan message from memory
 */
struct rspamd_result * rspamd_scan_memory (const guchar *message, gsize length, GHashTable *headers, GError **err);

/*
 * Scan message from file
 */
struct rspamd_result * rspamd_scan_file (const guchar *filename, GHashTable *headers, GError **err);

/*
 * Scan message from fd
 */
struct rspamd_result * rspamd_scan_fd (int fd, GHashTable *headers, GError **err);

/*
 * Learn message from memory
 */
gboolean rspamd_learn_memory (const guchar *message, gsize length, const gchar *symbol, const gchar *password, GError **err);

/*
 * Learn message from file
 */
gboolean rspamd_learn_file (const guchar *filename, const gchar *symbol, const gchar *password, GError **err);

/*
 * Learn message from fd
 */
gboolean rspamd_learn_fd (int fd, const gchar *symbol, const gchar *password, GError **err);

/*
 * Learn message fuzzy from memory
 */
gboolean rspamd_fuzzy_memory (const guchar *message, gsize length, const gchar *password, gint weight, gint flag, gboolean delete, GError **err);

/*
 * Learn message fuzzy from file
 */
gboolean rspamd_fuzzy_file (const guchar *filename, const gchar *password, gint weight, gint flag, gboolean delete, GError **err);

/*
 * Learn message fuzzy from fd
 */
gboolean rspamd_fuzzy_fd (int fd, const gchar *password, gint weight, gint flag, gboolean delete, GError **err);

/*
 * Get statistic from server
 */
GString *rspamd_get_stat (GError **err);

/*
 * Get uptime from server
 */
GString *rspamd_get_uptime (GError **err);

/*
 * Free results
 */
void rspamd_free_result (struct rspamd_result *result);

/*
 * Close library and free associated resources
 */
void rspamd_client_close (void);

#endif
