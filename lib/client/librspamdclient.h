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
struct rspamd_client;
struct in_addr;

/**
 * Result of scan
 */
struct rspamd_result {
	struct rspamd_connection *conn;
	gboolean is_ok;
	GHashTable *metrics;
	GHashTable *headers;
};

/**
 * Result of controller command
 */
struct rspamd_controller_result {
	struct rspamd_connection *conn;
	const gchar *server_name;
	gint code;
	GString *result;
	GHashTable *headers;
	GString *data;
};

/**
 * Init rspamd client library
 */
struct rspamd_client* rspamd_client_init (void);

/**
 * Init rspamd client library and bind it
 */
struct rspamd_client* rspamd_client_init_binded (const struct in_addr *local_addr);

/**
 * Add rspamd server
 */
gboolean rspamd_add_server (struct rspamd_client* client, const gchar *host,
		guint16 port, guint16 controller_port, GError **err);

/**
 * Set timeouts (values in milliseconds)
 */
void rspamd_set_timeout (struct rspamd_client* client, guint connect_timeout, guint read_timeout);

/**
 * Scan message from memory
 */
struct rspamd_result * rspamd_scan_memory (struct rspamd_client* client, const guchar *message, gsize length, GHashTable *headers, GError **err);

/**
 * Scan message from file
 */
struct rspamd_result * rspamd_scan_file (struct rspamd_client* client, const guchar *filename, GHashTable *headers, GError **err);

/**
 * Scan message from fd
 */
struct rspamd_result * rspamd_scan_fd (struct rspamd_client* client, int fd, GHashTable *headers, GError **err);

/**
 * Perform a simple controller command on all rspamd servers
 * @param client  rspamd client
 * @param command command to send
 * @param password password (NULL if no password required)
 * @param in_headers custom in headers, specific for this command (or NULL)
 * @param err error object (should be pointer to NULL object)
 * @return list of rspamd_controller_result structures for each server
 */
GList* rspamd_controller_command_simple (struct rspamd_client* client, const gchar *command, const gchar *password,
		GHashTable *in_headers, GError **err);

/**
 * Perform a controller command on all rspamd servers with in memory argument
 * @param client  rspamd client
 * @param command command to send
 * @param password password (NULL if no password required)
 * @param in_headers custom in headers, specific for this command (or NULL)
 * @param message data to pass to the controller
 * @param length its length
 * @param err error object (should be pointer to NULL object)
 * @return list of rspamd_controller_result structures for each server
 */
GList* rspamd_controller_command_memory (struct rspamd_client* client, const gchar *command, const gchar *password,
		GHashTable *in_headers, const guchar *message, gsize length, GError **err);

/**
 * Perform a controller command on all rspamd servers with descriptor argument
 * @param client  rspamd client
 * @param command command to send
 * @param password password (NULL if no password required)
 * @param in_headers custom in headers, specific for this command (or NULL)
 * @param fd file descriptor of data
 * @param err error object (should be pointer to NULL object)
 * @return list of rspamd_controller_result structures for each server
 */
GList* rspamd_controller_command_fd (struct rspamd_client* client, const gchar *command, const gchar *password,
		GHashTable *in_headers, gint fd, GError **err);

/**
 * Perform a controller command on all rspamd servers with descriptor argument
 * @param client  rspamd client
 * @param command command to send
 * @param password password (NULL if no password required)
 * @param in_headers custom in headers, specific for this command (or NULL)
 * @param filename filename of data
 * @param err error object (should be pointer to NULL object)
 * @return list of rspamd_controller_result structures for each server
 */
GList* rspamd_controller_command_file (struct rspamd_client* client, const gchar *command, const gchar *password,
		GHashTable *in_headers, const gchar *filename, GError **err);

/*
 * Free results
 */
void rspamd_free_result (struct rspamd_result *result);

/*
 * Free controller results
 */
void rspamd_free_controller_result (struct rspamd_controller_result *result);

/*
 * Close library and free associated resources
 */
void rspamd_client_close (struct rspamd_client *client);

#endif
