#ifndef RSPAMD_CFG_XML_H
#define RSPAMD_CFG_XML_H

#include "config.h"
#include "cfg_file.h"

#define MAX_NAME 8192

#define XML_START_MISSING 1
#define XML_PARAM_MISSING 2
#define XML_EXTRA_ELEMENT 3
#define XML_UNMATCHED_TAG 4

enum xml_read_state {
	XML_READ_START,
	XML_READ_PARAM,
	XML_READ_MODULE,
	XML_READ_CLASSIFIER,
	XML_READ_STATFILE,
	XML_READ_FACTORS,
	XML_READ_METRIC,
	XML_READ_WORKER,
	XML_READ_VIEW,
	XML_READ_LOGGING,
	XML_READ_VALUE,
	XML_ERROR,
	XML_END
};

struct rspamd_xml_userdata {
	enum xml_read_state state;
	struct config_file *cfg;
	gchar section_name[MAX_NAME];
	gpointer section_pointer;
	gpointer parent_pointer;
	GHashTable *cur_attrs;
};

/* Text is NULL terminated here */
typedef gboolean (*element_handler_func) (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, int offset);

/* Callbacks */

/* Called for open tags <foo bar="baz"> */
void rspamd_xml_start_element (GMarkupParseContext	*context,
								const gchar         *element_name,
								const gchar        **attribute_names,
								const gchar        **attribute_values,
								gpointer             user_data,
								GError             **error);

/* Called for close tags </foo> */
void rspamd_xml_end_element (GMarkupParseContext	*context,
								const gchar         *element_name,
								gpointer             user_data,
								GError             **error);

/* text is not nul-terminated */
void rspamd_xml_text       (GMarkupParseContext		*context,
								const gchar         *text,
								gsize                text_len,  
								gpointer             user_data,
								GError             **error);

/* Called on error, including one set by other
* methods in the vtable. The GError should not be freed.
*/
void rspamd_xml_error	(GMarkupParseContext		*context,
								GError              *error,
								gpointer             user_data);


/* Handlers */
/* Basic xml parsing functions */
gboolean xml_handle_string (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, int offset);

/* Numeric params */
gboolean xml_handle_size (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, int offset);
gboolean xml_handle_double (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, int offset);
gboolean xml_handle_seconds (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, int offset);
gboolean xml_handle_int (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, int offset);
gboolean xml_handle_uint32 (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, int offset);
gboolean xml_handle_uint16 (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, int offset);

/* Flags */
gboolean xml_handle_boolean (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, int offset);

/* Specific params */
gboolean worker_handle_param (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, int offset);
gboolean worker_handle_type (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, int offset);
gboolean worker_handle_bind (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, int offset);

gboolean handle_factor (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, int offset);

gboolean handle_module_opt (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, int offset);

gboolean handle_log_type (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, int offset);
gboolean handle_log_level (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, int offset);

gboolean handle_lua (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, int offset);

gboolean handle_module_path (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, int offset);

gboolean handle_variable (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, int offset);
gboolean handle_composite (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, int offset);

gboolean handle_view_ip (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, int offset);
gboolean handle_view_client_ip (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, int offset);
gboolean handle_view_from (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, int offset);
gboolean handle_view_symbols (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, int offset);

gboolean handle_user_settings (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, int offset);
gboolean handle_domain_settings (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, int offset);

gboolean handle_classifier_tokenizer (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, int offset);
gboolean handle_classifier_opt (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, int offset);

gboolean handle_statfile_normalizer (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, int offset);
gboolean handle_statfile_binlog (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, int offset);
gboolean handle_statfile_binlog_rotate (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, int offset);
gboolean handle_statfile_binlog_master (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, int offset);

/* Dumper functions */
gboolean xml_dump_config (struct config_file *cfg, const char *filename);

#endif
