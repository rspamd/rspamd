#ifndef RSPAMD_CFG_XML_H
#define RSPAMD_CFG_XML_H

#include "config.h"
#include "cfg_file.h"

#define MAX_NAME 8192

#define XML_START_MISSING 1
#define XML_PARAM_MISSING 2
#define XML_EXTRA_ELEMENT 3
#define XML_UNMATCHED_TAG 4
#define XML_INVALID_ATTR 5

#define MAX_INHERIT 5

enum xml_read_state {
	XML_READ_START,
	XML_READ_PARAM,
	XML_READ_MODULE,
	XML_READ_MODULE_META,
	XML_READ_MODULES,
	XML_READ_CLASSIFIER,
	XML_READ_STATFILE,
	XML_READ_METRIC,
	XML_READ_WORKER,
	XML_READ_VIEW,
	XML_READ_LOGGING,
	XML_READ_OPTIONS,
	XML_READ_VALUE,
	XML_SKIP_ELEMENTS,
	XML_ERROR,
	XML_SUBPARSER,
	XML_END
};

enum module_opt_type {
	MODULE_OPT_TYPE_STRING = 0,
	MODULE_OPT_TYPE_INT,
	MODULE_OPT_TYPE_UINT,
	MODULE_OPT_TYPE_DOUBLE,
	MODULE_OPT_TYPE_TIME,
	MODULE_OPT_TYPE_MAP,
	MODULE_OPT_TYPE_SIZE,
	MODULE_OPT_TYPE_FLAG,
	MODULE_OPT_TYPE_META,
	MODULE_OPT_TYPE_ANY
};

/**
 * Structure that is used for semantic resolution of configuration
 */
struct rspamd_xml_userdata {
	enum xml_read_state state;				/*< state of parser							*/
	struct config_file *cfg;				/*< configuration object 					*/
	gchar section_name[MAX_NAME];			/*< current section							*/
	gpointer section_pointer;				/*< pointer to object related with section	*/
	gpointer parent_pointer[MAX_INHERIT];	/*< parent's section object					*/
	GHashTable *cur_attrs;					/*< attributes of current tag				*/
	GQueue *if_stack;						/*< stack of if elements					*/
};

/* Text is NULL terminated here */
typedef gboolean (*element_handler_func) (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, gint offset);
typedef gboolean (*element_default_handler_func) (struct config_file *cfg, struct rspamd_xml_userdata *ctx, const gchar *tag, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, gint offset);

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
gboolean xml_handle_string (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, gint offset);
gboolean xml_handle_string_list (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, gint offset);

/* Handle glist attributes as strings */
gboolean xml_handle_list (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, gint offset);

/* Numeric params */
gboolean xml_handle_size (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, gint offset);
gboolean xml_handle_size_64 (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, gint offset);
gboolean xml_handle_double (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, gint offset);
gboolean xml_handle_seconds (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, gint offset);
gboolean xml_handle_seconds_double (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, gint offset);
gboolean xml_handle_int (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, gint offset);
gboolean xml_handle_uint32 (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, gint offset);
gboolean xml_handle_uint16 (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, gint offset);

/* Flags */
gboolean xml_handle_boolean (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, gint offset);

/* For deprecated attributes */
gboolean xml_handle_deprecated (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, gint offset);

/* Specific params */
/* Options specific */
gboolean options_handle_nameserver (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, gint offset);
/* Handle workers param */
gboolean worker_handle_param (struct config_file *cfg, struct rspamd_xml_userdata *ctx, const gchar *tag, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, gint offset);
gboolean worker_handle_type (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, gint offset);
gboolean worker_handle_bind (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, gint offset);

/* Handle metric symbol */
gboolean handle_metric_symbol (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, gint offset);
gboolean handle_metric_action (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, gint offset);

/* Handle common module option */
gboolean handle_module_opt (struct config_file *cfg, struct rspamd_xml_userdata *ctx, const gchar *tag, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, gint offset);
gboolean handle_module_meta (struct config_file *cfg, struct rspamd_xml_userdata *ctx, const gchar *tag, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, gint offset);

/* Handle loging params */
gboolean handle_log_type (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, gint offset);
gboolean handle_log_level (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, gint offset);

/* Handle lua include */
gboolean handle_lua (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, gint offset);

/* Handle path to modules */
gboolean handle_module_path (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, gint offset);

/* Handle variables and composites */
gboolean handle_variable (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, gint offset);
gboolean handle_composite (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, gint offset);

/* Handle views */
gboolean handle_view_ip (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, gint offset);
gboolean handle_view_client_ip (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, gint offset);
gboolean handle_view_from (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, gint offset);
gboolean handle_view_rcpt (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, gint offset);
gboolean handle_view_symbols (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, gint offset);

/* Handle settings */
gboolean handle_user_settings (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, gint offset);
gboolean handle_domain_settings (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, gint offset);

/* Handle classifier */
gboolean handle_classifier_tokenizer (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, gint offset);
gboolean handle_classifier_opt (struct config_file *cfg, struct rspamd_xml_userdata *ctx, const gchar *tag, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, gint offset);

/* Handle statfile */
gboolean handle_statfile_normalizer (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, gint offset);
gboolean handle_statfile_binlog (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, gint offset);
gboolean handle_statfile_binlog_rotate (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, gint offset);
gboolean handle_statfile_binlog_master (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, gint offset);
gboolean handle_statfile_opt (struct config_file *cfg, struct rspamd_xml_userdata *ctx, const gchar *tag, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, gint offset);

/* Register new module option */
void register_module_opt (const gchar *mname, const gchar *optname, enum module_opt_type type);

/* Register new worker's options */
void register_worker_opt (gint wtype, const gchar *optname, element_handler_func func, gpointer dest_struct, gint offset);

/* Register new classifier option */
void register_classifier_opt (const gchar *ctype, const gchar *optname);

/* Register new xml subparser */
void register_subparser (const gchar *tag, enum xml_read_state state,
		const GMarkupParser *parser, void (*fin_func)(gpointer ud), gpointer user_data);

/* Check validity of module option */
gboolean check_module_option (const gchar *mname, const gchar *optname, const gchar *data);

/* Dumper functions */
gboolean xml_dump_config (struct config_file *cfg, const gchar *filename);

/* XML error quark for reporting errors */
GQuark xml_error_quark (void);

#endif
