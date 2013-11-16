#ifndef RSPAMD_CFG_XML_H
#define RSPAMD_CFG_XML_H

#include "config.h"
#include "cfg_file.h"

#define MAX_NAME 128

#define XML_START_MISSING 1
#define XML_PARAM_MISSING 2
#define XML_EXTRA_ELEMENT 3
#define XML_UNMATCHED_TAG 4
#define XML_INVALID_ATTR 5

#define MAX_INHERIT 5

/**
 * Structure that is used for semantic resolution of configuration
 */
struct rspamd_xml_userdata {
	int state;				/*< state of parser							*/
	struct config_file *cfg;				/*< configuration object 					*/
	gchar section_name[MAX_INHERIT][MAX_NAME];			/*< current section							*/
	gpointer section_pointer;				/*< pointer to object related with section	*/
	gpointer parent_pointer[MAX_INHERIT];	/*< parent's section object					*/
	GHashTable *cur_attrs;					/*< attributes of current tag				*/
	gint nested;
};


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


/* XML error quark for reporting errors */
GQuark xml_error_quark (void);

void  rspamd_xml_error (GMarkupParseContext *context, GError *error, gpointer user_data);

#endif
