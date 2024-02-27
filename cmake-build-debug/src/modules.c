#include "rspamd.h"
extern module_t regexp_module;
extern module_t chartable_module;
extern module_t fuzzy_check_module;
extern module_t dkim_module;


module_t *modules[] = {
&regexp_module,
&chartable_module,
&fuzzy_check_module,
&dkim_module,
NULL
};
