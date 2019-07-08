/*-
 * Copyright 2019 Vsevolod Stakhov
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef RSPAMD_CFG_FILE_PRIVATE_H
#define RSPAMD_CFG_FILE_PRIVATE_H

#include "cfg_file.h"
#include "../../contrib/mumhash/mum.h"
#define HASH_CASELESS
#include "uthash_strcase.h"

#ifdef  __cplusplus
extern "C" {
#endif

/**
 * Action config definition
 */
struct rspamd_action {
	enum rspamd_action_type action_type;
	enum rspamd_action_flags flags;
	guint priority;
	gint lua_handler_ref; /* If special handling is needed */
	gdouble threshold;
	gchar *name;
	struct UT_hash_handle hh; /* Index by name */
};

#ifdef  __cplusplus
}
#endif

#endif
