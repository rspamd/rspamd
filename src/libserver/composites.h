/*-
 * Copyright 2016 Vsevolod Stakhov
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
#ifndef SRC_LIBSERVER_COMPOSITES_H_
#define SRC_LIBSERVER_COMPOSITES_H_

#include "config.h"

struct rspamd_task;

/**
 * Subr for composite expressions
 */
extern const struct rspamd_atom_subr composite_expr_subr;

enum rspamd_composite_policy {
	RSPAMD_COMPOSITE_POLICY_REMOVE_ALL = 0,
	RSPAMD_COMPOSITE_POLICY_REMOVE_SYMBOL,
	RSPAMD_COMPOSITE_POLICY_REMOVE_WEIGHT,
	RSPAMD_COMPOSITE_POLICY_LEAVE,
	RSPAMD_COMPOSITE_POLICY_UNKNOWN
};

/**
 * Composite structure
 */
struct rspamd_composite {
	struct rspamd_expression *expr;
	gint id;
	enum rspamd_composite_policy policy;
};

/**
 * Process all results and form composite metrics from existent metrics as it is defined in config
 * @param task worker's task that present message from user
 */
void rspamd_make_composites (struct rspamd_task *task);

enum rspamd_composite_policy rspamd_composite_policy_from_str (const gchar *string);

#endif /* SRC_LIBSERVER_COMPOSITES_H_ */
