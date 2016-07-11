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
#include "rspamadm.h"

extern struct rspamadm_command pw_command;
extern struct rspamadm_command keypair_command;
extern struct rspamadm_command configtest_command;
extern struct rspamadm_command fuzzy_merge_command;
extern struct rspamadm_command configdump_command;
extern struct rspamadm_command control_command;
extern struct rspamadm_command confighelp_command;
extern struct rspamadm_command statconvert_command;
extern struct rspamadm_command signtool_command;
extern struct rspamadm_command lua_command;
extern struct rspamadm_command dkim_keygen_command;

const struct rspamadm_command *commands[] = {
	&help_command,
	&pw_command,
	&keypair_command,
	&configtest_command,
	&fuzzy_merge_command,
	&configdump_command,
	&control_command,
	&confighelp_command,
	&statconvert_command,
	&signtool_command,
	&lua_command,
	&dkim_keygen_command,
	NULL
};


const struct rspamadm_command *
rspamadm_search_command (const gchar *name)
{
	const struct rspamadm_command *ret = NULL;
	guint i;

	if (name == NULL) {
		name = "help";
	}

	for (i = 0; i < G_N_ELEMENTS (commands); i ++) {
		if (commands[i] != NULL) {
			if (strcmp (name, commands[i]->name) == 0) {
				ret = commands[i];
				break;
			}
		}
	}

	return ret;
}
