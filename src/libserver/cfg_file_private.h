/*
 * Copyright 2023 Vsevolod Stakhov
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
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

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Action config definition
 */
struct rspamd_action {
	enum rspamd_action_type action_type;
	int flags; /* enum rspamd_action_flags */
	unsigned int priority;
	double threshold;
	char *name;
};

#ifdef __cplusplus
}
#endif

#endif
