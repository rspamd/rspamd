/*-
 * Copyright 2017 Vsevolod Stakhov
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

#ifndef RSPAMD_LANG_DETECTION_H
#define RSPAMD_LANG_DETECTION_H

#include "config.h"
#include "libserver/cfg_file.h"

struct rspamd_lang_detector;

struct rspamd_lang_detector* rspamd_language_detector_init (struct rspamd_config *cfg);

#endif
