/*-
 * Copyright 2025 Vsevolod Stakhov
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

#ifndef RSPAMD_HTML_CTA_HXX
#define RSPAMD_HTML_CTA_HXX

namespace rspamd::html {

struct html_content;

/**
 * Recompute CTA weights for all URLs present in the HTML document.
 */
void html_compute_cta_weights(html_content &hc);

}// namespace rspamd::html

#endif//RSPAMD_HTML_CTA_HXX
