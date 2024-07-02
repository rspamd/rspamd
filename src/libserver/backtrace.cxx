/*
 * Copyright 2024 Vsevolod Stakhov
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

#include "config.h"

#ifdef BACKWARD_ENABLE

#include "contrib/backward-cpp/backward.hpp"
#include "fmt/base.h"
#include "logger.h"

namespace rspamd {

void log_backtrace(void)
{
	using namespace backward;
	StackTrace st;
	st.load_here(128);

	TraceResolver tr;
	tr.load_stacktrace(st);

	for (auto i = 0ul; i < st.size(); ++i) {
		auto trace = tr.resolve(st[i]);
		auto trace_line = fmt::format("#{}: [{}]: ", i, trace.addr);

		if (!trace.source.filename.empty()) {
			trace_line += fmt::format("{}:{} in {}", trace.source.filename, trace.source.line, trace.source.function);
		}
		else {
			trace_line += fmt::format("{} in {}", trace.object_filename, trace.object_function);
		}

		msg_err("%s", trace_line.c_str());
	}
}

}// namespace rspamd
#endif

extern "C" void rspamd_print_crash(void);

void rspamd_print_crash(void)
{
#ifdef BACKWARD_ENABLE
	rspamd::log_backtrace();
#endif
}