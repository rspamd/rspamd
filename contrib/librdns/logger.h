/* Copyright (c) 2014, Vsevolod Stakhov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *       * Redistributions of source code must retain the above copyright
 *         notice, this list of conditions and the following disclaimer.
 *       * Redistributions in binary form must reproduce the above copyright
 *         notice, this list of conditions and the following disclaimer in the
 *         documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED ''AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#ifndef LOGGER_H_
#define LOGGER_H_

#include <stdarg.h>
#include "dns_private.h"

#ifdef __GNUC__
__attribute__((format(printf, 4, 0)))
#endif
void rdns_logger_internal (void *log_data, enum rdns_log_level level,
		const char *function, const char *format,
		va_list args);

#ifdef __GNUC__
__attribute__((format(printf, 4, 5)))
#endif
void rdns_logger_helper (struct rdns_resolver *resolver,
		enum rdns_log_level level,
		const char *function, const char *format, ...);

#define rdns_err(...) do { rdns_logger_helper (resolver, RDNS_LOG_ERROR, __func__, __VA_ARGS__); } while (0)
#define rdns_warn(...) do { rdns_logger_helper (resolver, RDNS_LOG_WARNING, __func__, __VA_ARGS__); } while (0)
#define rdns_info(...) do { rdns_logger_helper (resolver, RDNS_LOG_INFO, __func__, __VA_ARGS__); } while (0)
#define rdns_debug(...) do { rdns_logger_helper (resolver, RDNS_LOG_DEBUG, __func__, __VA_ARGS__); } while (0)

#endif /* LOGGER_H_ */
