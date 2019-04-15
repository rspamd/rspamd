--[[
Copyright (c) 2019, Vsevolod Stakhov <vsevolod@highsecure.ru>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
]]--

--[[[
-- @module lua_ffi/common
-- Common ffi definitions
--]]

local ffi = require 'ffi'

ffi.cdef[[
struct GString {
  char  *str;
  size_t len;
  size_t allocated_len;
};
struct GArray {
  char *data;
  unsigned len;
};
typedef void (*ref_dtor_cb_t)(void *data);
struct ref_entry_s {
	unsigned int refcount;
	ref_dtor_cb_t dtor;
};

void g_string_free (struct GString *st, int free_data);
void g_free (void *p);
long rspamd_snprintf (char *buf, long max, const char *fmt, ...);
]]

return {}