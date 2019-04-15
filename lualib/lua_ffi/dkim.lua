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
-- @module lua_ffi/dkim
-- This module contains ffi interfaces to DKIM
--]]

local ffi = require 'ffi'

ffi.cdef[[
struct rspamd_dkim_sign_context_s;
struct rspamd_dkim_key_s;
struct rspamd_task;
enum rspamd_dkim_key_format {
  RSPAMD_DKIM_KEY_FILE = 0,
  RSPAMD_DKIM_KEY_PEM,
  RSPAMD_DKIM_KEY_BASE64,
  RSPAMD_DKIM_KEY_RAW,
};
enum rspamd_dkim_type {
	RSPAMD_DKIM_NORMAL,
	RSPAMD_DKIM_ARC_SIG,
	RSPAMD_DKIM_ARC_SEAL
};
struct rspamd_dkim_sign_context_s*
rspamd_create_dkim_sign_context (struct rspamd_task *task,
    struct rspamd_dkim_key_s *priv_key,
    int headers_canon,
    int body_canon,
    const char *dkim_headers,
    enum rspamd_dkim_type type,
    void *unused);
struct rspamd_dkim_key_s* rspamd_dkim_sign_key_load (const char *what, size_t len,
    enum rspamd_dkim_key_format,
    void *err);
void rspamd_dkim_key_unref (struct rspamd_dkim_key_s *k);
struct GString *rspamd_dkim_sign (struct rspamd_task *task,
    const char *selector,
    const char *domain,
    unsigned long expire,
    size_t len,
    unsigned int idx,
    const char *arc_cv,
    struct rspamd_dkim_sign_context_s *ctx);
]]

local function load_sign_key(what, format)
  if not format then
    format = ffi.C.RSPAMD_DKIM_KEY_PEM
  else
    if format == 'file' then
      format = ffi.C.RSPAMD_DKIM_KEY_FILE
    elseif format == 'base64' then
      format = ffi.C.RSPAMD_DKIM_KEY_BASE64
    elseif format == 'raw' then
      format = ffi.C.RSPAMD_DKIM_KEY_RAW
    else
      return nil,'unknown key format'
    end
  end

  return ffi.C.rspamd_dkim_sign_key_load(what, #what, format, nil)
end

local default_dkim_headers =
"(o)from:(o)sender:(o)reply-to:(o)subject:(o)date:(o)message-id:" ..
"(o)to:(o)cc:(o)mime-version:(o)content-type:(o)content-transfer-encoding:" ..
"resent-to:resent-cc:resent-from:resent-sender:resent-message-id:" ..
"(o)in-reply-to:(o)references:list-id:list-owner:list-unsubscribe:" ..
"list-subscribe:list-post:(o)openpgp:(o)autocrypt"

local function create_sign_context(task, privkey, dkim_headers, sign_type)
  if not task or not privkey then
    return nil,'invalid arguments'
  end

  if not dkim_headers then
    dkim_headers = default_dkim_headers
  end

  if not sign_type then
    sign_type = 'dkim'
  end

  if sign_type == 'dkim' then
    sign_type = ffi.C.RSPAMD_DKIM_NORMAL
  elseif sign_type == 'arc-sig' then
    sign_type = ffi.C.RSPAMD_DKIM_ARC_SIG
  elseif sign_type == 'arc-seal' then
    sign_type = ffi.C.RSPAMD_DKIM_ARC_SEAL
  else
    return nil,'invalid sign type'
  end


  return ffi.C.rspamd_create_dkim_sign_context(task:topointer(), privkey,
      1, 1, dkim_headers, sign_type, nil)
end

local function do_sign(task, sign_context, selector, domain,
                       expire, len, arc_idx)
  if not task or not sign_context or not selector or not domain then
    return nil,'invalid arguments'
  end

  if not expire then expire = 0 end
  if not len then len = 0 end
  if not arc_idx then arc_idx = 0 end

  local gstring = ffi.C.rspamd_dkim_sign(task:topointer(), selector, domain, expire, len, arc_idx, nil, sign_context)

  if not gstring then
    return nil,'cannot sign'
  end

  local ret = ffi.string(gstring.str, gstring.len)
  ffi.C.g_string_free(gstring, true)

  return ret
end

return {
  load_sign_key = load_sign_key,
  create_sign_context = create_sign_context,
  do_sign = do_sign
}
