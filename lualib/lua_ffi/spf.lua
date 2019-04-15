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
-- @module lua_ffi/spf
-- This module contains ffi interfaces to SPF
--]]

local ffi = require 'ffi'

ffi.cdef[[
enum spf_mech_e {
	SPF_FAIL,
	SPF_SOFT_FAIL,
	SPF_PASS,
	SPF_NEUTRAL
};
static const unsigned RSPAMD_SPF_FLAG_IPV6 = (1 << 0);
static const unsigned RSPAMD_SPF_FLAG_IPV4 = (1 << 1);
static const unsigned RSPAMD_SPF_FLAG_ANY = (1 << 3);
struct spf_addr {
	unsigned char addr6[16];
	unsigned char addr4[4];
	union {
		struct {
			uint16_t mask_v4;
			uint16_t mask_v6;
		} dual;
		uint32_t idx;
	} m;
	unsigned flags;
	enum spf_mech_e mech;
	char *spf_string;
	struct spf_addr *prev, *next;
};

struct spf_resolved {
	char *domain;
	unsigned ttl;
	int temp_failed;
	int na;
	int perm_failed;
	uint64_t digest;
	struct GArray *elts;
	struct ref_entry_s ref;
};

typedef void (*spf_cb_t)(struct spf_resolved *record,
		struct rspamd_task *task, void *data);
struct rspamd_task;
int rspamd_spf_resolve(struct rspamd_task *task, spf_cb_t callback,
		void *cbdata);
const char * rspamd_spf_get_domain (struct rspamd_task *task);
struct spf_resolved * spf_record_ref (struct spf_resolved *rec);
void spf_record_unref (struct spf_resolved *rec);
char * spf_addr_mask_to_string (struct spf_addr *addr);
struct spf_addr * spf_addr_match_task (struct rspamd_task *task, struct spf_resolved *rec);
]]

local function convert_mech(mech)
  if mech == ffi.C.SPF_FAIL then
    return 'fail'
  elseif mech == ffi.C.SPF_SOFT_FAIL then
    return 'softfail'
  elseif mech == ffi.C.SPF_PASS then
    return 'pass'
  elseif mech == ffi.C.SPF_NEUTRAL then
    return 'neutral'
  end
end

local NULL = ffi.new 'void*'

local function spf_addr_tolua(ffi_spf_addr)
  local ipstr = ffi.C.spf_addr_mask_to_string(ffi_spf_addr)
  local ret = {
    res = convert_mech(ffi_spf_addr.mech),
    ipnet = ffi.string(ipstr),
  }

  if ffi_spf_addr.spf_string ~= NULL then
    ret.spf_str = ffi.string(ffi_spf_addr.spf_string)
  end

  ffi.C.g_free(ipstr)
  return ret
end

local function spf_resolve(task, cb)
  local function spf_cb(rec, _, _)
    if not rec then
      cb(false, 'record is empty')
    else
      local nelts = rec.elts.len
      local elts = ffi.cast("struct spf_addr *", rec.elts.data)
      local res = {
        addrs = {}
      }
      local digstr = ffi.new("char[64]")
      ffi.C.rspamd_snprintf(digstr, 64, "0x%xuL", rec.digest)
      res.digest = ffi.string(digstr)
      for i = 1,nelts do
        res.addrs[i] = spf_addr_tolua(elts[i - 1])
      end

      local matched = ffi.C.spf_addr_match_task(task:topointer(), rec)

      if matched ~= NULL then
        cb(true, res, spf_addr_tolua(matched))
      else
        cb(true, res, nil)
      end
    end
  end

  local ret = ffi.C.rspamd_spf_resolve(task:topointer(), spf_cb, nil)

  if not ret then
    cb(false, 'cannot perform resolving')
  end
end

local function spf_unref(rec)
  ffi.C.spf_record_unref(rec)
end

return {
  spf_resolve = spf_resolve,
  spf_unref = spf_unref
}