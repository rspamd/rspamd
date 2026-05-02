--[[
Copyright (c) 2026, Vsevolod Stakhov <vsevolod@rspamd.com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
]] --

local rspamd_util = require "rspamd_util"
local argparse = require "argparse"

local parser = argparse()
    :name "rspamadm control memstat"
    :description "Show memory usage statistics across all workers"
    :help_description_margin(32)
parser:flag "-n --number"
      :description "Disable numbers humanization"
parser:option "--top"
      :description "Show top-N mempool callsites per worker (default 20)"
      :convert(tonumber)
      :default(20)
parser:flag "--no-callsites"
      :description "Skip per-callsite mempool breakdown"
parser:flag "--no-jemalloc"
      :description "Skip jemalloc text dump"

local function bytes(n, raw)
  if not n then
    return '-'
  end
  if raw then
    return tostring(n)
  end
  return rspamd_util.humanize_number(n)
end

local function pid_sort(a, b)
  return tonumber(a) < tonumber(b)
end

local function sorted_keys(t, cmp)
  local out = {}
  for k in pairs(t) do
    table.insert(out, k)
  end
  table.sort(out, cmp)
  return out
end

local function print_summary(workers, total, opts)
  print("Memory usage by worker:")
  print("")
  print(string.format("  %-7s %-13s %10s %10s %10s %12s",
      "pid", "type", "RSS", "Lua", "mempool", "jemalloc"))
  print("  " .. string.rep("-", 67))

  for _, pid in ipairs(sorted_keys(workers, pid_sort)) do
    local w = workers[pid]
    print(string.format("  %-7s %-13s %10s %10s %10s %12s",
        pid,
        w.type or "?",
        bytes((w.rss_kb or 0) * 1024, opts.number),
        bytes((w.lua_kb or 0) * 1024, opts.number),
        bytes(w.mempool_bytes or 0, opts.number),
        bytes(w.jemalloc_allocated or 0, opts.number)))
  end

  if total then
    print("  " .. string.rep("-", 67))
    print(string.format("  %-7s %-13s %10s %10s %10s %12s",
        "total", "",
        bytes((total.rss_kb or 0) * 1024, opts.number),
        bytes((total.lua_kb or 0) * 1024, opts.number),
        bytes(total.mempool_bytes or 0, opts.number),
        bytes(total.jemalloc_allocated or 0, opts.number)))
  end
  print("")
end

local function print_process(workers, opts)
  local any = false
  for _, pid in ipairs(sorted_keys(workers, pid_sort)) do
    local w = workers[pid]
    local proc = w.data and w.data.process
    if proc then
      if not any then
        print("Process memory:")
        any = true
      end
      print(string.format("  %s (%s):", pid, w.type or "?"))
      local fields = {
        { "vm_size",   proc.vm_size },
        { "vm_rss",    proc.vm_rss },
        { "rss_anon",  proc.rss_anon },
        { "rss_file",  proc.rss_file },
        { "rss_shmem", proc.rss_shmem },
        { "vm_data",   proc.vm_data },
        { "vm_stack",  proc.vm_stack },
        { "vm_text",   proc.vm_text },
        { "vm_lib",    proc.vm_lib },
        { "vm_pte",    proc.vm_pte },
      }
      local parts = {}
      for _, kv in ipairs(fields) do
        if kv[2] and kv[2] > 0 then
          table.insert(parts, string.format("%s=%s", kv[1], bytes(kv[2], opts.number)))
        end
      end
      print("    " .. table.concat(parts, "  "))
    end
  end
  if any then
    print("")
  end
end

local function print_mempool_aggregate(workers, opts)
  local any = false
  for _, pid in ipairs(sorted_keys(workers, pid_sort)) do
    local w = workers[pid]
    local mp = w.data and w.data.mempool
    if mp and mp.aggregate then
      if not any then
        print("Mempool aggregate:")
        any = true
      end
      local a = mp.aggregate
      print(string.format("  %s (%s):", pid, w.type or "?"))
      print(string.format(
          "    pools=%d/%d  bytes=%s  chunks=%d/%d  shared=%d  oversized=%d  fragmented=%s",
          a.pools_allocated or 0, a.pools_freed or 0,
          bytes(a.bytes_allocated or 0, opts.number),
          a.chunks_allocated or 0, a.chunks_freed or 0,
          a.shared_chunks_allocated or 0,
          a.oversized_chunks or 0,
          bytes(a.fragmented_size or 0, opts.number)))
    end
  end
  if any then
    print("")
  end
end

local function print_callsites(workers, opts)
  if opts.no_callsites then
    return
  end
  local limit = opts.top or 20
  local any = false
  for _, pid in ipairs(sorted_keys(workers, pid_sort)) do
    local w = workers[pid]
    local entries = w.data and w.data.mempool and w.data.mempool.entries
    if entries and #entries > 0 then
      if not any then
        print(string.format("Top %d mempool callsites by suggestion:", limit))
        any = true
      end
      table.sort(entries, function(a, b)
        return (a.cur_suggestion or 0) > (b.cur_suggestion or 0)
      end)
      print(string.format("  %s (%s):", pid, w.type or "?"))
      for i = 1, math.min(limit, #entries) do
        local e = entries[i]
        print(string.format(
            "    [%-9s] %-50s elts=%-4d vars=%-4d dtors=%-4d avg_frag=%-9s avg_left=%-9s n=%d",
            bytes(e.cur_suggestion or 0, opts.number),
            e.src or "?",
            e.cur_elts or 0,
            e.cur_vars or 0,
            e.cur_dtors or 0,
            bytes(e.avg_fragmentation or 0, opts.number),
            bytes(e.avg_leftover or 0, opts.number),
            e.samples or 0))
      end
    end
  end
  if any then
    print("")
  end
end

local function print_lua(workers, opts)
  local any = false
  for _, pid in ipairs(sorted_keys(workers, pid_sort)) do
    local w = workers[pid]
    local lua = w.data and w.data.lua
    if lua then
      if not any then
        print("Lua heap:")
        any = true
      end
      print(string.format("  %s (%s): %s",
          pid, w.type or "?",
          bytes(lua.used_bytes or 0, opts.number)))
    end
  end
  if any then
    print("")
  end
end

local function print_jemalloc(workers, opts)
  local any = false
  for _, pid in ipairs(sorted_keys(workers, pid_sort)) do
    local w = workers[pid]
    local j = w.data and w.data.jemalloc
    if j then
      if not any then
        print("Jemalloc:")
        any = true
      end
      print(string.format("  %s (%s):", pid, w.type or "?"))
      if j.stats then
        local parts = {}
        for _, k in ipairs({ "allocated", "active", "metadata", "resident", "mapped", "retained" }) do
          if j.stats[k] then
            table.insert(parts, string.format("%s=%s", k, bytes(j.stats[k], opts.number)))
          end
        end
        if #parts > 0 then
          print("    " .. table.concat(parts, "  "))
        end
      end
      if j.config then
        local parts = {}
        for k, v in pairs(j.config) do
          table.insert(parts, string.format("%s=%s", k, tostring(v)))
        end
        table.sort(parts)
        if #parts > 0 then
          print("    config: " .. table.concat(parts, "  "))
        end
      end
      if not opts.no_jemalloc and j.text and #j.text > 0 then
        print("    --- malloc_stats_print ---")
        for line in tostring(j.text):gmatch("[^\r\n]+") do
          print("    " .. line)
        end
        print("    --- end ---")
      end
    end
  end
  if any then
    print("")
  end
end

return function(args, res)
  local opts = parser:parse(args or {})
  local workers = res and res.workers or {}
  local total = res and res.total

  print_summary(workers, total, opts)
  print_process(workers, opts)
  print_mempool_aggregate(workers, opts)
  print_callsites(workers, opts)
  print_lua(workers, opts)
  print_jemalloc(workers, opts)
end
