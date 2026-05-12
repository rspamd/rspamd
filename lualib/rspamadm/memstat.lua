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

local KNOWN_SUBSYSTEMS = {
  summary = true,
  process = true,
  mempool = true,
  callsites = true,
  lua = true,
  jemalloc = true,
}

local parser = argparse()
    :name "rspamadm control memstat"
    :description "Show memory usage statistics across all workers"
    :help_description_margin(32)
parser:flag "-n --number"
      :description "Disable numbers humanization"
parser:flag "-s --short"
      :description "Short output: only the per-worker summary table"
parser:flag "-c --compact"
      :description "Compact output: one line per worker per section"
parser:option "--only"
      :description "Comma-separated subsystems to show: summary,process,mempool,callsites,lua,jemalloc"
parser:option "--top"
      :description "Show top-N mempool callsites per worker (default 20)"
      :convert(tonumber)
      :default(20)
parser:flag "--no-process"
      :description "Skip per-worker process memory breakdown"
parser:flag "--no-mempool"
      :description "Skip mempool aggregate section"
parser:flag "--no-callsites"
      :description "Skip per-callsite mempool breakdown"
parser:flag "--no-lua"
      :description "Skip Lua heap section"
parser:flag "--no-jemalloc"
      :description "Skip jemalloc section"
parser:option "--callsite-sort"
      :description "Sort callsites by: suggestion, cur_bytes, total_bytes, cur_pools, total_pools (default cur_bytes)"
      :convert {
        suggestion = "suggestion",
        cur_bytes = "cur_bytes",
        total_bytes = "total_bytes",
        cur_pools = "cur_pools",
        total_pools = "total_pools",
      }
      :default("cur_bytes")
parser:option "--sort"
      :description "Sort summary table by: rss, lua, mempool, jemalloc, pid (default pid)"
      :convert {
        rss = "rss",
        lua = "lua",
        mempool = "mempool",
        jemalloc = "jemalloc",
        pid = "pid",
      }
      :default("pid")

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

local function summary_sorter(workers, mode)
  if mode == nil or mode == "pid" then
    return pid_sort
  end
  local field_map = {
    rss = "rss_kb",
    lua = "lua_kb",
    mempool = "mempool_bytes",
    jemalloc = "jemalloc_allocated",
  }
  local field = field_map[mode]
  if not field then
    return pid_sort
  end
  return function(a, b)
    local av = workers[a] and workers[a][field] or 0
    local bv = workers[b] and workers[b][field] or 0
    if av == bv then
      return tonumber(a) < tonumber(b)
    end
    return av > bv
  end
end

local function build_subsystems_filter(opts)
  -- Returns a table keyed by subsystem name with boolean values telling
  -- whether to show that subsystem. --only takes precedence; otherwise
  -- everything is on except sections turned off via --no-*. --short collapses
  -- to summary only.
  local enabled = {
    summary = true, process = true, mempool = true,
    callsites = true, lua = true, jemalloc = true,
  }
  if opts.only and #opts.only > 0 then
    for k in pairs(enabled) do
      enabled[k] = false
    end
    for token in string.gmatch(opts.only, "[^,%s]+") do
      local name = token:lower()
      if KNOWN_SUBSYSTEMS[name] then
        enabled[name] = true
      else
        io.stderr:write(string.format(
            "warning: unknown subsystem '%s' in --only (ignored)\n", token))
      end
    end
    -- summary is always implied unless explicitly excluded via --no-summary,
    -- but keep --only authoritative for that too.
    return enabled
  end
  if opts.short then
    for k in pairs(enabled) do
      enabled[k] = (k == "summary")
    end
    return enabled
  end
  if opts.no_process then enabled.process = false end
  if opts.no_mempool then enabled.mempool = false end
  if opts.no_callsites then enabled.callsites = false end
  if opts.no_lua then enabled.lua = false end
  if opts.no_jemalloc then enabled.jemalloc = false end
  return enabled
end

local function print_summary(workers, total, opts)
  print("Memory usage by worker:")
  print("")
  print(string.format("  %-7s %-13s %10s %10s %10s %12s",
      "pid", "type", "RSS", "Lua", "mempool", "jemalloc"))
  print("  " .. string.rep("-", 67))

  for _, pid in ipairs(sorted_keys(workers, summary_sorter(workers, opts.sort))) do
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

-- Process memory keys we care about, in render order
local PROC_KEYS = {
  "vm_size", "vm_rss", "rss_anon", "rss_file", "rss_shmem",
  "vm_data", "vm_stack", "vm_text", "vm_lib", "vm_pte",
}

local function format_kv_line(t, keys, opts)
  local parts = {}
  for _, k in ipairs(keys) do
    local v = t[k]
    if v and v > 0 then
      table.insert(parts, string.format("%s=%s", k, bytes(v, opts.number)))
    end
  end
  return table.concat(parts, " ")
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
      if opts.compact then
        print(string.format("  %-7s %-13s %s",
            pid, w.type or "?", format_kv_line(proc, PROC_KEYS, opts)))
      else
        print(string.format("  %s (%s):", pid, w.type or "?"))
        print("    " .. format_kv_line(proc, PROC_KEYS, opts):gsub(" ", "  "))
      end
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
      local line = string.format(
          "pools=%d/%d bytes=%s chunks=%d/%d shared=%d oversized=%d frag=%s",
          a.pools_allocated or 0, a.pools_freed or 0,
          bytes(a.bytes_allocated or 0, opts.number),
          a.chunks_allocated or 0, a.chunks_freed or 0,
          a.shared_chunks_allocated or 0,
          a.oversized_chunks or 0,
          bytes(a.fragmented_size or 0, opts.number))
      if opts.compact then
        print(string.format("  %-7s %-13s %s", pid, w.type or "?", line))
      else
        print(string.format("  %s (%s):", pid, w.type or "?"))
        print("    " .. line)
      end
    end
  end
  if any then
    print("")
  end
end

local function callsite_basename(src)
  if not src then return "?" end
  -- Strip the directory portion: "src/libserver/foo.c:123" -> "foo.c:123".
  -- Filenames in callsite locations never contain '/' so the last segment
  -- is always file:line.
  local tail = string.match(src, "([^/]+)$")
  return tail or src
end

local function callsite_key(e, mode)
  if mode == "suggestion" then
    return e.cur_suggestion or 0
  elseif mode == "total_bytes" then
    return e.bytes_allocated_total or 0
  elseif mode == "cur_pools" then
    return (e.pools_allocated or 0) - (e.pools_freed or 0)
  elseif mode == "total_pools" then
    return e.pools_allocated or 0
  end
  -- default cur_bytes
  return e.bytes_currently_used or 0
end

local function print_callsites(workers, opts)
  local limit = opts.top or 20
  local sort_mode = opts.callsite_sort or "cur_bytes"
  local any = false
  for _, pid in ipairs(sorted_keys(workers, pid_sort)) do
    local w = workers[pid]
    local entries = w.data and w.data.mempool and w.data.mempool.entries
    if entries and #entries > 0 then
      if not any then
        print(string.format("Top %d mempool callsites by %s:", limit, sort_mode))
        any = true
      end
      table.sort(entries, function(a, b)
        return callsite_key(a, sort_mode) > callsite_key(b, sort_mode)
      end)
      print(string.format("  %s (%s):", pid, w.type or "?"))
      if opts.compact then
        print(string.format("    %-32s %10s %10s %8s %8s %10s",
            "callsite", "cur_bytes", "tot_bytes", "cur_p", "tot_p", "suggest"))
        for i = 1, math.min(limit, #entries) do
          local e = entries[i]
          local cur_pools = (e.pools_allocated or 0) - (e.pools_freed or 0)
          print(string.format("    %-32s %10s %10s %8d %8d %10s",
              callsite_basename(e.src),
              bytes(e.bytes_currently_used or 0, opts.number),
              bytes(e.bytes_allocated_total or 0, opts.number),
              cur_pools,
              e.pools_allocated or 0,
              bytes(e.cur_suggestion or 0, opts.number)))
        end
      else
        print(string.format(
            "    %-32s %10s %10s %8s %8s %10s %5s %5s %5s %10s %10s %5s",
            "callsite", "cur_bytes", "tot_bytes", "cur_p", "tot_p", "suggest",
            "elts", "vars", "dtors", "avg_frag", "avg_left", "n"))
        for i = 1, math.min(limit, #entries) do
          local e = entries[i]
          local cur_pools = (e.pools_allocated or 0) - (e.pools_freed or 0)
          print(string.format(
              "    %-32s %10s %10s %8d %8d %10s %5d %5d %5d %10s %10s %5d",
              callsite_basename(e.src),
              bytes(e.bytes_currently_used or 0, opts.number),
              bytes(e.bytes_allocated_total or 0, opts.number),
              cur_pools,
              e.pools_allocated or 0,
              bytes(e.cur_suggestion or 0, opts.number),
              e.cur_elts or 0,
              e.cur_vars or 0,
              e.cur_dtors or 0,
              bytes(e.avg_fragmentation or 0, opts.number),
              bytes(e.avg_leftover or 0, opts.number),
              e.samples or 0))
        end
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
      print(string.format("  %-7s %-13s %s",
          pid, w.type or "?",
          bytes(lua.used_bytes or 0, opts.number)))
    end
  end
  if any then
    print("")
  end
end

local JEMALLOC_STATS_KEYS = {
  "allocated", "active", "metadata", "resident", "mapped", "retained",
}

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

      if opts.compact then
        local s = j.stats or {}
        local arenas_count = j.arenas and #j.arenas or 0
        print(string.format("  %-7s %-13s alloc=%s active=%s mapped=%s resident=%s retained=%s arenas=%d",
            pid, w.type or "?",
            bytes(s.allocated or 0, opts.number),
            bytes(s.active or 0, opts.number),
            bytes(s.mapped or 0, opts.number),
            bytes(s.resident or 0, opts.number),
            bytes(s.retained or 0, opts.number),
            arenas_count))
      else
        print(string.format("  %s (%s):", pid, w.type or "?"))

        if j.config then
          local cfg_parts = {}
          if j.config.version then
            table.insert(cfg_parts, string.format("version=%s", tostring(j.config.version)))
          end
          if j.config.narenas then
            table.insert(cfg_parts, string.format("narenas=%d", j.config.narenas))
          end
          if j.config.page_size then
            table.insert(cfg_parts, string.format("page=%s",
                bytes(j.config.page_size, opts.number)))
          end
          if j.config.dirty_decay_ms ~= nil then
            table.insert(cfg_parts, string.format("dirty_decay=%dms", j.config.dirty_decay_ms))
          end
          if j.config.muzzy_decay_ms ~= nil then
            table.insert(cfg_parts, string.format("muzzy_decay=%dms", j.config.muzzy_decay_ms))
          end
          if #cfg_parts > 0 then
            print("    config: " .. table.concat(cfg_parts, " "))
          end
        end

        if j.stats then
          print("    totals: " .. format_kv_line(j.stats, JEMALLOC_STATS_KEYS, opts))
        end

        if j.arenas and #j.arenas > 0 then
          print(string.format("    %4s %10s %10s %10s %10s %10s %10s %10s %10s %5s",
              "id", "alloc", "small", "large", "mapped", "retained",
              "resident", "dirty", "muzzy", "thr"))
          for _, a in ipairs(j.arenas) do
            print(string.format("    %4d %10s %10s %10s %10s %10s %10s %10s %10s %5d",
                a.id or 0,
                bytes(a.allocated or 0, opts.number),
                bytes(a.small_allocated or 0, opts.number),
                bytes(a.large_allocated or 0, opts.number),
                bytes(a.mapped or 0, opts.number),
                bytes(a.retained or 0, opts.number),
                bytes(a.resident or 0, opts.number),
                bytes(a.dirty or 0, opts.number),
                bytes(a.muzzy or 0, opts.number),
                a.nthreads or 0))
          end
        end
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
  local enabled = build_subsystems_filter(opts)

  if enabled.summary then
    print_summary(workers, total, opts)
  end
  if enabled.process then
    print_process(workers, opts)
  end
  if enabled.mempool then
    print_mempool_aggregate(workers, opts)
  end
  if enabled.callsites then
    print_callsites(workers, opts)
  end
  if enabled.lua then
    print_lua(workers, opts)
  end
  if enabled.jemalloc then
    print_jemalloc(workers, opts)
  end
end
