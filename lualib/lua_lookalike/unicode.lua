--[[
Unicode helpers for the lookalike-sender module: UTF-8 <-> code points, the per-code-point
maps (confusable fold skeleton, casefold, NFKC-casefold) bundled from the impersonation-detector
engine, invisible-character stripping, and UTS #39 script / character-class lookups.

Lua 5.1 / LuaJIT compatible (no bitops, no utf8 library). The per-code-point maps are a compact,
pre-computed form of the Unicode confusables and normalization data: each table entry maps one
code point to the string the engine would produce for it, so applying the map code-point by
code-point reproduces the engine's skeleton()/casefold()/tokenise() for the inputs that occur in
mail (sender names, domains, URL hosts). See data/README for the one documented limitation
(cross-code-point canonical reordering of stacked combining marks, which cannot occur in a DNS
hostname and is verified absent on the engine's full benchmark corpus).
]]--

local M = {}

local here = (...):gsub("%.unicode$", "")
local CPFOLD = require(here .. ".data.cpfold")
local CPCASE = require(here .. ".data.cpcase")
local CPNORM = require(here .. ".data.cpnorm")
local SCRIPTS = require(here .. ".data.scripts")
local WORDCHARS = require(here .. ".data.wordchars")
local DIGITS = require(here .. ".data.digits")

-- --- UTF-8 ------------------------------------------------------------------

--- Decode a UTF-8 string into an array of code points. Invalid bytes fall back to their byte
--- value (Latin-1), which keeps the function total; valid UTF-8 (what Rspamd supplies) decodes
--- exactly.
function M.codepoints(s)
  local cps = {}
  local i, n = 1, #s
  while i <= n do
    local b = string.byte(s, i)
    local cp, size
    if b < 0x80 then cp, size = b, 1
    elseif b >= 0xF0 then cp, size = b - 0xF0, 4
    elseif b >= 0xE0 then cp, size = b - 0xE0, 3
    elseif b >= 0xC0 then cp, size = b - 0xC0, 2
    else cp, size = b, 1 end -- stray continuation byte: pass through
    if size > 1 then
      local ok = true
      for k = 1, size - 1 do
        local cb = string.byte(s, i + k)
        if not cb or cb < 0x80 or cb >= 0xC0 then ok = false; break end
        cp = cp * 0x40 + (cb - 0x80)
      end
      if not ok then cp, size = b, 1 end
    end
    cps[#cps + 1] = cp
    i = i + size
  end
  return cps
end

--- Encode one code point as a UTF-8 string.
function M.encode(cp)
  if cp < 0x80 then
    return string.char(cp)
  elseif cp < 0x800 then
    return string.char(0xC0 + math.floor(cp / 0x40), 0x80 + (cp % 0x40))
  elseif cp < 0x10000 then
    return string.char(0xE0 + math.floor(cp / 0x1000),
      0x80 + (math.floor(cp / 0x40) % 0x40), 0x80 + (cp % 0x40))
  else
    return string.char(0xF0 + math.floor(cp / 0x40000),
      0x80 + (math.floor(cp / 0x1000) % 0x40),
      0x80 + (math.floor(cp / 0x40) % 0x40), 0x80 + (cp % 0x40))
  end
end

--- Number of code points in a UTF-8 string.
function M.len(s)
  return #M.codepoints(s)
end

--- Map each code point of `s` through `tbl` (code point -> replacement string), leaving code
--- points not in `tbl` unchanged; concatenate the result.
local function map_concat(s, tbl)
  local cps = M.codepoints(s)
  local out = {}
  for k = 1, #cps do
    local cp = cps[k]
    out[k] = tbl[cp] or M.encode(cp)
  end
  return table.concat(out)
end
M.map_concat = map_concat

--- UTS #39 confusable skeleton, case-folded (the engine's foldSkeleton).
function M.fold_skeleton(s)
  if s == "" then return "" end
  return map_concat(s, CPFOLD)
end

--- Python/JS-equivalent str.casefold() (the engine's casefold).
function M.casefold(s)
  if s == "" then return "" end
  return map_concat(s, CPCASE)
end

--- casefold(NFKC(s)): the normalization the engine's tokenise() applies.
function M.nfkc_casefold(s)
  if s == "" then return "" end
  return map_concat(s, CPNORM)
end

-- --- invisibles / controls --------------------------------------------------

-- Matches impersonation-detector domains.py INVISIBLE_CODEPOINTS + CONTROL.
local INVISIBLE = {
  [0x200b] = true, [0x200c] = true, [0x200d] = true, [0x2060] = true, [0xfeff] = true,
  [0x00ad] = true, [0x034f] = true, [0x061c] = true, [0x180e] = true,
}
for cp = 0x2061, 0x2064 do INVISIBLE[cp] = true end
for cp = 0x206a, 0x206f do INVISIBLE[cp] = true end
for cp = 0xe0000, 0xe007f do INVISIBLE[cp] = true end

local function is_control(cp)
  return (cp >= 0x00 and cp <= 0x08) or cp == 0x0b or cp == 0x0c
    or (cp >= 0x0e and cp <= 0x1f) or (cp >= 0x7f and cp <= 0x9f)
end

local function is_hidden(cp)
  return INVISIBLE[cp] or is_control(cp)
end

function M.has_invisible(s)
  local cps = M.codepoints(s)
  for k = 1, #cps do if is_hidden(cps[k]) then return true end end
  return false
end

function M.strip_invisible(s)
  local cps = M.codepoints(s)
  local out = {}
  for k = 1, #cps do
    local cp = cps[k]
    if not is_hidden(cp) then out[#out + 1] = M.encode(cp) end
  end
  return table.concat(out)
end

-- --- ranges (scripts / word chars / digits) ---------------------------------

--- Binary search an array of {lo, hi, value} ranges sorted by lo; return value or nil.
local function range_lookup(ranges, cp)
  local lo, hi = 1, #ranges + 1
  while lo < hi do
    local mid = math.floor((lo + hi) / 2)
    if ranges[mid][1] <= cp then lo = mid + 1 else hi = mid end
  end
  local i = lo - 1
  if i >= 1 then
    local r = ranges[i]
    if r[1] <= cp and cp <= r[2] then return r[3] end
  end
  return nil
end
M.range_lookup = range_lookup

function M.script_of(cp)
  return range_lookup(SCRIPTS, cp) or "Unknown"
end

function M.is_word_cp(cp)
  return cp == 0x5f or range_lookup(WORDCHARS, cp) ~= nil -- '_' or \p{L}\p{N}
end

function M.is_digit_cp(cp)
  return range_lookup(DIGITS, cp) ~= nil -- \p{Nd}
end

-- --- scripts / mixed-script (UTS #39 section 5) ------------------------------

local NEUTRAL = { Common = true, Inherited = true, Unknown = true }
local ALLOWED = {
  { Latin = true, Han = true, Hiragana = true, Katakana = true },
  { Latin = true, Han = true, Bopomofo = true },
  { Latin = true, Han = true, Hangul = true },
}

function M.scripts_in(s)
  local cps = M.codepoints(s)
  local found = {}
  for k = 1, #cps do
    local sc = M.script_of(cps[k])
    if not NEUTRAL[sc] then found[sc] = true end
  end
  return found
end

function M.sorted_scripts(s)
  local found = M.scripts_in(s)
  local list = {}
  for sc in pairs(found) do list[#list + 1] = sc end
  table.sort(list)
  return list
end

function M.is_mixed_script(s)
  local found = M.scripts_in(s)
  local n = 0
  for _ in pairs(found) do n = n + 1 end
  if n <= 1 then return false end
  for _, combo in ipairs(ALLOWED) do
    local all = true
    for sc in pairs(found) do if not combo[sc] then all = false; break end end
    if all then return false end
  end
  return true
end

return M
