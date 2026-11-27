--[[
Layer 1: deterministic lookalike detection against a protected set.
Faithful port of the engine's lookalike.ts. Lua 5.1 / LuaJIT compatible.
]]--

local base = (...):gsub("%.lookalike$", "")
local uni = require(base .. ".unicode")
local dom = require(base .. ".domains")
local distance = require(base .. ".distance")

local M = {}
local Detector = {}
Detector.__index = Detector

local function trim(s) return (s:gsub("^%s+", ""):gsub("%s+$", "")) end

function M.new(protected_names, max_distance)
  local self = setmetatable({}, Detector)
  self.max_distance = max_distance or 2
  self.protected = {}
  self.skeletons = {} -- array of {name=, skel=}
  for _, p in ipairs(protected_names or {}) do
    local t = trim(p)
    if #t > 0 then
      self.protected[#self.protected + 1] = t
      self.skeletons[#self.skeletons + 1] = { name = t, skel = uni.fold_skeleton(t) }
    end
  end
  return self
end

function Detector:threshold(name)
  local n = uni.len(name)
  if n <= 4 then return 0 end
  if n <= 8 then return math.min(self.max_distance, 1) end
  return self.max_distance
end

--- Returns an array of matches {candidate, protected, reasons={...}, distance}.
function Detector:check(candidate)
  local shown = dom.decode_idn(candidate)
  local folded = uni.casefold(shown)
  local cand_skel = uni.fold_skeleton(shown)
  local mixed = uni.is_mixed_script(shown)
  local matches = {}
  for _, entry in ipairs(self.skeletons) do
    local name, prot_skel = entry.name, entry.skel
    if folded ~= uni.casefold(name) then
      local reasons = {}
      if cand_skel == prot_skel then reasons[#reasons + 1] = "confusable-skeleton" end
      local dist = distance.osa(cand_skel, prot_skel)
      local th = self:threshold(name)
      if dist > 0 and dist <= th then reasons[#reasons + 1] = "edit-distance<=" .. th end
      if #reasons > 0 and mixed then
        reasons[#reasons + 1] = "mixed-script:" .. table.concat(uni.sorted_scripts(shown), "+")
      end
      if #reasons > 0 and shown ~= candidate then reasons[#reasons + 1] = "punycode" end
      if #reasons > 0 then
        matches[#matches + 1] = { candidate = candidate, protected = name, reasons = reasons, distance = dist }
      end
    end
  end
  table.sort(matches, function(a, b)
    if a.distance ~= b.distance then return a.distance < b.distance end
    return a.protected < b.protected
  end)
  return matches
end

function Detector:is_lookalike(candidate)
  return #self:check(candidate) > 0
end

return M
