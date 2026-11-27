--[[
Layer 2: the explainable logistic sender/domain score.
Faithful port of the engine's scorer.ts, using the shipped weights (data/weights.lua, generated
from scorer_weights.json). Lua 5.1 / LuaJIT compatible.
]]--

local base = (...):gsub("%.scorer$", "")
local features = require(base .. ".features")
local WEIGHTS = require(base .. ".data.weights")

local M = {}
local Scorer = {}
Scorer.__index = Scorer

function M.new(protected_names, max_distance)
  local self = setmetatable({}, Scorer)
  self.extractor = features.new(protected_names, max_distance)
  self.weights = WEIGHTS.weights
  self.bias = WEIGHTS.bias
  for _, k in ipairs(features.FEATURE_NAMES) do
    if self.weights[k] == nil then error("weights missing feature: " .. k) end
  end
  return self
end

local function score_features(self, feats)
  local contrib = {}
  local z = self.bias
  for _, k in ipairs(features.FEATURE_NAMES) do
    local c = self.weights[k] * feats[k]
    contrib[k] = c
    z = z + c
  end
  local p = 1 / (1 + math.exp(-z))
  return { probability = p, features = feats, contributions = contrib }
end
M.score_features = score_features

function Scorer:score(sender)
  return score_features(self, self.extractor:extract(sender))
end

function Scorer:score_domain(host)
  local feats = features.zero_features()
  local df = self.extractor:domain_features(host)
  for k, v in pairs(df) do feats[k] = v end
  return score_features(self, feats)
end

--- Feature names that pushed the score up, strongest first.
function M.score_reasons(s)
  local items = {}
  for _, k in ipairs(features.FEATURE_NAMES) do
    local c = s.contributions[k] or 0
    if c > 0 and (s.features[k] or 0) > 0 then items[#items + 1] = { k = k, c = c } end
  end
  table.sort(items, function(a, b) return a.c > b.c end)
  local out = {}
  for _, it in ipairs(items) do out[#out + 1] = it.k end
  return out
end

return M
