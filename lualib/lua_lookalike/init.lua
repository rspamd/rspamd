--[[
lua_lookalike: Layers 1 and 2 of the impersonation-detector engine, as a self-contained Lua
library (no Rspamd dependency, so it is unit-testable). Given an operator-configured protected
set and a message's sender and link hosts, it returns the lookalike matches, embedded-domain
findings, and the explainable logistic scores for the sender and each link host.

  local lookalike = require "lua_lookalike"
  local det = lookalike.new({ "linkedin.com", "LinkedIn" })
  local r = det:analyze({ name = "LinkedIn Support", address = "li.support@gmail.com",
                          hosts = { "linkedin-verify.app" } })
]]--

local base = ...
local uni = require(base .. ".unicode")
local dom = require(base .. ".domains")
local lookalike = require(base .. ".lookalike")
local scorer_mod = require(base .. ".scorer")

local M = {
  unicode = uni,
  domains = dom,
  distance = require(base .. ".distance"),
  lookalike = lookalike,
  features = require(base .. ".features"),
  scorer = scorer_mod,
}

local Detector = {}
Detector.__index = Detector

--- opts: { registrable_lookalike=true, skip_protected_subdomains=true,
---         brand_on_own_domain_is_benign=true, max_distance=2 }
function M.new(protected_names, opts)
  opts = opts or {}
  local self = setmetatable({}, Detector)
  self.protected = protected_names or {}
  self.registrable_lookalike = opts.registrable_lookalike ~= false
  self.skip_protected_subdomains = opts.skip_protected_subdomains ~= false
  self.max_distance = opts.max_distance or 2
  self.detector = lookalike.new(self.protected, self.max_distance)
  self.scorer = scorer_mod.new(self.protected, self.max_distance)
  self.scorer.extractor.brand_on_own_domain_is_benign = (opts.brand_on_own_domain_is_benign ~= false)
  self.protected_domains = dom.protected_domains(self.protected)
  return self
end

local function contains(list, v)
  for _, x in ipairs(list) do if x == v then return true end end
  return false
end

--- msg: { name=display, address=from-address, hosts={link hosts...} }
function Detector:analyze(msg)
  local name = msg.name or ""
  local address = msg.address or ""
  local _, _, sender_domain = dom.parse_address(address)
  local hosts = {}
  for _, h in ipairs(msg.hosts or {}) do
    local nh = dom.normalize_host(h)
    if nh ~= "" and not contains(hosts, nh) then hosts[#hosts + 1] = nh end
  end

  local result = { lookalikes = {}, embedded = {}, sender_score = nil, link_scores = {} }
  local matched_hosts = {}

  -- Layer 1: lookalike of the display name, the sender domain, and each link host.
  local candidates = {}
  for _, c in ipairs({ name, sender_domain }) do if c ~= "" then candidates[#candidates + 1] = c end end
  for _, h in ipairs(hosts) do candidates[#candidates + 1] = h end

  for _, c in ipairs(candidates) do
    local is_host = contains(hosts, c)
    local skip = self.skip_protected_subdomains and (c == sender_domain or is_host)
      and self.protected_domains[dom.registrable(c)]
    if not skip then
      for _, m in ipairs(self.detector:check(c)) do
        local where = (c == sender_domain) and "sender" or (c == name and "sender_name" or "link")
        result.lookalikes[#result.lookalikes + 1] =
          { candidate = c, protected = m.protected, reasons = m.reasons, distance = m.distance, where = where }
        if is_host then matched_hosts[c] = true end
      end
    end
  end

  if self.registrable_lookalike then
    for _, h in ipairs(hosts) do
      local reg = dom.registrable(h)
      if reg ~= "" and reg ~= h and not matched_hosts[h] and not self.protected_domains[reg] then
        for _, m in ipairs(self.detector:check(reg)) do
          result.lookalikes[#result.lookalikes + 1] =
            { candidate = h, protected = m.protected, reasons = m.reasons, distance = m.distance, where = "link" }
          matched_hosts[h] = true
        end
      end
    end
  end

  -- Embedded-domain findings on the sender domain and each link host.
  for _, h in ipairs(hosts) do
    local inner = dom.embedded_domain(h)
    if inner then result.embedded[#result.embedded + 1] = { host = h, inner = inner } end
  end

  -- Layer 2: sender score, and a domain score for each link host.
  result.sender_score = self.scorer:score({ display_name = name, address = address })
  for _, h in ipairs(hosts) do
    if not (h == sender_domain and result.sender_score.probability >= 0.5) then
      local s = self.scorer:score_domain(h)
      result.link_scores[#result.link_scores + 1] = { host = h, score = s }
    end
  end

  return result
end

return M
