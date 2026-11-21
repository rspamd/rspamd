--[[
Layer 2 feature extraction: the 23 named features of a sender and a domain.
Faithful port of impersonation_detector/features.py (and features.ts), including the engine's
iteration order (so tie-breaks on the nearest protected name match exactly).
Lua 5.1 / LuaJIT compatible.
]]--

local base = (...):gsub("%.features$", "")
local uni = require(base .. ".unicode")
local dom = require(base .. ".domains")
local distance = require(base .. ".distance")

local M = {}

M.FEATURE_NAMES = {
  "domain_is_protected", "domain_skeleton_match", "domain_close_typo", "domain_mixed_script",
  "domain_punycode", "domain_tld_swap", "domain_brand_affix", "domain_brand_in_subdomain",
  "domain_embeds_foreign_domain", "domain_lure_words", "domain_leet_match", "domain_free_mail",
  "domain_missing", "domain_invisible_chars",
  "display_brand_token", "display_brand_lookalike", "display_role_word",
  "display_claims_brand_off_domain", "display_invisible_chars", "display_mixed_script",
  "local_brand_token", "local_role_word", "local_brand_lookalike",
}

local function trim(s) return (s:gsub("^%s+", ""):gsub("%s+$", "")) end

local function zero_features()
  local f = {}
  for _, k in ipairs(M.FEATURE_NAMES) do f[k] = 0 end
  return f
end
M.zero_features = zero_features

local INF = 1e18

local Extractor = {}
Extractor.__index = Extractor

function M.new(protected_names, max_distance)
  local self = setmetatable({}, Extractor)
  self.max_distance = max_distance or 2
  self.brand_on_own_domain_is_benign = false

  local protected = {}
  for _, p in ipairs(protected_names or {}) do
    local t = trim(p)
    if #t > 0 then protected[#protected + 1] = t end
  end
  self.protected = protected

  -- Brand tokens, ordered and unique (engine Set insertion order).
  local brands_list, brands_set = {}, {}
  for _, name in ipairs(protected) do
    for _, tok in ipairs(dom.tokenize(name)) do
      if uni.len(tok) >= 4 and not brands_set[tok] then
        -- brand_tokens filtering: not generic, not all-digit (dom.brand_tokens enforces generic)
        if dom.brand_tokens({ name })[tok] then
          brands_set[tok] = true
          brands_list[#brands_list + 1] = tok
        end
      end
    end
  end
  self.brands = brands_set
  self.brand_skels = {} -- array of {tok, skel}
  local brand_skel_by_tok = {}
  for _, b in ipairs(brands_list) do
    local sk = uni.fold_skeleton(b)
    self.brand_skels[#self.brand_skels + 1] = { tok = b, skel = sk }
    brand_skel_by_tok[b] = sk
  end

  -- Protected registrable domains, ordered/unique.
  local domains_set, domains_list = {}, {}
  for _, p in ipairs(protected) do
    if p:find(".", 1, true) and not trim(p):find(" ", 1, true) then
      local reg = dom.registrable(p)
      if not domains_set[reg] then domains_set[reg] = true; domains_list[#domains_list + 1] = reg end
    end
  end
  self.domains = domains_set

  -- sld skeletons, ordered by first occurrence of each sld.
  local sld_order, sld_seen = {}, {}
  for _, reg in ipairs(domains_list) do
    local s = dom.sld(reg)
    if not sld_seen[s] then sld_seen[s] = true; sld_order[#sld_order + 1] = s end
  end

  -- targets: sld entries first, then brand entries whose key is not already an sld key
  -- (engine builds a Map(sldSkeletons) then sets brand entries; same-key keeps position).
  self.targets = {}        -- array of {name, skel}
  self.targets_has = {}    -- set of keys
  for _, s in ipairs(sld_order) do
    self.targets[#self.targets + 1] = { name = s, skel = uni.fold_skeleton(s) }
    self.targets_has[s] = true
  end
  for _, b in ipairs(brands_list) do
    if not self.targets_has[b] then
      self.targets[#self.targets + 1] = { name = b, skel = brand_skel_by_tok[b] }
      self.targets_has[b] = true
    end
  end

  self.name_skeletons = {}
  for _, p in ipairs(protected) do self.name_skeletons[uni.fold_skeleton(p)] = true end

  return self
end

function Extractor:threshold(name)
  local n = uni.len(name)
  if n <= 4 then return 0 end
  if n <= 8 then return math.min(self.max_distance, 1) end
  return self.max_distance
end

function Extractor:closest_brand(token)
  local sk = uni.fold_skeleton(token)
  local best, bestd = nil, INF
  for _, e in ipairs(self.brand_skels) do
    local d = distance.osa(sk, e.skel)
    if d < bestd then best, bestd = e.tok, d end
  end
  return best, bestd
end

function Extractor:token_is_brand(token)
  if self.brands[token] then return true end
  local sk = uni.fold_skeleton(token)
  for _, e in ipairs(self.brand_skels) do if e.skel == sk then return true end end
  return false
end

function Extractor:token_is_lookalike(token)
  if self.brands[token] then return false end
  local brand, d = self:closest_brand(token)
  if brand == nil then return false end
  if d == 0 then return true end
  return d > 0 and d <= self:threshold(brand)
end

function Extractor:contains_brand(text)
  local t = uni.fold_skeleton(text)
  for _, e in ipairs(self.brand_skels) do
    if uni.len(e.skel) >= 4 and t:find(e.skel, 1, true) then return true end
  end
  return false
end

local function split_ascii_alnum(s)
  local out = {}
  for piece in (s .. "\1"):gmatch("([a-z0-9]*)[^a-z0-9]*") do
    if #piece > 0 then out[#out + 1] = piece end
  end
  return out
end

local function all_ascii_digits(tok)
  return tok:match("^[0-9]+$") ~= nil
end

function Extractor:domain_features(domain)
  local f = zero_features()
  if not domain or domain == "" then
    f.domain_missing = 1
    return f
  end
  local raw = domain
  local reg = dom.registrable(domain)
  local s = dom.sld(domain)
  f.domain_invisible_chars = uni.has_invisible(raw) and 1 or 0
  f.domain_punycode = uni.casefold(raw):find("xn--", 1, true) and 1 or 0
  f.domain_mixed_script = uni.is_mixed_script(reg) and 1 or 0
  f.domain_free_mail = dom.FREE_MAIL[reg] and 1 or 0
  f.domain_embeds_foreign_domain = (dom.embedded_domain(domain) ~= nil) and 1 or 0

  local sld_tokens = split_ascii_alnum(s)
  local lure = #sld_tokens > 0 and not dom.FREE_MAIL[reg]
  if lure then
    for _, t in ipairs(sld_tokens) do
      if not (dom.DOMAIN_LURE_WORDS[t] or all_ascii_digits(t)) then lure = false; break end
    end
  end
  f.domain_lure_words = lure and 1 or 0

  if self.domains[reg] then
    f.domain_is_protected = 1
    return f
  end
  if s == "" then return f end

  local ssk = uni.fold_skeleton(s)
  local best_name, best_d = nil, INF
  for _, e in ipairs(self.targets) do
    local d = distance.osa(ssk, e.skel)
    if d < best_d then best_name, best_d = e.name, d end
  end
  if best_name ~= nil then
    if best_d == 0 then
      if self.targets_has[s] then f.domain_tld_swap = 1 else f.domain_skeleton_match = 1 end
    elseif best_d <= self:threshold(best_name) then
      f.domain_close_typo = 1
    end
  end
  if f.domain_skeleton_match == 0 and f.domain_tld_swap == 0 then
    if self:contains_brand(s) then
      f.domain_brand_affix = 1
    else
      local usk = uni.fold_skeleton(dom.unleet(s))
      for _, e in ipairs(self.targets) do if e.skel == usk then f.domain_leet_match = 1; break end end
    end
  end
  local subs = dom.subdomain_labels(domain)
  for _, lab in ipairs(subs) do
    if self:token_is_brand(lab) or self:contains_brand(lab) then f.domain_brand_in_subdomain = 1; break end
  end
  return f
end

local function any(list, pred)
  for _, v in ipairs(list) do if pred(v) then return true end end
  return false
end

--- sender = {display_name=..., address=...}
function Extractor:extract(sender)
  local parsed_name, lpart, domain = dom.parse_address(sender.address or "")
  local display = (sender.display_name ~= nil and sender.display_name ~= "") and sender.display_name or parsed_name

  local f = zero_features()
  local df = self:domain_features(domain)
  for k, v in pairs(df) do f[k] = v end

  local dtoks = dom.tokenize(display)
  f.display_invisible_chars = uni.has_invisible(display) and 1 or 0
  f.display_mixed_script = uni.is_mixed_script(display) and 1 or 0
  f.display_role_word = any(dtoks, function(t) return dom.ROLE_WORDS[t] end) and 1 or 0
  local disp_brand = any(dtoks, function(t) return self:token_is_brand(t) end)
    or self.name_skeletons[uni.fold_skeleton(display)]
    or any(dtoks, function(t) return self:contains_brand(t) end)
  f.display_brand_token = disp_brand and 1 or 0
  f.display_brand_lookalike = any(dtoks, function(t) return self:token_is_lookalike(t) end) and 1 or 0
  local claims = f.display_brand_token == 1 or f.display_brand_lookalike == 1
  f.display_claims_brand_off_domain = (claims and f.domain_is_protected == 0) and 1 or 0

  local ltoks = dom.tokenize(lpart)
  f.local_role_word = any(ltoks, function(t) return dom.ROLE_WORDS[t] end) and 1 or 0
  f.local_brand_token = any(ltoks, function(t) return self:token_is_brand(t) or self:contains_brand(t) end) and 1 or 0
  f.local_brand_lookalike = any(ltoks, function(t) return self:token_is_lookalike(t) end) and 1 or 0

  if f.domain_is_protected == 1 and self.brand_on_own_domain_is_benign then
    f.display_brand_token = 0; f.display_brand_lookalike = 0
    f.local_brand_token = 0; f.local_brand_lookalike = 0
  end
  return f
end

return M
