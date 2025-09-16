--[[
CTA and link affiliation analysis

Purpose:
- Given a capped list of candidate links extracted in C during HTML parsing,
  compute simple affiliation scores between those links and the sender’s
  first-party domain, and pick a likely CTA (call-to-action) link.

How it is called:
- C code (message processing after HTML parsing) loads this function via
  `rspamd_lua_require_function(L, "lua_cta", "process_html_links")` and calls
  `process_html_links(task, part, ctx)` once per HTML text part.

Inputs (ctx table):
- links_total: total number of links in the part (summary; may be omitted)
- domains_total: number of distinct link domains (summary)
- max_links_single_domain: maximum links seen for a single domain (summary)
- candidates: array (capped in C, default 24) of small objects with fields:
  - host: link host (string)
  - idn, numeric, has_port, has_query, display_mismatch: booleans
  - order, part_order: integers (ordering hints)
  - etld1: optional eTLD+1 (if not set, this module approximates from host)

Outputs (returned table):
- cta_affiliated: boolean – whether the selected CTA appears affiliated
- cta_weight: number – simple weight hint (e.g. 1.0 if display mismatch)
- affiliated_ratio: number – fraction of candidates considered affiliated
- trackerish_ratio: number – fraction of candidates that look trackerish

Configuration (rspamd.conf):
- Use the `link_affiliation { ... }` section.
- Options:
  - stopwords: map (set/regexp/glob) used to strip common tracking tokens from
               domains when computing token overlap
  - whitelist / blacklist: optional maps (set) to tweak affiliation
  - min_similarity: number (default 0.5) – Jaccard threshold for affiliation
  - max_candidates: number (default 24) – extra Lua-side cap (C caps as well)

This module keeps all heavy config logic in Lua using lua_maps and only relies
on C to provide a bounded set of safe, pre-filtered candidates.
]]
local M = {}

local lua_util = require "lua_util"
local lua_maps = require "lua_maps"
local rspamd_util = require "rspamd_util"

-- Reasonable defaults (can be overridden in rspamd.conf: link_affiliation { ... })
local DEFAULT_STOPWORDS = {
  -- Common TLD tokens and ccTLDs
  "com", "net", "org", "info", "biz", "co", "io", "me", "us", "uk", "ru", "de", "fr", "au", "ca", "cn", "jp", "kr", "in",
  "eu",
  "es", "it", "nl", "pl", "se", "no", "fi", "dk", "cz", "sk", "pt", "tr", "gr", "hu", "ro", "bg", "ua", "by", "lt", "lv",
  "ee",
  "br", "mx", "ch", "be", "at", "dk", "cz", "sk", "pt", "ar", "cl", "pe", "tw", "th", "ph", "vn", "id", "hk", "sg", "nz",
  "za",
  "il", "ie", "is", "lu", "si", "hr", "rs", "gl", "ly",
  -- Generic / infrastructural
  "www", "web", "site", "app", "apps", "cloud", "cdn", "edge", "fastly", "akamai", "akamaihd", "edgesuite", "cloudfront",
  -- Tracking/redirect/marketing tokens
  "mail", "email", "news", "newsletter", "click", "link", "links", "go", "redir", "redirect", "rdir", "safe", "safelinks",
  "trk", "track", "tracking", "ref", "mkt", "mktg", "campaign", "promo", "offer", "offers",
  -- ESPs and bulk mailers (tokens found in their eTLD+1)
  "mailchimp", "mandrill", "sendgrid", "sparkpost", "sparkpostmail", "amazonses", "ses", "postmark", "postmarkapp",
  "mailgun",
  "sendinblue", "constantcontact", "list", "manage", "rs6", "aweber", "hubspot", "campaignmonitor", "cmail", "klaviyo",
  "sailthru",
  "drip", "convertkit", "getresponse", "mautic", "braze", "acoustic", "responsys", "eloqua", "iterable", "sendy",
  "emarsys", "mailjet",
  "mailerlite", "mailerq", "mailrelay", "mailup", "omnisend", "clickdimensions", "dotdigital", "pepipost"
}

local DEFAULT_WHITELIST = {
  -- Intentionally empty by default. Users can add trusted eTLD+1 domains here
}

local DEFAULT_BLACKLIST = {
  -- Popular shorteners / redirection eTLD+1
  "t.co", "bit.ly", "goo.gl", "tinyurl.com", "lnkd.in", "buff.ly", "ow.ly", "rebrand.ly", "bitly.com", "is.gd", "v.gd",
  "t.ly",
  "cutt.ly", "shorturl.at", "reurl.cc", "rb.gy", "s.id", "trib.al",
  -- Common ESP/tracker link domains (treat as non-affiliated by default)
  "list-manage.com", "mandrillapp.com", "sendgrid.net", "sparkpostmail.com", "amazonses.com", "postmarkapp.com",
  "mailgun.org",
  "sendinblue.com", "constantcontact.com", "campaignmonitor.com", "cmail1.com", "cmail2.com", "aweber.com", "hubspot.com",
  "exacttarget.com", "clickdimensions.com", "eloqua.com", "responsys.net", "emarsys.net", "mailjet.com", "klaviyo.com",
  "dripemail2.com",
  "getresponse.com", "benchmarkemail.com", "omnisend.com", "mailerlite.com", "dotdigital.com"
}

local settings = {
  min_similarity = 0.5,
  max_candidates = 24,
  stopwords = nil,
  whitelist = nil,
  blacklist = nil,
}

local function load_settings()
  local cfg = rawget(_G, 'rspamd_config')
  local opts = (cfg and cfg:get_all_opt('link_affiliation')) or {}
  settings = lua_util.override_defaults(settings, opts)
  -- Convert map definitions to maps if needed
  if settings.stopwords then
    if type(settings.stopwords) ~= 'table' or not settings.stopwords.get_key then
      settings.stopwords = lua_maps.map_add_from_ucl(settings.stopwords, 'set', 'link affiliation stopwords')
    end
  else
    settings.stopwords = lua_maps.map_add_from_ucl(DEFAULT_STOPWORDS, 'set', 'link affiliation stopwords (default)')
  end
  if settings.whitelist then
    if type(settings.whitelist) ~= 'table' or not settings.whitelist.get_key then
      settings.whitelist = lua_maps.map_add_from_ucl(settings.whitelist, 'set', 'link affiliation whitelist')
    end
  else
    settings.whitelist = lua_maps.map_add_from_ucl(DEFAULT_WHITELIST, 'set', 'link affiliation whitelist (default)')
  end
  if settings.blacklist then
    if type(settings.blacklist) ~= 'table' or not settings.blacklist.get_key then
      settings.blacklist = lua_maps.map_add_from_ucl(settings.blacklist, 'set', 'link affiliation blacklist')
    end
  else
    settings.blacklist = lua_maps.map_add_from_ucl(DEFAULT_BLACKLIST, 'set', 'link affiliation blacklist (default)')
  end
end

load_settings()

local function etld1_tokens(dom)
  local t = {}
  for token in string.gmatch(string.lower(dom or ''), "[a-z0-9]+") do
    if not (settings.stopwords and settings.stopwords:get_key(token)) then
      t[token] = true
    end
  end
  return t
end

local function jaccard(a, b)
  local inter, uni = 0, 0
  for k in pairs(a) do
    if b[k] then inter = inter + 1 end
    uni = uni + 1
  end
  for k in pairs(b) do
    if not a[k] then uni = uni + 1 end
  end
  if uni == 0 then return 0 end
  return inter / uni
end

M.process_html_links = function(task, part, ctx)
  local first_party = nil
  -- Derive first-party from From: if not provided
  do
    local from = task:get_from('mime') or {}
    if from[1] and from[1].domain then
      first_party = from[1].domain
    end
  end

  local cands = ctx.candidates or {}
  if #cands > settings.max_candidates then
    local tmp = {}
    for i = 1, settings.max_candidates do tmp[i] = cands[i] end
    cands = tmp
  end
  local affiliated = 0
  local trackerish = 0

  local fp_tokens = etld1_tokens(first_party)

  for _, c in ipairs(cands) do
    local etld1 = c.etld1 or rspamd_util.get_tld(c.host or '') or (c.host or '')

    local toks = etld1_tokens(etld1)
    local sim = jaccard(fp_tokens, toks)

    if sim >= settings.min_similarity then
      affiliated = affiliated + 1
    end

    -- very naive trackerish: all tokens are stopwords or too few tokens
    local n_tokens, n_nonstop = 0, 0
    for _ in pairs(toks) do
      n_tokens = n_tokens + 1; n_nonstop = n_nonstop + 1
    end
    if n_nonstop == 0 then trackerish = trackerish + 1 end
  end

  local res = {
    affiliated_ratio = (#cands > 0) and (affiliated / #cands) or 0,
    trackerish_ratio = (#cands > 0) and (trackerish / #cands) or 0,
  }

  -- Simple CTA guess: prefer higher C-side weight, then display_mismatch, then earliest order
  if #cands > 0 then
    table.sort(cands, function(a, b)
      local aw, bw = tonumber(a.weight) or 0, tonumber(b.weight) or 0
      if aw ~= bw then return aw > bw end
      if a.display_mismatch ~= b.display_mismatch then return a.display_mismatch end
      if a.order ~= b.order then return a.order < b.order end
      return a.part_order < b.part_order
    end)
    local cta = cands[1]
    local etld1 = cta.etld1 or rspamd_util.get_tld(cta.host or '') or (cta.host or '')
    local toks = etld1_tokens(etld1)
    local sim = jaccard(fp_tokens, toks)
    res.cta_affiliated = (sim >= settings.min_similarity)
    res.cta_weight = (cta.display_mismatch and 1.0 or 0.5)
  end

  return res
end

return M
