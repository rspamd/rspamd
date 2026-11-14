--[[
Copyright (c) 2026, Sochima Ezema <sochimaezema00@gmail.com>

Licensed under the MIT License. See the LICENSE file in the repository root.
]]--

--[[
lookalike_sender plugin - Layers 1 and 2 of the impersonation-detector engine as an Rspamd
module. For each message it checks the From display name, the From domain and every URL host
against an operator-configured protected set:

  Layer 1  UTS #39 confusable-skeleton and mixed-script lookalike detection, plus embedded-domain
           detection (brand.com inside evil.example).
  Layer 2  an explainable logistic "impersonation" score over 23 named features of the sender and
           of each link host, using the model weights shipped with the engine.

It emits symbols with the offending value and a human-readable reason as options. Unlike the
built-in `phishing` module (which compares the visible URL text against the real URL host, i.e.
display/href mismatch), this module reasons about *who the sender and the hosts resemble* relative
to a configured protected set, so it catches look-alike senders and brand-impersonating hosts even
when the visible text and the href agree.

All logic is local and deterministic; the module makes no network requests.
]]--

if confighelp then
  return
end

local rspamd_logger = require "rspamd_logger"
local lua_util = require "lua_util"
local N = "lookalike_sender"

local ok_lib, lookalike = pcall(require, "lua_lookalike")
if not ok_lib then
  rspamd_logger.errx(rspamd_config, "%s: cannot load lua_lookalike library (%s); is lualib/lua_lookalike on the Lua path?", N, lookalike)
  return
end

local settings = {
  -- Operator-configured protected set: brand names and/or registrable domains, e.g.
  -- protected = ["example.com", "Example", "chase.com", "Chase"];
  protected = {},

  symbol_sender_lookalike = 'LOOKALIKE_SENDER',
  symbol_url_lookalike = 'LOOKALIKE_URL',
  symbol_embedded = 'LOOKALIKE_EMBEDDED_DOMAIN',
  symbol_sender_score = 'IMPERSONATION_SENDER',
  symbol_url_score = 'IMPERSONATION_URL',

  -- A sender/host whose logistic probability reaches this is reported.
  score_threshold = 0.5,
  -- How far to let the score tables influence skeleton/typo matching.
  max_distance = 2,

  -- Default symbol weights (overridable in the usual ways).
  weight_sender_lookalike = 7.0,
  weight_url_lookalike = 5.0,
  weight_embedded = 5.0,
  weight_sender_score = 4.0,
  weight_url_score = 3.0,
}

local detector

local function fmt_reasons(reasons)
  return table.concat(reasons, ", ")
end

local function callback(task)
  if not detector then return end

  -- Sender: prefer the MIME From (what the recipient sees), fall back to the envelope.
  local from = (task:get_from('mime') or {})[1] or (task:get_from('smtp') or {})[1]
  local name, address = "", ""
  if from then
    name = from.name or ""
    if from.user and from.domain then
      address = from.user .. "@" .. from.domain
    else
      address = from.addr or ""
    end
  end

  -- Link hosts.
  local hosts = {}
  local urls = task:get_urls() or {}
  for _, u in ipairs(urls) do
    local h = u:get_host()
    if h and h ~= "" then hosts[#hosts + 1] = h end
  end

  local r = detector:analyze({ name = name, address = address, hosts = hosts })

  -- Layer 1: lookalike matches.
  for _, la in ipairs(r.lookalikes) do
    local opt = string.format("%s imitates %s [%s]", la.candidate, la.protected, fmt_reasons(la.reasons))
    if la.where == "link" then
      task:insert_result(settings.symbol_url_lookalike, 1.0, opt)
    else
      task:insert_result(settings.symbol_sender_lookalike, 1.0, opt)
    end
  end

  -- Layer 1: embedded-domain findings.
  for _, em in ipairs(r.embedded) do
    task:insert_result(settings.symbol_embedded, 1.0,
      string.format("%s embeds %s", em.host, em.inner))
  end

  -- Layer 2: sender score (multiplier = probability, so the contribution scales with confidence).
  if r.sender_score and r.sender_score.probability >= settings.score_threshold then
    local reasons = lookalike.scorer.score_reasons(r.sender_score)
    task:insert_result(settings.symbol_sender_score, r.sender_score.probability,
      string.format("p=%.2f %s", r.sender_score.probability, fmt_reasons(reasons)))
  end

  -- Layer 2: link-host scores.
  for _, ls in ipairs(r.link_scores) do
    if ls.score.probability >= settings.score_threshold then
      local reasons = lookalike.scorer.score_reasons(ls.score)
      task:insert_result(settings.symbol_url_score, ls.score.probability,
        string.format("%s p=%.2f %s", ls.host, ls.score.probability, fmt_reasons(reasons)))
    end
  end
end

local opts = rspamd_config:get_all_opt(N)
if opts then
  for k, v in pairs(opts) do settings[k] = v end
end

if not settings.protected or #settings.protected == 0 then
  rspamd_logger.infox(rspamd_config, '%s: no protected names/domains configured, disabling module', N)
  lua_util.disable_module(N, "config")
  return
end

detector = lookalike.new(settings.protected, {
  max_distance = settings.max_distance,
  registrable_lookalike = true,
  skip_protected_subdomains = true,
  brand_on_own_domain_is_benign = true,
})

local id = rspamd_config:register_symbol({
  name = 'LOOKALIKE_SENDER_CHECK',
  type = 'callback',
  callback = callback,
  group = N,
})

local function virtual(sym, weight, description)
  rspamd_config:register_symbol({
    name = sym,
    type = 'virtual',
    parent = id,
    group = N,
    score = weight,
    description = description,
  })
end

virtual(settings.symbol_sender_lookalike, settings.weight_sender_lookalike,
  "From sender is a confusable/typo lookalike of a protected name")
virtual(settings.symbol_url_lookalike, settings.weight_url_lookalike,
  "A URL host is a confusable/typo lookalike of a protected name")
virtual(settings.symbol_embedded, settings.weight_embedded,
  "A URL host hides another registrable domain inside its subdomains")
virtual(settings.symbol_sender_score, settings.weight_sender_score,
  "Logistic impersonation score for the sender (scaled by probability)")
virtual(settings.symbol_url_score, settings.weight_url_score,
  "Logistic impersonation score for a URL host (scaled by probability)")

rspamd_logger.infox(rspamd_config, '%s: enabled with %s protected entries', N, #settings.protected)
