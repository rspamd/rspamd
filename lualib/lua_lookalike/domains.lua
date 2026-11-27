--[[
Domain, address and token helpers. Faithful port of impersonation_detector/domains.py
(and the engine's domains.ts): registrable domain, second-level label, tokenisation, punycode/IDNA
decoding, embedded-domain detection, and the word lists (free-mail, role words, lure words).
Lua 5.1 / LuaJIT compatible.
]]--

local uni = require((...):gsub("%.domains$", "") .. ".unicode")

local M = {}

-- --- word lists (verbatim from domains.py) ----------------------------------

local function set(list) local t = {}; for _, v in ipairs(list) do t[v] = true end; return t end

M.FREE_MAIL = set({
  "gmail.com", "googlemail.com", "yahoo.com", "ymail.com", "outlook.com", "hotmail.com",
  "live.com", "msn.com", "icloud.com", "me.com", "aol.com", "proton.me", "protonmail.com",
  "pm.me", "mail.com", "yandex.com", "gmx.com", "gmx.net", "zoho.com", "tutanota.com",
  "fastmail.com", "hey.com", "mail.ru", "qq.com", "163.com",
})

local MULTI_SUFFIX = set({
  "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "com.au", "net.au", "org.au", "edu.au",
  "co.nz", "co.jp", "ne.jp", "or.jp", "co.in", "net.in", "org.in", "co.za", "com.br",
  "com.mx", "com.ar", "com.sg", "com.hk", "com.tw", "co.kr", "com.cn", "com.tr", "com.ng",
  "co.il", "com.my", "com.ph", "com.pk", "com.eg", "com.sa",
})
M.MULTI_SUFFIX = MULTI_SUFFIX

local KNOWN_TLDS = set({
  "com", "net", "org", "edu", "gov", "mil", "int", "io", "co", "ai", "app", "dev", "me", "us",
  "uk", "ca", "de", "fr", "au", "in", "jp", "br", "nl", "se", "no", "es", "it", "ch", "ru", "cn",
  "info", "biz", "xyz", "online", "site", "top", "club", "shop", "store", "tech", "cloud",
  "live", "link", "click", "help", "support", "careers", "jobs", "work", "ly", "gl", "tv",
})
M.KNOWN_TLDS = KNOWN_TLDS

local INSTITUTIONAL_TLDS = { "edu", "gov", "mil", "ac.uk", "edu.au", "ac.jp", "ac.in" }

M.ROLE_WORDS = set({
  "support", "security", "help", "helpdesk", "verify", "verification", "account", "accounts",
  "admin", "administrator", "billing", "careers", "career", "recruit", "recruiter", "recruiting",
  "recruitment", "hr", "talent", "team", "official", "noreply", "no-reply", "donotreply", "alerts",
  "alert", "notifications", "notification", "service", "services", "it", "desk", "payroll",
  "compliance", "trust", "safety", "fraud", "update", "updates", "info", "contact", "onboarding",
  "hiring", "jobs", "employer", "employers",
})

M.DOMAIN_LURE_WORDS = set({
  "verify", "verification", "login", "logon", "signin", "auth", "secure", "security", "account",
  "accounts", "update", "portal", "support", "helpdesk", "alert", "alerts", "notice", "check",
  "confirm", "validate", "recovery", "reset", "payroll", "billing", "invoice", "docs", "share",
  "mail", "webmail", "service", "services", "careers", "jobs", "hr", "talent", "connect", "hiring",
  "official", "team", "admin",
})

local GENERIC = {}
for w in pairs(M.ROLE_WORDS) do GENERIC[w] = true end
for _, w in ipairs({
  "com", "net", "org", "edu", "io", "co", "www", "mail", "email", "the", "inc", "llc", "corp",
  "ltd", "group", "global", "online", "app", "my", "get", "join", "use", "go", "login", "secure",
  "portal", "us", "usa",
}) do GENERIC[w] = true end

local LEET = {
  ["0"] = "o", ["1"] = "l", ["3"] = "e", ["4"] = "a", ["5"] = "s", ["7"] = "t", ["8"] = "b",
  ["@"] = "a", ["$"] = "s", ["|"] = "l", ["!"] = "i",
}

-- --- small string helpers ---------------------------------------------------

local function trim(s) return (s:gsub("^%s+", ""):gsub("%s+$", "")) end
local function is_ascii(s)
  for i = 1, #s do if string.byte(s, i) > 127 then return false end end
  return true
end

--- Split a string on a Lua pattern of separators; keep non-empty pieces.
local function split_plain(s, sep)
  local out = {}
  for piece in (s .. sep):gmatch("(.-)" .. sep) do
    if #piece > 0 then out[#out + 1] = piece end
  end
  return out
end

-- --- punycode / IDNA (RFC 3492), port of unicode.ts -------------------------

local BASE, TMIN, TMAX, SKEW, DAMP, INITIAL_BIAS, INITIAL_N = 36, 1, 26, 38, 700, 72, 128

local function adapt(delta, numpoints, firsttime)
  delta = firsttime and math.floor(delta / DAMP) or math.floor(delta / 2)
  delta = delta + math.floor(delta / numpoints)
  local k = 0
  while delta > math.floor(((BASE - TMIN) * TMAX) / 2) do
    delta = math.floor(delta / (BASE - TMIN))
    k = k + BASE
  end
  return k + math.floor(((BASE - TMIN + 1) * delta) / (delta + SKEW))
end

local function digit_value(cp)
  if cp - 48 >= 0 and cp - 48 < 10 then return cp - 22 end
  if cp - 65 >= 0 and cp - 65 < 26 then return cp - 65 end
  if cp - 97 >= 0 and cp - 97 < 26 then return cp - 97 end
  return BASE
end

local function punycode_decode(input)
  local output = {}
  local basic = 0
  for i = #input, 1, -1 do if string.byte(input, i) == 45 then basic = i; break end end -- last '-'
  for j = 1, basic - 1 do
    local cp = string.byte(input, j)
    if cp >= 0x80 then error("not-basic") end
    output[#output + 1] = cp
  end
  local n, bias, i = INITIAL_N, INITIAL_BIAS, 0
  local index = (basic > 0) and (basic + 1) or 1
  local len = #input
  while index <= len do
    local oldi, w = i, 1
    local k = BASE
    while true do
      if index > len then error("invalid-input") end
      local d = digit_value(string.byte(input, index)); index = index + 1
      if d >= BASE then error("invalid-input") end
      i = i + d * w
      local t = (k <= bias) and TMIN or ((k >= bias + TMAX) and TMAX or (k - bias))
      if d < t then break end
      w = w * (BASE - t)
      k = k + BASE
    end
    local out = #output + 1
    bias = adapt(i - oldi, out, oldi == 0)
    n = n + math.floor(i / out)
    i = i % out
    table.insert(output, i + 1, n) -- splice at i (0-based) -> Lua index i+1
    i = i + 1
  end
  local parts = {}
  for _, cp in ipairs(output) do parts[#parts + 1] = uni.encode(cp) end
  return table.concat(parts)
end

local function idna_to_unicode(host)
  if not is_ascii(host) then return host end
  local ok, res = pcall(function()
    local labs = split_plain(host, "%.")
    -- split_plain drops empties; rebuild preserving structure via manual split
    local out, start = {}, 1
    for i = 1, #host + 1 do
      local c = (i <= #host) and host:sub(i, i) or "."
      if c == "." then
        local lab = host:sub(start, i - 1)
        if lab:sub(1, 4):lower() == "xn--" then
          out[#out + 1] = punycode_decode(lab:sub(5))
        else
          out[#out + 1] = lab
        end
        start = i + 1
      end
    end
    return table.concat(out, ".")
  end)
  if ok then return res else return host end
end

local function decode_idn(host)
  if not uni.casefold(host):find("xn--", 1, true) then return host end
  return idna_to_unicode(host)
end
M.decode_idn = decode_idn

-- --- host parsing -----------------------------------------------------------

function M.normalize_host(host)
  local h = uni.strip_invisible(host)
  h = trim(h)
  h = h:gsub("^%.+", ""):gsub("%.+$", "")
  h = uni.casefold(h)
  h = h:gsub("/.*$", "")
  h = h:gsub(":.*$", "")
  return h
end

function M.labels(host)
  local decoded = decode_idn(M.normalize_host(host))
  local out, start = {}, 1
  for i = 1, #decoded + 1 do
    local c = (i <= #decoded) and decoded:sub(i, i) or "."
    if c == "." then
      local lab = decoded:sub(start, i - 1)
      if #lab > 0 then out[#out + 1] = lab end
      start = i + 1
    end
  end
  return out
end

function M.registrable(host)
  local labs = M.labels(host)
  local n = #labs
  if n <= 2 then return table.concat(labs, ".") end
  local last2 = labs[n - 1] .. "." .. labs[n]
  if MULTI_SUFFIX[last2] and n >= 3 then
    return labs[n - 2] .. "." .. labs[n - 1] .. "." .. labs[n]
  end
  return labs[n - 1] .. "." .. labs[n]
end

function M.sld(host)
  local reg = M.registrable(host)
  if reg == "" then return "" end
  return reg:gsub("%..*$", "")
end

function M.tld(host)
  local reg = M.registrable(host)
  local i = reg:find(".", 1, true)
  if i then return reg:sub(i + 1) else return "" end
end

function M.subdomain_labels(host)
  local labs = M.labels(host)
  if #labs == 0 then return {} end
  local reglen = select(2, M.registrable(host):gsub("%.", "")) + 1 -- number of labels in registrable
  local keep = #labs - reglen
  local out = {}
  for i = 1, (keep > 0 and keep or 0) do out[i] = labs[i] end
  return out
end

function M.embedded_domain(host)
  local subs = M.subdomain_labels(host)
  for i = 2, #subs do
    if KNOWN_TLDS[subs[i]] and not KNOWN_TLDS[subs[i - 1]] then
      if i + 1 <= #subs and MULTI_SUFFIX[subs[i] .. "." .. subs[i + 1]] then
        return subs[i - 1] .. "." .. subs[i] .. "." .. subs[i + 1]
      end
      return subs[i - 1] .. "." .. subs[i]
    end
  end
  return nil
end

function M.is_institutional(host)
  local reg = M.registrable(host)
  for _, t in ipairs(INSTITUTIONAL_TLDS) do
    if reg == t or reg:sub(-(#t + 1)) == ("." .. t) then return true end
  end
  return false
end

--- Split `"Name" <local@domain>` / `local@domain` / a bare handle into {name, local, domain}.
function M.parse_address(address)
  address = address or ""
  -- angle form: optional "name" then <local@domain>
  local name, lp, dom = address:match('^%s*"?([^"<]-)"?%s*<([^%s<>@]+)@([^%s<>@]+)>%s*$')
  if lp then
    return trim(name), trim(lp), uni.casefold(trim(dom):gsub("^%.+", ""):gsub("%.+$", ""))
  end
  lp, dom = address:match("^%s*([^%s<>@]+)@([^%s<>@]+)%s*$")
  if lp then
    return "", trim(lp), uni.casefold(trim(dom):gsub("^%.+", ""):gsub("%.+$", ""))
  end
  return "", (trim(address):gsub("^@+", "")), ""
end

-- --- tokens -----------------------------------------------------------------

--- Casefolded, NFKC-normalized, invisibles-removed alphanumeric/underscore tokens.
function M.tokenize(text)
  local norm = uni.nfkc_casefold(uni.strip_invisible(text or ""))
  local cps = uni.codepoints(norm)
  local tokens, buf = {}, {}
  for k = 1, #cps do
    local cp = cps[k]
    if uni.is_word_cp(cp) then
      buf[#buf + 1] = uni.encode(cp)
    elseif #buf > 0 then
      tokens[#tokens + 1] = table.concat(buf); buf = {}
    end
  end
  if #buf > 0 then tokens[#tokens + 1] = table.concat(buf) end
  return tokens
end

function M.unleet(text)
  local cps = uni.codepoints(text or "")
  local out = {}
  for k = 1, #cps do
    local cp = cps[k]
    local ch = uni.encode(cp)
    out[k] = (cp < 128 and LEET[ch]) or ch
  end
  return table.concat(out)
end

local function is_digit_token(tok)
  local cps = uni.codepoints(tok)
  if #cps == 0 then return false end
  for k = 1, #cps do if not uni.is_digit_cp(cps[k]) then return false end end
  return true
end
M.is_digit_token = is_digit_token

--- Distinctive brand tokens (>=4 code points, not generic, not all-digit) from protected names.
function M.brand_tokens(protected_names)
  local out = {}
  for _, name in ipairs(protected_names) do
    for _, tok in ipairs(M.tokenize(name)) do
      if uni.len(tok) >= 4 and not GENERIC[tok] and not is_digit_token(tok) then
        out[tok] = true
      end
    end
  end
  return out
end

function M.protected_domains(protected_names)
  local out = {}
  for _, p in ipairs(protected_names) do
    if p:find(".", 1, true) and not trim(p):find(" ", 1, true) then
      out[M.registrable(p)] = true
    end
  end
  return out
end

return M
