--[[
Context management for LLM-based spam detection

Provides:
  - fetch(task, redis_params, opts, callback): load context JSON from Redis and format prompt snippet
  - update_after_classification(task, redis_params, opts, result, sel_part): update context after LLM result

Opts (all optional, safe defaults applied):
  enabled: boolean
  level: 'user' | 'domain' | 'esld' (scope for context key)
  key_prefix: string (prefix before scope)
  key_suffix: string (suffix after identity)
  max_messages: number (sliding window size)
  message_ttl: seconds
  ttl: seconds (Redis key TTL)
  top_senders: number (how many to keep in top_senders)
  summary_max_chars: number (truncate stored text)
  flagged_phrases: array of strings (case-insensitive match)
  last_labels_count: number
]]

local M = {}

local lua_redis = require "lua_redis"
local lua_util = require "lua_util"
local rspamd_logger = require "rspamd_logger"
local ucl = require "ucl"
local rspamd_util = require "rspamd_util"
local llm_common = require "llm_common"

local EMPTY = {}

local DEFAULTS = {
  enabled = false,
  level = 'user',
  key_prefix = 'user',
  key_suffix = 'mail_context',
  max_messages = 40,
  min_messages = 5, -- minimum messages in context before injecting into prompt
  message_ttl = 14 * 24 * 3600,
  ttl = 30 * 24 * 3600,
  top_senders = 5,
  summary_max_chars = 512,
  flagged_phrases = {
    'reset your password',
    'click here to verify',
    'confirm your account',
    'urgent invoice',
    'wire transfer',
  },
  last_labels_count = 10,
}

local function to_seconds(v)
  if type(v) == 'number' then return v end
  return tonumber(v) or 0
end

local function get_principal_recipient(task)
  return task:get_principal_recipient()
end

local function get_domain_from_addr(addr)
  if not addr then return nil end
  return string.match(addr, '.*@(.+)')
end

local function compute_identity(task, opts)
  local scope = opts.level or DEFAULTS.level
  local identity
  if scope == 'user' then
    identity = task:get_user() or get_principal_recipient(task)
    if not identity then
      local from = ((task:get_from('smtp') or EMPTY)[1] or EMPTY)['addr']
      identity = from
    end
  elseif scope == 'domain' then
    local rcpt = get_principal_recipient(task)
    identity = get_domain_from_addr(rcpt)
    if not identity then
      identity = ((task:get_from('smtp') or EMPTY)[1] or EMPTY)['domain']
    end
  elseif scope == 'esld' then
    local rcpt = get_principal_recipient(task)
    local d = get_domain_from_addr(rcpt)
    if d then
      identity = rspamd_util.get_tld(d)
    end
    if not identity then
      local fd = ((task:get_from('smtp') or EMPTY)[1] or EMPTY)['domain']
      if fd then identity = rspamd_util.get_tld(fd) end
    end
  else
    scope = 'user'
    identity = task:get_user() or get_principal_recipient(task)
  end

  if not identity or identity == '' then
    return nil
  end

  local key_prefix = opts.key_prefix or DEFAULTS.key_prefix
  local key_suffix = opts.key_suffix or DEFAULTS.key_suffix
  local key = string.format('%s:%s:%s', key_prefix, identity, key_suffix)

  return {
    scope = scope,
    identity = identity,
    key = key,
  }
end

local function parse_json(str)
  if not str or str == '' then return nil end
  local parser = ucl.parser()
  local ok, err = parser:parse_string(str)
  if not ok then return nil, err end
  return parser:get_object()
end

local function encode_json(obj)
  return ucl.to_format(obj, 'json-compact', true)
end

local function now()
  return os.time()
end

local function truncate_text(txt, limit)
  if not txt then return '' end
  if #txt <= limit then return txt end
  return string.sub(txt, 1, limit)
end

local function has_flag(flags, flag_name)
  if type(flags) ~= 'table' then return false end
  for _, f in ipairs(flags) do
    if f == flag_name then return true end
  end
  return false
end

local function extract_keywords(text_part, limit)
  if not text_part then return {} end
  local words = text_part:get_words('full')
  if not words or #words == 0 then return {} end

  local counts = {}
  for _, w in ipairs(words) do
    local norm_word = w[2] or '' -- normalized
    local flags = w[4] or {}
    -- Skip stop words, too short, or non-text
    if not has_flag(flags, 'stop_word') and #norm_word > 2 and has_flag(flags, 'text') then
      counts[norm_word] = (counts[norm_word] or 0) + 1
    end
  end

  local arr = {}
  for word, cnt in pairs(counts) do
    table.insert(arr, { w = word, c = cnt })
  end
  table.sort(arr, function(a, b)
    if a.c == b.c then return a.w < b.w end
    return a.c > b.c
  end)

  local res = {}
  for i = 1, math.min(limit or 12, #arr) do
    table.insert(res, arr[i].w)
  end
  return res
end

local function safe_array(arr)
  if type(arr) ~= 'table' then return {} end
  return arr
end

local function build_message_summary(task, sel_part, opts)
  local model_cfg = { max_tokens = 256 }
  local content_tbl
  if sel_part then
    local itbl = llm_common.build_llm_input(task, { max_tokens = model_cfg.max_tokens })
    content_tbl = itbl
  else
    content_tbl = llm_common.build_llm_input(task, { max_tokens = model_cfg.max_tokens })
  end
  if type(content_tbl) ~= 'table' then
    return nil
  end
  local txt = content_tbl.text or ''
  local summary_max = opts.summary_max_chars or DEFAULTS.summary_max_chars
  local msg = {
    from = content_tbl.from or ((task:get_from('smtp') or EMPTY)[1] or EMPTY)['addr'],
    subject = content_tbl.subject or '',
    ts = now(),
    keywords = extract_keywords(sel_part, 12),
  }
  if txt and #txt > 0 then
    msg.text = truncate_text(txt, summary_max)
  end
  return msg
end

local function trim_messages(recent_messages, max_messages, min_ts)
  local res = {}
  for _, m in ipairs(recent_messages) do
    if not min_ts or (m.ts and m.ts >= min_ts) then
      table.insert(res, m)
    end
  end
  table.sort(res, function(a, b)
    local ta = a.ts or 0
    local tb = b.ts or 0
    return ta > tb
  end)
  while #res > max_messages do
    table.remove(res)
  end
  return res
end

local function recompute_top_senders(sender_counts, limit_n)
  local arr = {}
  for s, c in pairs(sender_counts or {}) do
    table.insert(arr, { s = s, c = c })
  end
  table.sort(arr, function(a, b)
    if a.c == b.c then return a.s < b.s end
    return a.c > b.c
  end)
  local res = {}
  for i = 1, math.min(limit_n, #arr) do
    table.insert(res, arr[i].s)
  end
  return res
end

local function ensure_defaults(ctx)
  if type(ctx) ~= 'table' then ctx = {} end
  ctx.recent_messages = safe_array(ctx.recent_messages)
  ctx.top_senders = safe_array(ctx.top_senders)
  ctx.flagged_phrases = safe_array(ctx.flagged_phrases)
  ctx.last_spam_labels = safe_array(ctx.last_spam_labels)
  ctx.sender_counts = ctx.sender_counts or {}
  return ctx
end

local function contains_ci(haystack, needle)
  if not haystack or not needle then return false end
  return string.find(string.lower(haystack), string.lower(needle), 1, true) ~= nil
end

local function update_flagged_phrases(ctx, text_part, opts)
  local phrases = opts.flagged_phrases or DEFAULTS.flagged_phrases
  if not text_part then return end
  local words = text_part:get_words('norm')
  if not words or #words == 0 then return end
  local text_lower = table.concat(words, ' ')
  for _, p in ipairs(phrases) do
    if contains_ci(text_lower, p) then
      local present = false
      for _, e in ipairs(ctx.flagged_phrases) do
        if string.lower(e) == string.lower(p) then
          present = true
          break
        end
      end
      if not present then
        table.insert(ctx.flagged_phrases, p)
      end
    end
  end
end

local function to_bullets_recent(recent_messages, limit_n)
  local lines = {}
  local n = math.min(limit_n, #recent_messages)
  for i = 1, n do
    local m = recent_messages[i]
    local from = m.from or m.sender or ''
    local subj = m.subject or ''
    table.insert(lines, string.format('- %s: %s', from, subj))
  end
  return table.concat(lines, '\n')
end

local function join_list(arr)
  if not arr or #arr == 0 then return '' end
  return table.concat(arr, ', ')
end

local function format_context_prompt(ctx)
  local bullets = to_bullets_recent(ctx.recent_messages or {}, 5)
  local top_senders = join_list(ctx.top_senders or {})
  local flagged = join_list(ctx.flagged_phrases or {})
  local spam_types = join_list(ctx.last_spam_labels or {})

  local parts = {}
  table.insert(parts, 'User recent correspondence summary:')
  if bullets ~= '' then
    table.insert(parts, bullets)
  else
    table.insert(parts, '- (no recent messages)')
  end
  table.insert(parts, string.format('Top senders in mailbox: %s', top_senders))
  if flagged ~= '' then
    table.insert(parts, string.format('Recently flagged suspicious phrases: %s', flagged))
  end
  if spam_types ~= '' then
    table.insert(parts, string.format('Last detected spam types: %s', spam_types))
  end

  return table.concat(parts, '\n')
end

function M.fetch(task, redis_params, opts, callback)
  opts = lua_util.override_defaults(DEFAULTS, opts or {})
  if not opts.enabled then
    callback(nil, nil, nil)
    return
  end
  if not redis_params then
    callback('no redis', nil, nil)
    return
  end

  local ident = compute_identity(task, opts)
  if not ident then
    callback('no identity', nil, nil)
    return
  end

  local function on_get(err, data)
    if err then
      rspamd_logger.errx(task, 'llm_context: get failed: %s', err)
      callback(err, nil, nil)
      return
    end
    local ctx
    if data then
      ctx = ensure_defaults(select(1, parse_json(data)) or {})
    else
      ctx = ensure_defaults({})
    end

    -- Check if context has enough messages for warm-up
    local min_msgs = opts.min_messages or DEFAULTS.min_messages
    local msg_count = #(ctx.recent_messages or {})
    if msg_count < min_msgs then
      lua_util.debugm('llm_context', task, 'context has only %s messages (min: %s), not injecting into prompt',
        msg_count, min_msgs)
      callback(nil, ctx, nil) -- return ctx but no prompt snippet
      return
    end

    local prompt_snippet = format_context_prompt(ctx)
    callback(nil, ctx, prompt_snippet)
  end

  local ok = lua_redis.redis_make_request(task, redis_params, ident.key, false, on_get, 'GET', { ident.key })
  if not ok then
    callback('request not scheduled', nil, nil)
  end
end

function M.update_after_classification(task, redis_params, opts, result, sel_part)
  opts = lua_util.override_defaults(DEFAULTS, opts or {})
  if not opts.enabled then return end
  if not redis_params then return end

  local ident = compute_identity(task, opts)
  if not ident then return end

  local function on_get(err, data)
    if err then
      rspamd_logger.errx(task, 'llm_context: get for update failed: %s', err)
      return
    end
    local ctx = ensure_defaults(select(1, parse_json(data)) or {})

    local msg = build_message_summary(task, sel_part, opts)
    if msg then
      table.insert(ctx.recent_messages, 1, msg)
      local sender = msg.from or ''
      if sender ~= '' then
        ctx.sender_counts[sender] = (ctx.sender_counts[sender] or 0) + 1
      end
      update_flagged_phrases(ctx, sel_part, opts)
    end

    local min_ts = now() - to_seconds(opts.message_ttl)
    ctx.recent_messages = trim_messages(ctx.recent_messages, opts.max_messages, min_ts)
    ctx.top_senders = recompute_top_senders(ctx.sender_counts, opts.top_senders)

    local labels = {}
    if result then
      if result.categories and type(result.categories) == 'table' then
        for _, c in ipairs(result.categories) do table.insert(labels, tostring(c)) end
      end
      if result.probability then
        if result.probability > 0.5 then
          table.insert(labels, 'spam')
        else
          table.insert(labels, 'ham')
        end
      end
    end
    for _, l in ipairs(labels) do table.insert(ctx.last_spam_labels, 1, l) end
    while #ctx.last_spam_labels > opts.last_labels_count do table.remove(ctx.last_spam_labels) end

    ctx.updated_at = now()

    local payload = encode_json(ctx)
    local ttl = to_seconds(opts.ttl)
    local function on_set(set_err)
      if set_err then
        rspamd_logger.errx(task, 'llm_context: set failed: %s', set_err)
      end
    end
    local ok = lua_redis.redis_make_request(task, redis_params, ident.key, true, on_set, 'SETEX',
      { ident.key, tostring(ttl), payload })
    if not ok then
      rspamd_logger.errx(task, 'llm_context: set request was not scheduled')
    end
  end

  local ok = lua_redis.redis_make_request(task, redis_params, ident.key, false, on_get, 'GET', { ident.key })
  if not ok then
    rspamd_logger.errx(task, 'llm_context: initial get request was not scheduled')
  end
end

return M
