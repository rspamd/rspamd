--[[
Text hash provider for neural feature fusion.
Extracts stemmed tokens from text parts, computes unigram and bigram hashes,
and accumulates them into a fixed-size feature vector using the hashing trick.

This is a cheap, zero-latency alternative to LLM embeddings that captures
bag-of-words and bigram structure from message content.
]] --

local rspamd_logger = require "rspamd_logger"
local rspamd_util = require "rspamd_util"
local lua_mime = require "lua_mime"
local neural_common = require "plugins/neural"

local N = "neural.text_hash"

-- Default configuration
local default_hash_size = 16384 -- 2^14; must be power of 2
local default_seed = 0xBEEF1234
local default_bigram_seed = 0xDEAD5678

-- Fast modular reduction for power-of-2 sizes
local function hash_to_bucket(hash_val, size)
  -- Lua 5.1/LuaJIT: use math.fmod since we can't do bitwise AND
  -- hash_val from caseless_hash_fast is a double, take absolute value
  if hash_val < 0 then
    hash_val = -hash_val
  end
  return (math.floor(hash_val) % size) + 1
end

-- Extract words from all relevant text parts
local function extract_words(task, opts)
  local words = {}
  local how = opts.word_form or 'stem'

  -- Get text parts; prefer displayed text part for focused signal
  local parts
  if opts.all_parts then
    parts = task:get_text_parts()
  else
    local sel = lua_mime.get_displayed_text_part(task)
    if sel then
      parts = { sel }
    else
      parts = task:get_text_parts()
    end
  end

  if not parts then
    return words
  end

  for _, part in ipairs(parts) do
    local pw = part:get_words(how)
    if pw then
      for _, w in ipairs(pw) do
        if type(w) == 'string' and #w > 0 then
          words[#words + 1] = w
        end
      end
    end
  end

  return words
end

-- Build the hashed feature vector from words
local function build_hash_vector(words, hash_size, seed, bigram_seed)
  local vec = {}
  for i = 1, hash_size do
    vec[i] = 0.0
  end

  local n_words = #words

  -- Unigrams
  for i = 1, n_words do
    local h = rspamd_util.caseless_hash_fast(words[i], seed)
    local bucket = hash_to_bucket(h, hash_size)
    -- Use sign trick to reduce collisions: hash determines +1 or -1
    local sign_h = rspamd_util.caseless_hash_fast(words[i], seed + 1)
    local sign = (math.floor(sign_h) % 2 == 0) and 1.0 or -1.0
    vec[bucket] = vec[bucket] + sign
  end

  -- Bigrams
  for i = 2, n_words do
    local bigram = words[i - 1] .. '\0' .. words[i]
    local h = rspamd_util.caseless_hash_fast(bigram, bigram_seed)
    local bucket = hash_to_bucket(h, hash_size)
    local sign_h = rspamd_util.caseless_hash_fast(bigram, bigram_seed + 1)
    local sign = (math.floor(sign_h) % 2 == 0) and 1.0 or -1.0
    vec[bucket] = vec[bucket] + sign
  end

  -- L2 normalize
  local sumsq = 0.0
  for i = 1, hash_size do
    sumsq = sumsq + vec[i] * vec[i]
  end
  if sumsq > 0 then
    local inv = 1.0 / math.sqrt(sumsq)
    for i = 1, hash_size do
      vec[i] = vec[i] * inv
    end
  end

  return vec
end

-- Also hash subject line and headers as additional signal
local function add_header_features(task, vec, hash_size, seed)
  -- Subject
  local subj = task:get_subject()
  if subj and #subj > 0 then
    local h = rspamd_util.caseless_hash_fast(subj, seed + 100)
    local bucket = hash_to_bucket(h, hash_size)
    vec[bucket] = vec[bucket] + 0.5
  end

  -- From domain
  local from = task:get_from('mime')
  if from and from[1] and from[1].domain then
    local h = rspamd_util.caseless_hash_fast('FROM:' .. from[1].domain, seed + 200)
    local bucket = hash_to_bucket(h, hash_size)
    vec[bucket] = vec[bucket] + 0.5
  end
end

neural_common.register_provider('text_hash', {
  collect_async = function(task, ctx, cont)
    local pcfg = ctx.config or {}
    local hash_size = pcfg.hash_size or default_hash_size
    local seed = pcfg.seed or default_seed
    local bigram_seed = pcfg.bigram_seed or default_bigram_seed

    local words = extract_words(task, {
      word_form = pcfg.word_form or 'stem',
      all_parts = pcfg.all_parts,
    })

    if #words == 0 then
      rspamd_logger.debugm(N, task, 'text_hash: no words found; skip')
      cont(nil)
      return
    end

    rspamd_logger.debugm(N, task, 'text_hash: hashing %s words into %s buckets',
      #words, hash_size)

    local vec = build_hash_vector(words, hash_size, seed, bigram_seed)

    -- Optionally add header features
    if pcfg.include_headers ~= false then
      add_header_features(task, vec, hash_size, seed)
    end

    local meta = {
      name = pcfg.name or 'text_hash',
      type = 'text_hash',
      dim = hash_size,
      weight = ctx.weight or 1.0,
    }

    rspamd_logger.debugm(N, task, 'text_hash: produced %s-dim vector from %s words',
      hash_size, #words)
    cont(vec, meta)
  end,
})
