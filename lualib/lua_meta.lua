--[[
Copyright (c) 2017, Vsevolod Stakhov <vsevolod@highsecure.ru>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
]]--

local exports = {}

local N = "metatokens"
local ts = require("tableshape").types
local logger = require "rspamd_logger"

-- Metafunctions
local function meta_size_function(task)
  local sizes = {
    100,
    200,
    500,
    1000,
    2000,
    4000,
    10000,
    20000,
    30000,
    100000,
    200000,
    400000,
    800000,
    1000000,
    2000000,
    8000000,
  }

  local size = task:get_size()
  for i = 1,#sizes do
    if sizes[i] >= size then
      return {(1.0 * i) / #sizes}
    end
  end

  return {0}
end

local function meta_images_function(task)
  local images = task:get_images()
  local ntotal = 0
  local njpg = 0
  local npng = 0
  local nlarge = 0
  local nsmall = 0

  if images then
    for _,img in ipairs(images) do
      if img:get_type() == 'png' then
        npng = npng + 1
      elseif img:get_type() == 'jpeg' then
        njpg = njpg + 1
      end

      local w = img:get_width()
      local h = img:get_height()

      if w > 0 and h > 0 then
        if w + h > 256 then
          nlarge = nlarge + 1
        else
          nsmall = nsmall + 1
        end
      end

      ntotal = ntotal + 1
    end
  end
  if ntotal > 0 then
    njpg = 1.0 * njpg / ntotal
    npng = 1.0 * npng / ntotal
    nlarge = 1.0 * nlarge / ntotal
    nsmall = 1.0 * nsmall / ntotal
  end
  return {ntotal,njpg,npng,nlarge,nsmall}
end

local function meta_nparts_function(task)
  local nattachments = 0
  local ntextparts = 0
  local totalparts = 1

  local tp = task:get_text_parts()
  if tp then
    ntextparts = #tp
  end

  local parts = task:get_parts()

  if parts then
    for _,p in ipairs(parts) do
      if p:is_attachment() then
        nattachments = nattachments + 1
      end
      totalparts = totalparts + 1
    end
  end

  return {(1.0 * ntextparts)/totalparts, (1.0 * nattachments)/totalparts}
end

local function meta_encoding_function(task)
  local nutf = 0
  local nother = 0

  local tp = task:get_text_parts()
  if tp and #tp > 0 then
    for _,p in ipairs(tp) do
      if p:is_utf() then
        nutf = nutf + 1
      else
        nother = nother + 1
      end
    end

    return {nutf / #tp, nother / #tp}
  end

  return {0, 0}
end

local function meta_recipients_function(task)
  local nmime = 0
  local nsmtp = 0

  if task:has_recipients('mime') then
    nmime = #(task:get_recipients('mime'))
  end
  if task:has_recipients('smtp') then
    nsmtp = #(task:get_recipients('smtp'))
  end

  if nmime > 0 then nmime = 1.0 / nmime end
  if nsmtp > 0 then nsmtp = 1.0 / nsmtp end

  return {nmime,nsmtp}
end

local function meta_received_function(task)
  local count_factor = 0
  local invalid_factor = 0
  local rh = task:get_received_headers()
  local time_factor = 0
  local secure_factor = 0
  local fun = require "fun"

  if rh and #rh > 0 then

    local ntotal = 0.0
    local init_time = 0

    fun.each(function(rc)
      ntotal = ntotal + 1.0

      if not rc.by_hostname then
        invalid_factor = invalid_factor + 1.0
      end
      if init_time == 0 and rc.timestamp then
        init_time = rc.timestamp
      elseif rc.timestamp then
        time_factor = time_factor + math.abs(init_time - rc.timestamp)
        init_time = rc.timestamp
      end
      if rc.flags and (rc.flags['ssl'] or rc.flags['authenticated']) then
        secure_factor = secure_factor + 1.0
      end
    end,
    fun.filter(function(rc) return not rc.flags or not rc.flags['artificial'] end, rh))

    if ntotal > 0 then
      invalid_factor = invalid_factor / ntotal
      secure_factor = secure_factor / ntotal
      count_factor = 1.0 / ntotal
    end

    if time_factor ~= 0 then
      time_factor = 1.0 / time_factor
    end
  end

  return {count_factor, invalid_factor, time_factor, secure_factor}
end

local function meta_urls_function(task)
  local has_urls,nurls = task:has_urls()
  if has_urls and nurls > 0 then
    return {1.0 / nurls}
  end

  return {0}
end

local function meta_words_function(task)
  local avg_len = task:get_mempool():get_variable("avg_words_len", "double") or 0.0
  local short_words = task:get_mempool():get_variable("short_words_cnt", "double") or 0.0
  local ret_len = 0

  local lens = {
    2,
    3,
    4,
    5,
    6,
    7,
    8,
    9,
    10,
    15,
    20,
  }

  for i = 1,#lens do
    if lens[i] >= avg_len then
      ret_len = (1.0 * i) / #lens
      break
    end
  end

  local tp = task:get_text_parts()
  local wres = {
    0, -- spaces rate
    0, -- double spaces rate
    0, -- non spaces rate
    0, -- ascii characters rate
    0, -- non-ascii characters rate
    0, -- capital characters rate
    0, -- numeric cahracters
  }
  for _,p in ipairs(tp) do
    local stats = p:get_stats()
    local len = p:get_length()

    if len > 0 then
      wres[1] = wres[1] + stats['spaces'] / len
      wres[2] = wres[2] + stats['double_spaces'] / len
      wres[3] = wres[3] + stats['non_spaces'] / len
      wres[4] = wres[4] + stats['ascii_characters'] / len
      wres[5] = wres[5] + stats['non_ascii_characters'] / len
      wres[6] = wres[6] + stats['capital_letters'] / len
      wres[7] = wres[7] + stats['numeric_characters'] / len
    end
  end

  local ret = {
    short_words,
    ret_len,
  }

  local divisor = 1.0
  if #tp > 0 then
    divisor = #tp
  end

  for _,wr in ipairs(wres) do
    table.insert(ret, wr / divisor)
  end

  return ret
end

local metafunctions = {
  {
    cb = meta_size_function,
    ninputs = 1,
    names = {
      "size"
    },
    description = 'Describes size of the message',
  },
  {
    cb = meta_images_function,
    ninputs = 5,
    -- 1 - number of images,
    -- 2 - number of png images,
    -- 3 - number of jpeg images
    -- 4 - number of large images (> 128 x 128)
    -- 5 - number of small images (< 128 x 128)
    names = {
      'nimages',
      'npng_images',
      'njpeg_images',
      'nlarge_images',
      'nsmall_images'
    },
    description = [[Functions for images matching:
    - number of images,
    - number of png images,
    - number of jpeg images
    - number of large images (> 128 x 128)
    - number of small images (< 128 x 128)
]]
  },
  {
    cb = meta_nparts_function,
    ninputs = 2,
    -- 1 - number of text parts
    -- 2 - number of attachments
    names = {
      'ntext_parts',
      'nattachments'
    },
    description = [[Functions for images matching:
    - number of text parts
    - number of attachments
]]
  },
  {
    cb = meta_encoding_function,
    ninputs = 2,
    -- 1 - number of utf parts
    -- 2 - number of non-utf parts
    names = {
      'nutf_parts',
      'nascii_parts'
    },
    description = [[Functions for encoding matching:
    - number of utf parts
    - number of non-utf parts
]]
  },
  {
    cb = meta_recipients_function,
    ninputs = 2,
    -- 1 - number of mime rcpt
    -- 2 - number of smtp rcpt
    names = {
      'nmime_rcpt',
      'nsmtp_rcpt'
    },
    description = [[Functions for recipients data matching:
    - number of mime rcpt
    - number of smtp rcpt
]]
  },
  {
    cb = meta_received_function,
    ninputs = 4,
    names = {
      'nreceived',
      'nreceived_invalid',
      'nreceived_bad_time',
      'nreceived_secure'
    },
    description = [[Functions for received headers data matching:
    - number of received headers
    - number of bad received headers
    - number of skewed time received headers
    - number of received via secured relays
]]
  },
  {
    cb = meta_urls_function,
    ninputs = 1,
    names = {
      'nurls'
    },
    description = [[Functions for urls data matching:
    - number of urls
]]
  },
  {
    cb = meta_words_function,
    ninputs = 9,
    names = {
      'avg_words_len',
      'nshort_words',
      'spaces_rate',
      'double_spaces_rate',
      'non_spaces_rate',
      'ascii_characters_rate',
      'non_ascii_characters_rate',
      'capital_characters_rate',
      'numeric_cahracters'
    },
    description = [[Functions for words data matching:
    - average length of the words
    - number of short words
    - rate of spaces in the text
    - rate of multiple spaces
    - rate of non space characters
    - rate of ascii characters
    - rate of non-ascii characters
    - rate of capital letters
    - rate of numbers
]]
  },
}

local meta_schema = ts.shape{
  cb = ts.func,
  ninputs = ts.number,
  names = ts.array_of(ts.string),
  description = ts.string:is_optional()
}

local metatokens_by_name = {}

local function fill_metatokens_by_name()
  metatokens_by_name = {}

  for _,mt in ipairs(metafunctions) do
    for i=1,mt.ninputs do
      local name = mt.names[i]

      metatokens_by_name[name] = function(task)
        local results = mt.cb(task)
        return results[i]
      end
    end
  end
end

local function calculate_digest()
  local cr = require "rspamd_cryptobox_hash"

  local h = cr.create()
  for _,mt in ipairs(metafunctions) do
    for i=1,mt.ninputs do
      local name = mt.names[i]
      h:update(name)
    end
  end

  exports.digest = h:hex()
end

local function rspamd_gen_metatokens(task, names)
  local lua_util = require "lua_util"
  local ipairs = ipairs
  local metatokens = {}

  if not names then
    local cached = task:cache_get('metatokens')

    if cached then
      return cached
    else
      for _,mt in ipairs(metafunctions) do
        local ct = mt.cb(task)
        for i,tok in ipairs(ct) do
          lua_util.debugm(N, task, "metatoken: %s = %s",
              mt.names[i], tok)
          if tok ~= tok or tok == math.huge then
            logger.errx(task, 'metatoken %s returned %s; replace it with 0 for sanity',
                mt.names[i], tok)
            tok = 0.0
          end
          table.insert(metatokens, tok)
        end
      end

      task:cache_set('metatokens', metatokens)
    end

  else
    for _,n in ipairs(names) do
      if metatokens_by_name[n] then
        local tok = metatokens_by_name[n](task)
        if tok ~= tok or tok == math.huge then
          logger.errx(task, 'metatoken %s returned %s; replace it with 0 for sanity',
              n, tok)
          tok = 0.0
        end
        table.insert(metatokens, tok)
      else
        logger.errx(task, 'unknown metatoken: %s', n)
      end
    end
  end

  return metatokens
  end

exports.rspamd_gen_metatokens = rspamd_gen_metatokens
exports.gen_metatokens = rspamd_gen_metatokens

local function rspamd_gen_metatokens_table(task)
  local metatokens = {}

  for _,mt in ipairs(metafunctions) do
    local ct = mt.cb(task)
    for i,tok in ipairs(ct) do
      if tok ~= tok or tok == math.huge then
        logger.errx(task, 'metatoken %s returned %s; replace it with 0 for sanity',
            mt.names[i], tok)
        tok = 0.0
      end

      metatokens[mt.names[i]] = tok
    end
  end

  return metatokens
end

exports.rspamd_gen_metatokens_table = rspamd_gen_metatokens_table
exports.gen_metatokens_table = rspamd_gen_metatokens_table

local function rspamd_count_metatokens()
  local ipairs = ipairs
  local total = 0
  for _,mt in ipairs(metafunctions) do
    total = total + mt.ninputs
  end

  return total
end

exports.rspamd_count_metatokens = rspamd_count_metatokens
exports.count_metatokens = rspamd_count_metatokens
exports.version = 1 -- MUST be increased on each change of metatokens

exports.add_metafunction = function(tbl)
  local ret, err = meta_schema(tbl)

  if not ret then
    logger.errx('cannot add metafunction: %s', err)
  else
    table.insert(metafunctions, tbl)
    fill_metatokens_by_name()
    calculate_digest()
  end
end

fill_metatokens_by_name()
calculate_digest()

return exports
