-- Licensed to the Apache Software Foundation (ASF) under one or more
-- contributor license agreements.  See the NOTICE file distributed with
-- this work for additional information regarding copyright ownership.
-- The ASF licenses this file to you under the Apache License, Version 2.0
-- (the "License"); you may not use this file except in compliance with
-- the License.  You may obtain a copy of the License at:
--
--     http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.

local reconf = config['regexp']

local rspamd_regexp = require "rspamd_regexp"

-- Messages that have only HTML part
reconf['MIME_HTML_ONLY'] = {
  re = 'has_only_html_part()',
  score = 0.2,
  description = 'Messages that have only HTML part',
  group = 'headers'
}

local function has_anchor_parent(tag)
  local parent = tag
  repeat
    parent = parent:get_parent()
    if parent then
      if parent:get_type() == 'a' then
        return true
      end
    end
  until not parent

  return false
end

local function check_html_image(task, min, max)
  local tp = task:get_text_parts()

  for _,p in ipairs(tp) do
    if p:is_html() then
      local hc = p:get_html()
      local len = p:get_length()


      if hc and len >= min and len < max then
        local images = hc:get_images()
        if images then
          for _,i in ipairs(images) do
            local tag = i['tag']
            if tag then
              if has_anchor_parent(tag) then
                -- do not trigger on small and unknown size images
                if i['height'] + i['width'] >= 210 and i['embedded'] then
                  return true
                end
              end
            end
          end
        end
      end
    end
  end
end

rspamd_config.HTML_SHORT_LINK_IMG_1 = {
  callback = function(task)
    return check_html_image(task, 0, 1024)
  end,
  score = 2.0,
  group = 'html',
  description = 'Short html part (0..1K) with a link to an image'
}

rspamd_config.HTML_SHORT_LINK_IMG_2 = {
  callback = function(task)
    return check_html_image(task, 1024, 1536)
  end,
  score = 1.0,
  group = 'html',
  description = 'Short html part (1K..1.5K) with a link to an image'
}

rspamd_config.HTML_SHORT_LINK_IMG_3 = {
  callback = function(task)
    return check_html_image(task, 1536, 2048)
  end,
  score = 0.5,
  group = 'html',
  description = 'Short html part (1.5K..2K) with a link to an image'
}

rspamd_config.R_EMPTY_IMAGE = {
  callback = function(task)
    local tp = task:get_text_parts() -- get text parts in a message

    for _,p in ipairs(tp) do -- iterate over text parts array using `ipairs`
      if p:is_html() then -- if the current part is html part
        local hc = p:get_html() -- we get HTML context
        local len = p:get_length() -- and part's length
        if hc and len < 50 then -- if we have a part that has less than 50 bytes of text
          local images = hc:get_images() -- then we check for HTML images

          if images then -- if there are images
            for _,i in ipairs(images) do -- then iterate over images in the part
              if i['height'] + i['width'] >= 400 then -- if we have a large image
                local tag = i['tag']
                if tag then
                  if not has_anchor_parent(tag) then
                    return true
                  end
                end
              end
            end
          end
        end
      end
    end
  end,

  score = 2.0,
  group = 'html',
  description = 'Message contains empty parts and image'
}

rspamd_config.R_SUSPICIOUS_IMAGES = {
  callback = function(task)
    local tp = task:get_text_parts() -- get text parts in a message

    for _, p in ipairs(tp) do
      local h = p:get_html()

      if h then
        local l = p:get_words_count()
        local img = h:get_images()
        local pic_words = 0

        if img then
          for _, i in ipairs(img) do
            local dim = i['width'] + i['height']
            local tag = i['tag']

            if tag then
              if has_anchor_parent(tag) then
                if dim > 100 and dim < 3000 then
                  -- We assume that a single picture 100x200 contains approx 3 words of text
                  pic_words = pic_words + dim / 100
                end
              end
            end
          end
        end

        if l + pic_words > 0 then
          local rel = pic_words / (l + pic_words)

          if rel > 0.5 then
            return true, (rel - 0.5) * 2
          end
        end
      end
    end

    return false
  end,

  score = 5.0,
  group = 'html',
  description = 'Message contains many suspicious messages'
}

local vis_check_id = rspamd_config:register_symbol{
  name = 'HTML_VISIBLE_CHECKS',
  type = 'callback',
  group = 'html',
  callback = function(task)
    --local logger = require "rspamd_logger"
    local tp = task:get_text_parts() -- get text parts in a message
    local ret = false
    local transp_rate = 0
    local invisible_blocks = 0
    local zero_size_blocks = 0
    local arg

    local normal_len = 0
    local transp_len = 0

    for _,p in ipairs(tp) do -- iterate over text parts array using `ipairs`
      normal_len = normal_len + p:get_length()
      if p:is_html() and p:get_html() then -- if the current part is html part
        local hc = p:get_html() -- we get HTML context

        hc:foreach_tag({'font', 'span', 'div', 'p', 'td'}, function(tag, clen, is_leaf)
          local bl = tag:get_style()
          if bl then
            if not bl.visible and clen > 0 and is_leaf then
              invisible_blocks = invisible_blocks + 1
            end

            if (bl.font_size or 12) == 0 and clen > 0 and is_leaf then
              zero_size_blocks = zero_size_blocks + 1
            end

            if bl.transparent and is_leaf then
              ret = true
              invisible_blocks = invisible_blocks + 1 -- This block is invisible
              transp_len = transp_len + clen
              normal_len = normal_len - clen
              local tr = transp_len / (normal_len + transp_len)
              if tr > transp_rate then
                transp_rate = tr
                if not bl.color then bl.color = {0, 0, 0} end
                if not bl.bgcolor then bl.bgcolor = {0, 0, 0} end
                arg = string.format('%s color #%x%x%x bgcolor #%x%x%x',
                    tag:get_type(),
                    bl.color[1], bl.color[2], bl.color[3],
                    bl.bgcolor[1], bl.bgcolor[2], bl.bgcolor[3])
              end
            end
          end

          return false -- Continue search
        end)

      end
    end

    if ret then
      transp_rate = transp_len / (normal_len + transp_len)

      if transp_rate > 0.1 then
        if transp_rate > 0.5 or transp_rate ~= transp_rate then
          transp_rate = 0.5
        end

        task:insert_result('R_WHITE_ON_WHITE', (transp_rate * 2.0), arg)
      end
    end

    if invisible_blocks > 0 then
      if invisible_blocks > 10 then
        invisible_blocks = 10
      end
      local rates = { -- From 1 to 10
        0.05,
        0.1,
        0.2,
        0.3,
        0.4,
        0.5,
        0.6,
        0.7,
        0.8,
        1.0,
      }
      task:insert_result('MANY_INVISIBLE_PARTS', rates[invisible_blocks],
          tostring(invisible_blocks))
    end

    if zero_size_blocks > 0 then
      if zero_size_blocks > 5 then
        if zero_size_blocks > 10 then
          -- Full score
          task:insert_result('ZERO_FONT', 1.0,
              tostring(zero_size_blocks))
        else
          zero_size_blocks = 5
        end
      end

      if zero_size_blocks <= 5 then
        local rates = { -- From 1 to 5
          0.1,
          0.2,
          0.2,
          0.3,
          0.5,
        }
        task:insert_result('ZERO_FONT', rates[zero_size_blocks],
            tostring(zero_size_blocks))
      end
    end
  end,
}

rspamd_config:register_symbol{
  type = 'virtual',
  parent = vis_check_id,
  name = 'R_WHITE_ON_WHITE',
  description = 'Message contains low contrast text',
  score = 4.0,
  group = 'html',
  one_shot = true,
}

rspamd_config:register_symbol{
  type = 'virtual',
  parent = vis_check_id,
  name = 'ZERO_FONT',
  description = 'Zero sized font used',
  score = 1.0, -- Reached if more than 5 elements have zero size
  one_shot = true,
  group = 'html'
}

rspamd_config:register_symbol{
  type = 'virtual',
  parent = vis_check_id,
  name = 'MANY_INVISIBLE_PARTS',
  description = 'Many parts are visually hidden',
  score = 1.0, -- Reached if more than 10 elements are hidden
  one_shot = true,
  group = 'html'
}

rspamd_config.EXT_CSS = {
  callback = function(task)
    local regexp_lib = require "rspamd_regexp"
    local re = regexp_lib.create_cached('/^.*\\.css(?:[?#].*)?$/i')
    local tp = task:get_text_parts() -- get text parts in a message
    local ret = false
    for _,p in ipairs(tp) do -- iterate over text parts array using `ipairs`
      if p:is_html() and p:get_html() then -- if the current part is html part
        local hc = p:get_html() -- we get HTML context
        hc:foreach_tag({'link'}, function(tag)
          local bl = tag:get_extra()
          if bl then
            local s = tostring(bl)
            if s and re:match(s) then
              ret = true
            end
          end

          return ret -- Continue search
        end)

      end
    end

    return ret
  end,

  score = 1.0,
  group = 'html',
  description = 'Message contains external CSS reference'
}

local https_re = rspamd_regexp.create_cached('/^https:/i')

rspamd_config.HTTP_TO_HTTPS = {
  callback = function(task)
    local found_opts
    local tp = task:get_text_parts() or {}

    for _,p in ipairs(tp) do
      if p:is_html() then
        local hc = p:get_html()
        if (not hc) then return false end

        local found = false

        hc:foreach_tag('a', function (tag, _)
          -- Skip this loop if we already have a match
          if (found) then return true end

          local c = tag:get_content()
          if (c) then
            if (not https_re:match(c)) then return false end

            local u = tag:get_extra()
            if (not u) then return false end
            local url_proto = u:get_protocol()

            if url_proto ~= 'http' then return false end
            -- Capture matches for http in href to https in visible part only
            found = true
            found_opts = u:get_host()
            return true
          end

          return false
        end)

        if (found) then
          return true,1.0,found_opts
        end

        return false
      end
    end
    return false
  end,
  description = 'Anchor text contains different scheme to target URL',
  score = 2.0,
  group = 'html'
}

rspamd_config.HTTP_TO_IP = {
  callback = function(task)
    local tp = task:get_text_parts()
    if (not tp) then return false end
    for _,p in ipairs(tp) do
      if p:is_html() then
        local hc = p:get_html()
        if (not hc) then return false end
        local found = false
        hc:foreach_tag('a', function (tag, length)
          if (found) then return true end
          local u = tag:get_extra()
          if (u) then
            u = tostring(u):lower()
            if (u:match('^https?://%d+%.%d+%.%d+%.%d+')) then
              found = true
            end
          end
          return false
        end)
        if found then return true end
        return false
      end
    end
  end,
  description = 'Anchor points to an IP address',
  score = 1.0,
  group = 'html'
}
