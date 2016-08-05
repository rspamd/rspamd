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
local rspamd_logger = require "rspamd_logger"

-- Messages that have only HTML part
reconf['MIME_HTML_ONLY'] = 'has_only_html_part()'

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
              local parent = tag:get_parent()
              if parent then
                if parent:get_type() == 'a' then
                  -- do not trigger on small and unknown size images
                  if i['height'] + i['width'] >= 210 or not i['embedded'] then
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
end

rspamd_config.HTML_SHORT_LINK_IMG_1 = {
  callback = function(task)
    return check_html_image(task, 0, 1024)
  end,
  score = 3.0,
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
                  local parent = tag:get_parent()
                  if parent then
                    if parent:get_type() ~= 'a' then
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
              local parent = tag:get_parent()
              if parent then
                if parent:get_type() == 'a' then
                  -- do not trigger on small and large images
                  if dim > 100 and dim < 3000 then
                    -- We assume that a single picture 100x200 contains approx 3 words of text
                    pic_words = pic_words + dim / 100
                  end
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

rspamd_config.R_WHITE_ON_WHITE = {
  callback = function(task)
    local tp = task:get_text_parts() -- get text parts in a message
    local ret = false
    local diff = 0.0

    for _,p in ipairs(tp) do -- iterate over text parts array using `ipairs`
      if p:is_html() then -- if the current part is html part
        local hc = p:get_html() -- we get HTML context

        hc:foreach_tag('font', function(tag, len)
          local bl = tag:get_extra()
          if bl then
            if bl['bgcolor'] and bl['color'] then
              local color = bl['color']
              local bgcolor = bl['bgcolor']
              -- Should use visual approach here some day
              local diff_r = math.abs(color[1] - bgcolor[1]) / 255.0
              local diff_g = math.abs(color[2] - bgcolor[2]) / 255.0
              local diff_b = math.abs(color[3] - bgcolor[3]) / 255.0
              diff = (diff_r + diff_g + diff_b) / 3.0

              if diff < 0.2 then
                ret = true
                return true
              end
            end
          end

          return false -- Continue search
        end)

      end
    end

    if ret then
      return true,(0.2 - diff) * 5.0,tostring(diff * 100.0)
    end

    return false
  end,

  score = 6.0,
  group = 'html',
  description = 'Message contains low contrast text'
}
