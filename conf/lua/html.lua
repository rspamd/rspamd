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
      local len = p:get_raw_length()
      
      if len >= min and len < max then
        local images = hc:get_images()
        
        if images then
          for _,i in ipairs(images) do
            if i['embedded'] then
              return true
            end
          end
        end
      end
    end
  end
end

rspamd_config.HTML_SHORT_LINK_IMG_1 = function(task)
  return check_html_image(task, 0, 1024)
end
rspamd_config.HTML_SHORT_LINK_IMG_2 = function(task)
  return check_html_image(task, 1024, 1536)
end
rspamd_config.HTML_SHORT_LINK_IMG_3 = function(task)
  return check_html_image(task, 1536, 2048)
end
rspamd_config.R_EMPTY_IMAGE = function(task)
  local tp = task:get_text_parts()
  
  for _,p in ipairs(tp) do
    if p:is_html() then
      local hc = p:get_html()
      local len = p:get_length()
      
      if len < 50 then
        local images = hc:get_images()
        
        if images then
          for _,i in ipairs(images) do
            if i['height'] + i['width'] >= 400 then
              return true
            end
          end
        end
      end
    end
  end
end