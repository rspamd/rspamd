--[[
Copyright (c) 2019, Vsevolod Stakhov <vsevolod@highsecure.ru>

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

-- This file contains functions to simplify bayes classifier auto-learning

local exports = {}

exports.autolearn = function(task, is_spam, is_unlearn)
  local learn_type = task:get_request_header('Learn-Type')

  if not (learn_type and tostring(learn_type) == 'bulk') then
    local prob = task:get_mempool():get_variable('bayes_prob', 'double')

    if prob then
      local in_class = false
      local cl
      if is_spam then
        cl = 'spam'
        in_class = prob >= 0.95
      else
        cl = 'ham'
        in_class = prob <= 0.05
      end

      if in_class then
        return false,string.format(
            'already in class %s; probability %.2f%%',
            cl, math.abs((prob - 0.5) * 200.0))
      end
    end
  end

  return true
end

return exports