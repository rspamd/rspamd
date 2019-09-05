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

--[[[
-- @module lua_magic/patterns
-- This module contains most common patterns
--]]

local patterns = {
  {
    -- MSDOS extension to match types table
    ext = 'pdf',
    -- These are alternatives
    matches = {
      {
        string = [[%PDF-\d]],
        position = 6, -- must be end of the match, as that's how hyperscan works
        weight = 60,
      },
      {
        string = [[\012%PDF-\d]],
        position = 7,
        weight = 60,
      },
      {
        string = [[%FDF-\d]],
        position = 6,
        weight = 60,
      },
    },
  }
}

return patterns