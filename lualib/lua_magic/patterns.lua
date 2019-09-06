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
  pdf = {
    -- These are alternatives
    matches = {
      {
        string = [[%PDF-\d]],
        position = 6, -- must be end of the match, as that's how hyperscan works (or use relative_position)
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
  },
  ps = {
    matches = {
      {
        string = [[%!PS-Adobe]],
        relative_position = 0,
        weight = 60,
      },
    },
  },
  -- RTF document
  rtf = {
    matches = {
      {
        string = [[{\\rtf\d]],
        position = 6,
        weight = 60,
      }
    }
  },
  chm = {
    matches = {
      {
        string = [[ITSF]],
        relative_position = 0,
        weight = 60,
      }
    }
  },
  djvu = {
    matches = {
      {
        string = [[AT&TFORM]],
        relative_position = 0,
        weight = 60,
      },
      {
        string = [[DJVM]],
        relative_position = 0x0c,
        weight = 60,
      }
    }
  },
  -- MS Exe file
  exe = {
    matches = {
      {
        string = [[MZ]],
        relative_position = 0,
        weight = 10,
      },
      -- PE part
      {
        string = [[PE\x{00}\x{00}]],
        position = {'>=', 0x3c + 4},
        weight = 40,
      }
    }
  },
  -- Archives
  arj = {
    matches = {
      {
        hex = '60EA',
        relative_position = 0,
        weight = 60,
      },
    }
  },
  ace = {
    matches = {
      {
        string = [[\*\*ACE\*\*]],
        position = 14,
        weight = 60,
      },
    }
  },
  cab = {
    matches = {
      {
        string = [[MSCF]],
        relative_position = 0,
        weight = 60,
      },
    }
  },
  -- Images
  psd = {
    matches = {
      {
        string = [[8BPS]],
        relative_position = 0,
        weight = 60,
      },
    }
  },
  ico = {
    matches = {
      {
        hex = [[00000100]],
        relative_position = 0,
        weight = 60,
      },
    }
  },
  pcx = {
    matches = {
      {
        hex = [[0A050108]],
        relative_position = 0,
        weight = 60,
      },
    }
  },
  pic = {
    matches = {
      {
        hex = [[FF80C9C71A00]],
        relative_position = 0,
        weight = 60,
      },
    }
  },
  -- Other
  pgp = {
    matches = {
      {
        hex = [[A803504750]],
        relative_position = 0,
        weight = 60,
      },
      {
        hex = [[2D424547494E20504750204D4553534147452D]],
        relative_position = 0,
        weight = 60,
      },
    }
  }
}

return patterns