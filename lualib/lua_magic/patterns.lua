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

local heuristics = require "lua_magic/heuristics"

local patterns = {
  pdf = {
    -- These are alternatives
    matches = {
      {
        string = [[%PDF-[12]\.\d]],
        position = {'<=', 1024},
        weight = 60,
        heuristic = heuristics.pdf_format_heuristic
      },
      {
        string = [[%FDF-[12]\.\d]],
        position = {'<=', 1024},
        weight = 60,
        heuristic = heuristics.pdf_format_heuristic
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
        string = [[^{\\rt]],
        position = 4,
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
  -- MS Office format, needs heuristic
  ole = {
    matches = {
      {
        hex = [[d0cf11e0a1b11ae1]],
        relative_position = 0,
        weight = 60,
        heuristic = heuristics.ole_format_heuristic
      }
    }
  },
  -- MS Exe file
  exe = {
    matches = {
      {
        string = [[MZ]],
        relative_position = 0,
        weight = 15,
      },
      -- PE part
      {
        string = [[PE\x{00}\x{00}]],
        position = {'>=', 0x3c + 4},
        weight = 15,
        heuristic = heuristics.pe_part_heuristic,
      }
    }
  },
  elf = {
    matches = {
      {
        hex = [[7f454c46]],
        relative_position = 0,
        weight = 60,
      },
    }
  },
  lnk = {
    matches = {
      {
        hex = [[4C0000000114020000000000C000000000000046]],
        relative_position = 0,
        weight = 60,
      },
    }
  },
  bat = {
    matches = {
      {
        string = [[(?i)@\s*ECHO\s+OFF]],
        position = {'>=', 0},
        weight = 60,
      },
    }
  },
  class = {
    -- Technically, this also matches MachO files, but I don't care about
    -- Apple and their mental health problems here: just consider Java files,
    -- Mach object files and all other cafe babes as bad and block them!
    matches = {
      {
        hex = [[cafebabe]],
        relative_position = 0,
        weight = 60,
      },
    }
  },
  ics = {
    matches = {
      {
        string = [[BEGIN:VCALENDAR]],
        weight = 60,
        relative_position = 0,
      }
    }
  },
  vcf = {
    matches = {
      {
        string = [[BEGIN:VCARD]],
        weight = 60,
        relative_position = 0,
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
        hex = [[4d53434600000000]], -- Can be anywhere for SFX :(
        position = {'>=', 8},
        weight = 60,
      },
    }
  },
  tar = {
    matches = {
      {
        string = [[ustar]],
        relative_position = 257,
        weight = 60,
      },
    }
  },
  bz2 = {
    matches = {
      {
        string = "^BZ[h0]",
        position = 3,
        weight = 60,
      },
    }
  },
  lz4 = {
    matches = {
      {
        hex = "04224d18",
        relative_position = 0,
        weight = 60,
      },
      {
        hex = "03214c18",
        relative_position = 0,
        weight = 60,
      },
      {
        hex = "02214c18",
        relative_position = 0,
        weight = 60,
      },
      {
        -- MozLZ4
        hex = '6d6f7a4c7a343000',
        relative_position = 0,
        weight = 60,
      }
    }
  },
  zst = {
    matches = {
      {
        string = [[^[\x{22}-\x{40}]\x{B5}\x{2F}\x{FD}]],
        position = 4,
        weight = 60,
      },
    }
  },
  zoo = {
    matches = {
      {
        hex = [[dca7c4fd]],
        relative_position = 20,
        weight = 60,
      },
    }
  },
  xar = {
    matches = {
      {
        string = [[xar!]],
        relative_position = 0,
        weight = 60,
      },
    }
  },
  iso = {
    matches = {
      {
        string = [[\x{01}CD001\x{01}]],
        position = {'>=', 0x8000 + 7}, -- first 32k is unused
        weight = 60,
      },
    }
  },
  egg = {
    -- ALZip egg
    matches = {
      {
        string = [[EGGA]],
        weight = 60,
        relative_position = 0,
      },
    }
  },
  alz = {
    -- ALZip alz
    matches = {
      {
        string = [[ALZ\x{01}]],
        weight = 60,
        relative_position = 0,
      },
    }
  },
  -- Apple is a 'special' child: this needs to be matched at the data tail...
  dmg = {
    matches = {
      {
        string = [[koly\x{00}\x{00}\x{00}\x{04}]],
        position = -512 + 8,
        weight = 61,
        tail = 512,
      },
    }
  },
  szdd = {
    matches = {
      {
        hex = [[535a4444]],
        relative_position = 0,
        weight = 60,
      },
    }
  },
  xz = {
    matches = {
      {
        hex = [[FD377A585A00]],
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
  swf = {
    matches = {
      {
        hex = [[5a5753]], -- LZMA
        relative_position = 0,
        weight = 60,
      },
      {
        hex = [[435753]], -- Zlib
        relative_position = 0,
        weight = 60,
      },
      {
        hex = [[465753]], -- Uncompressed
        relative_position = 0,
        weight = 60,
      },
    }
  },
  tiff = {
    matches = {
      {
        hex = [[49492a00]], -- LE encoded
        relative_position = 0,
        weight = 60,
      },
      {
        hex = [[4d4d]], -- BE tiff
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
  },
  uue = {
    matches = {
      {
        hex = [[626567696e20]],
        relative_position = 0,
        weight = 60,
      },
    }
  },
  dwg = {
    matches = {
      {
        string = '^AC10[12][2-9]',
        position = 6,
        weight = 60,
      }
    }
  },
  jpg = {
    matches = {
      { -- JPEG2000
        hex = [[0000000c6a5020200d0a870a]],
        relative_position = 0,
        weight = 60,
      },
      {
        string = [[^\x{ff}\x{d8}\x{ff}]],
        weight = 60,
        position = 3,
      },
    },
  },
  png = {
    matches = {
      {
        string = [[^\x{89}PNG\x{0d}\x{0a}\x{1a}\x{0a}]],
        position = 8,
        weight = 60,
      },
    }
  },
  gif = {
    matches = {
      {
        string = [[^GIF8\d]],
        position = 5,
        weight = 60,
      },
    }
  },
  bmp = {
    matches = {
      {
        string = [[^BM...\x{00}\x{00}\x{00}\x{00}]],
        position = 9,
        weight = 60,
      },
    }
  },
}

return patterns
