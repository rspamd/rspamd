--[[
Copyright (c) 2022, Vsevolod Stakhov <vsevolod@rspamd.com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
]] --

--[[[
-- @module lua_magic/patterns
-- This module contains most common patterns
--]]

local heuristics = require "lua_magic/heuristics"

-- Building blocks for the MHTML header signature (see the `mht` entry below).
--
-- mht_fws: RFC 5322 folding whitespace. Horizontal space, optionally continued
-- onto following lines. A continuation must begin with at least one space or
-- tab, and that requirement is exactly what separates a fold from the empty
-- line terminating the header block, so this can never run past the block.
local mht_fws = [=[[ \t]*(?:\r?\n[ \t]+)*]=]

-- mht_hdr_line: one non-blank line. The leading [^\r\n] rejects both "\r\n"
-- and "\n", so a run of these stops at the empty line that ends the header
-- block and cannot reach a nested part's headers. Folded continuation lines
-- start with space or tab and are matched, as they should be.
local mht_hdr_line = [=[(?:[^\r\n][^\n]*\n)*]=]

-- Characters that may legitimately follow a MIME token. An RFC 2045 token is
-- everything except SPACE, CTLs and tspecials, so any of these ends it, while
-- a token character continuing it means we matched only a *prefix* of some
-- other value - "multipart/relatedness" for the media type, "1.00" for the
-- version. LF is handled separately by the two forms below.
local mht_tok_end = [=[ \t;(\r]=]

-- Remainder of a header line after a matched token, used when further header
-- lines still have to be matched: either the line ends immediately, or what
-- follows the token starts with a terminator.
local mht_line_rest = [=[(?:[]=] .. mht_tok_end .. [=[][^\n]*)?\n]=]

-- Token terminator for a match that ends here: end of line, or end of content.
local mht_tok_boundary = [=[(?:[]=] .. mht_tok_end .. [=[\n]|$)]=]

local mht_mime_version = [=[MIME-Version:]=] .. mht_fws .. [=[1\.0]=]
local mht_related = [=[Content-Type:]=] .. mht_fws .. [=[multipart/related]=]

local patterns = {
  pdf = {
    -- These are alternatives
    matches = {
      {
        string = [[%PDF-[12]\.\d]],
        position = { '<=', 1024 },
        weight = 60,
        heuristic = heuristics.pdf_format_heuristic
      },
      {
        string = [[%FDF-[12]\.\d]],
        position = { '<=', 1024 },
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
  -- MHTML/MHT web page archive (RFC 2557): saved as a raw RFC822-style
  -- header block declaring a multipart/related structure. Browsers/MUAs
  -- normally attach this as an opaque blob (e.g. application/octet-stream
  -- or no useful Content-Type at all), so we cannot rely on MIME headers
  -- alone and detect it from the content itself instead. Both markers are
  -- required in a single pattern (rather than two independently-weighted
  -- matches) so that a plain "MIME-Version: 1.0" header alone (present on
  -- practically any forwarded message) can never trigger a false match.
  --
  -- Both markers must sit in the OUTER header block of the content.
  --
  -- "Somewhere in the first N bytes" is not good enough. A perfectly ordinary
  -- forwarded .eml carries MIME-Version: 1.0 in its own headers and, a few
  -- dozen bytes later, a nested part that opens with Content-Type:
  -- multipart/related - so a flat proximity search labels it an MHT archive
  -- and routes it down the MHTML path. Anchoring each marker to a line start
  -- does not help either: both of those ARE real headers, just not of the
  -- same entity.
  --
  -- So the header block is described explicitly: `^` pins the match to the
  -- start of the content and mht_hdr_line walks only non-blank lines. See the
  -- definitions above for why neither that walk nor the folding whitespace
  -- inside a header value can cross the blank line ending the block.
  --
  -- Both header orders are accepted, since MIME entity headers are unordered
  -- and only browsers reliably put MIME-Version first. Kept as one alternation
  -- rather than two matches so a document cannot score the weight twice.
  --
  -- This also costs less than the bounded .{0,256} gap it replaces: a handful
  -- of small NFA loops instead of two 256-wide bounded repeats, in a pattern
  -- that lives in the shared database every attachment is scanned against.
  mht = {
    matches = {
      {
        string = [=[(?i)^]=] .. mht_hdr_line .. [=[(?:]=] ..
            mht_mime_version .. mht_line_rest .. mht_hdr_line ..
            mht_related .. mht_tok_boundary ..
            [=[|]=] ..
            mht_related .. mht_line_rest .. mht_hdr_line ..
            mht_mime_version .. mht_tok_boundary ..
            [=[)]=],
        position = { '<=', 2048 },
        weight = 60,
      },
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
  -- OneNote section file: GUID {7B5C52E4-D88C-4DA7-AEB1-5378D02996D3}
  one = {
    matches = {
      {
        hex = [[e4525c7b8cd8a74daeb15378d02996d3]],
        relative_position = 0,
        weight = 60,
      }
    }
  },
  -- VHD: dynamic/differencing disks keep a copy of the "conectix" footer at
  -- offset 0 too (fixed-format VHDs, footer-only-at-EOF, are not matched here)
  vhd = {
    matches = {
      {
        string = [[conectix]],
        relative_position = 0,
        weight = 60,
      }
    }
  },
  vhdx = {
    matches = {
      {
        string = [[vhdxfile]],
        relative_position = 0,
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
        weight = 15,
      },
      -- PE part
      {
        string = [[PE\x{00}\x{00}]],
        position = { '>=', 0x3c + 4 },
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
        position = { '>=', 0 },
        weight = 60,
      },
    }
  },
  -- Windows Internet Shortcut (abused for NTLM-leak / WebDAV redirect phishing)
  url = {
    matches = {
      {
        string = [=[(?i)^(?:\x{ef}\x{bb}\x{bf})?\[InternetShortcut\]]=],
        position = { '<=', 32 },
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
  asc = {
    matches = {
      {
        string = [[-----BEGIN PGP PUBLIC KEY BLOCK-----]],
        weight = 60,
        relative_position = 0,
      },
    }
  },
  -- Detached ASCII-armored signature, e.g. foo.txt.sig; distinct from asc
  -- (pgp-keys) since file(1) also reports these under different mime types
  sig = {
    matches = {
      {
        string = [[-----BEGIN PGP SIGNATURE-----]],
        weight = 60,
        relative_position = 0,
      },
    }
  },
  xml = {
    matches = {
      {
        -- XML prolog
        string = [[<\?xml\b.+\?>]],
        position = { '>=', 0 },
        weight = 30,
      },
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
        position = { '>=', 8 },
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
  zip = {
    matches = {
      {
        hex = [[504b0304]], -- PK\x03\x04
        relative_position = 0,
        weight = 60,
      },
    }
  },
  rar = {
    matches = {
      {
        hex = [[526172211a0700]], -- RAR4
        relative_position = 0,
        weight = 60,
      },
      {
        hex = [[526172211a070100]], -- RAR5
        relative_position = 0,
        weight = 60,
      },
    }
  },
  ['7z'] = {
    matches = {
      {
        hex = [[377abcaf271c]], -- 7z signature
        relative_position = 0,
        weight = 60,
      },
    }
  },
  gz = {
    matches = {
      {
        string = [[^\x{1f}\x{8b}\x{08}]], -- gzip with deflate method
        position = 3,
        weight = 60,
      },
    }
  },
  z = {
    -- Unix compress (.Z)
    matches = {
      {
        hex = [[1f9d]],
        relative_position = 0,
        weight = 60,
      },
    }
  },
  lha = {
    -- LHA/LZH: byte0 header_size, byte1 header_checksum, bytes2-6 a 5-char
    -- method ID ("-lh5-", "-lz4-", ...); not anchored at 0, so match end
    -- offset must land exactly at byte 7
    matches = {
      {
        string = [[-l(?:h[0-7d]|z[45s])-]],
        position = 7,
        weight = 60,
      },
    }
  },
  lz = {
    -- lzip: "LZIP" + 1-byte version
    matches = {
      {
        hex = [[4c5a4950]],
        relative_position = 0,
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
        position = { '>=', 0x8000 + 7 }, -- first 32k is unused
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
  webp = {
    matches = {
      {
        -- RIFF....WEBP
        string = [[^RIFF....WEBP]],
        position = 12,
        weight = 60,
      },
    }
  },
  svg = {
    matches = {
      {
        -- Case-insensitive <svg ...> in the first chunk
        -- Use heuristic to avoid misdetecting HTML with embedded SVG
        string = [[(?i)<svg\b]],
        position = { '<=', 4096 },
        weight = 40,
        heuristic = heuristics.svg_format_heuristic
      },
      {
        -- Case-insensitive <!DOCTYPE svg ...> within the first 4KiB
        -- DOCTYPE svg is unambiguous - no heuristic needed
        string = [[(?i)<!doctype\s+svg]],
        position = { '<=', 4096 },
        weight = 40,
      },
    }
  },
  -- Other
  -- PKCS#7 / S/MIME detached signature: SEQUENCE header + signedData OID
  -- (1.2.840.113549.1.7.2); not anchored at 0, position <= 20 covers the
  -- outer SEQUENCE TLV header preceding the OID bytes
  p7s = {
    matches = {
      {
        hex = [[06092a864886f70d010702]],
        position = { '<=', 20 },
        weight = 60,
      },
    }
  },
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
  heic = {
    matches = {
      {
        -- HEIC/HEIF file format signature
        -- Starts with ftyp followed by specific brand identifiers
        string = "^....ftyphe[im][cs]",
        position = 12,
        weight = 60,
      },
      {
        -- Alternative signature for HEIC/HEIF
        string = [[^....ftypmif1]],
        position = 12,
        weight = 60,
      },
    }
  },
  wmf = {
    matches = {
      {
        -- Placeable WMF (Aldus Placeable Metafile)
        hex = [[D7CDC69A]],
        relative_position = 0,
        weight = 60,
      },
      {
        -- Standard WMF: type (1=memory/2=disk), header size=9
        string = [[^[\x{01}\x{02}]\x{00}\x{09}\x{00}]],
        position = 4,
        weight = 55,
      },
    }
  },
  -- EMF: EMR_HEADER record type=1, " EMF" signature at fixed offset 40
  emf = {
    matches = {
      {
        string = [[^\x{01}\x{00}\x{00}\x{00}.{36} EMF]],
        position = 44,
        weight = 60,
      },
    }
  },
  -- Audio/Video
  flac = {
    matches = {
      {
        string = [[fLaC]],
        relative_position = 0,
        weight = 60,
      },
    }
  },
  mp3 = {
    matches = {
      {
        -- ID3v2 tag: require version + flags bytes so plain ASCII text
        -- starting with "ID3" (e.g. a CSV export) does not match
        string = [[^ID3[\x{02}-\x{04}]\x{00}]],
        position = 5,
        weight = 60,
      },
      {
        -- Raw MPEG audio frame sync with no ID3 tag (e.g. voicemail/IVR
        -- dumps); the trie cannot bitmask, so a heuristic verifies the
        -- second header byte encodes a valid version/layer combination
        hex = [[FF]],
        relative_position = 0,
        weight = 10,
        heuristic = heuristics.mp3_frame_heuristic,
      },
    }
  },
  ogg = {
    matches = {
      {
        -- OggS capture pattern + stream structure version 0
        string = [[^OggS\x{00}]],
        position = 5,
        weight = 60,
        heuristic = heuristics.ogg_format_heuristic
      },
    }
  },
  avi = {
    matches = {
      {
        string = [[^RIFF....AVI ]],
        position = 12,
        weight = 60,
      },
    }
  },
  wav = {
    matches = {
      {
        string = [[^RIFF....WAVE]],
        position = 12,
        weight = 60,
      },
    }
  },
  aiff = {
    matches = {
      {
        string = '^FORM....AIF[FC]',
        position = 12,
        weight = 60,
      },
    }
  },
  flv = {
    matches = {
      {
        string = [[^FLV\x{01}]],
        position = 4,
        weight = 60,
      },
    }
  },
  asf = {
    -- ASF header object GUID (WMV/WMA container); heuristic reads the
    -- Stream Properties Object GUID to tell audio-only WMA from WMV
    matches = {
      {
        hex = [[3026b2758e66cf11a6d900aa0062ce6c]],
        relative_position = 0,
        weight = 60,
        heuristic = heuristics.asf_format_heuristic
      },
    }
  },
  mkv = {
    -- EBML magic (Matroska/WebM container); heuristic reads the DocType
    -- element and scans Tracks CodecIDs to tell webm/mkv and audio-only
    -- mka/weba apart
    matches = {
      {
        hex = [[1a45dfa3]],
        relative_position = 0,
        weight = 60,
        heuristic = heuristics.mkv_format_heuristic
      },
    }
  },
  mp4 = {
    matches = {
      {
        -- Any ISO-BMFF ftyp box; the heuristic dispatches on the major
        -- brand (bytes 9-12) since new brands (iso6, dash, ...) appear
        -- far faster than a hand-maintained regex list can track them,
        -- and falls back to mp4 for brands it doesn't specifically know
        string = [[^....ftyp]],
        position = 8,
        weight = 60,
        heuristic = heuristics.ftyp_format_heuristic
      },
    }
  },
  mov = {
    matches = {
      {
        -- Legacy/minimally-muxed QuickTime files with no ftyp box at all,
        -- starting directly with a moov or mdat atom
        string = [[^....(?:moov|mdat)]],
        position = 8,
        weight = 50,
      },
    }
  },
}

return patterns
