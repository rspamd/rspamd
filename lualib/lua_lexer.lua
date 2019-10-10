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

--[[ Lua LPEG grammar based on https://github.com/xolox/lua-lxsh/ ]]


local lpeg = require "lpeg"

local P = lpeg.P
local R = lpeg.R
local S = lpeg.S
local D = R'09' -- Digits
local I = R('AZ', 'az', '\127\255') + '_' -- Identifiers
local B = -(I + D) -- Word boundary
local EOS = -lpeg.P(1) -- end of string

-- Pattern for long strings and long comments.
local longstring = #(P'[[' + (P'[' * P'='^0 * '[')) * P(function(input, index)
  local level = input:match('^%[(=*)%[', index)
  if level then
    local _, last = input:find(']' .. level .. ']', index, true)
    if last then return last + 1 end
  end
end)

-- String literals.
local singlequoted = P"'" * ((1 - S"'\r\n\f\\") + (P'\\' * 1))^0 * "'"
local doublequoted = P'"' * ((1 - S'"\r\n\f\\') + (P'\\' * 1))^0 * '"'

-- Comments.
local eol = P'\r\n' + '\n'
local line = (1 - S'\r\n\f')^0 * eol^-1
local singleline = P'--' * line
local multiline = P'--' * longstring

-- Numbers.
local sign = S'+-'^-1
local decimal = D^1
local hexadecimal = P'0' * S'xX' * R('09', 'AF', 'af') ^ 1
local float = D^1 * P'.' * D^0 + P'.' * D^1
local maybeexp = (float + decimal) * (S'eE' * sign * D^1)^-1

local function compile_keywords(keywords)
  local list = {}
  for word in keywords:gmatch('%S+') do
    list[#list + 1] = word
  end
  -- Sort by length
  table.sort(list, function(a, b)
    return #a > #b
  end)

  local pattern
  for _, word in ipairs(list) do
    local p = lpeg.P(word)
    pattern = pattern and (pattern + p) or p
  end

  local AB = B + EOS -- ending boundary
  return pattern * AB
end

-- Identifiers
local ident = I * (I + D)^0
local expr = ('.' * ident)^0

local patterns = {
  {'whitespace',  S'\r\n\f\t\v '^1},
  {'constant', (P'true' + 'false' + 'nil') * B},
  {'string', singlequoted + doublequoted + longstring},
  {'comment', multiline + singleline},
  {'number', hexadecimal + maybeexp},
  {'operator', P'not' + '...' + 'and' + '..' + '~=' + '==' + '>=' + '<='
      + 'or' + S']{=>^[<;)*(%}+-:,/.#'},
  {'keyword', compile_keywords([[
      break do else elseif end for function if in local repeat return then until while
      ]])},
  {'identifier', lpeg.Cmt(ident,
      function(input, index)
        return expr:match(input, index)
      end)
  },
  {'error', 1},
}

local compiled

local function compile_patterns()
  if not compiled then
    local function process(elt)
      local n,grammar = elt[1],elt[2]
      return lpeg.Cc(n) * lpeg.P(grammar) * lpeg.Cp()
    end
    local any = process(patterns[1])
    for i = 2, #patterns do
      any = any + process(patterns[i])
    end
    compiled = any
  end

  return compiled
end

local function sync(token, lnum, cnum)
  local lastidx
  lnum, cnum = lnum or 1, cnum or 1
  if token:find '\n' then
    for i in token:gmatch '()\n' do
      lnum = lnum + 1
      lastidx = i
    end
    cnum = #token - lastidx + 1
  else
    cnum = cnum + #token
  end
  return lnum, cnum
end

local exports = {}

exports.gmatch = function(input)
  local parser = compile_patterns()
  local index, lnum, cnum = 1, 1, 1

  return function()
    local kind, after = parser:match(input, index)
    if kind and after then
      local text = input:sub(index, after - 1)
      local oldlnum, oldcnum = lnum, cnum
      index = after
      lnum, cnum = sync(text, lnum, cnum)
      return kind, text, oldlnum, oldcnum
    end
  end
end

exports.lex_to_table = function(input)
  local out = {}

  for kind, text, lnum, cnum in exports.gmatch(input) do
    out[#out + 1] = {kind, text, lnum, cnum}
  end

  return out
end

return exports

