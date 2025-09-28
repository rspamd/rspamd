local rspamd_util = require 'rspamd_util'
local rspamd_text = require 'rspamd_text'
local argparse = require 'argparse'

local parser = argparse()
    :name "secretbox"
    :description "Encrypt/decrypt given text with given key and nonce"
    :help_description_margin(32)
    :command_target('command')
    :require_command(true)

parser:mutex(
  parser:flag '-R --raw'
  :description('Encrypted text(and nonce if it is there) will be given in raw'),
  parser:flag '-H --hex'
  :description('Encrypted text(and nonce if it is there) will be given in hex'),
  parser:flag '-b --base32'
  :description('Encrypted text(and nonce if it is there) will be given in base32'),
  parser:flag '-B --base64'
  :description('Encrypted text(and nonce if it is there) will be given in base64')
)

local decrypt = parser:command 'decrypt'
    :description 'Decrypt text with given key and nonce'

decrypt:option "-t --text"
    :description("Encrypted text")
    :argname("<text>")
decrypt:option "-k --key"
    :description("Key used to encrypt text")
    :argname("<key>")
decrypt:option "-n --nonce"
    :description("Nonce used to encrypt text")
    :argname("<nonce>")
    :default(nil)

local encrypt = parser:command 'encrypt'
    :description 'Encrypt text with given key'

encrypt:option "-t --text"
    :description("Text to encrypt")
    :argname("<text>")
encrypt:option "-k --key"
    :description("Key to encrypt text")
    :argname("<key>")
encrypt:option "-n --nonce"
    :description("Nonce to encrypt text")
    :argname("<nonce>")
    :default(nil)

local keygen = parser:command 'keygen'
    :description 'Generate symmetric key'

keygen:option "-l --length"
    :description("Key length in bytes (default 32)")
    :argname("<length>")
    :default("32")

local function set_up_encoding(args, type, text)
  local function fromhex(str)
    return (str:gsub('..', function(cc)
      return string.char(tonumber(cc, 16))
    end))
  end

  local function tohex(str)
    return (str:gsub('.', function(c)
      return string.format('%02X', string.byte(c))
    end))
  end

  local output = text

  if type == 'encode' then
    if args.hex then
      output = tohex(text)
    elseif args.base32 then
      output = rspamd_util.encode_base32(text)
    elseif args.base64 then
      output = rspamd_util.encode_base64(text)
    end
  elseif type == 'decode' then
    if args.hex then
      output = fromhex(text)
    elseif args.base32 then
      output = rspamd_util.decode_base32(text)
    elseif args.base64 then
      output = rspamd_util.decode_base64(text)
    else
      -- Autodetect input encoding when no explicit flags are provided
      if text and #text > 0 then
        -- If input contains non-ASCII bytes, treat as raw to avoid corruption
        if not text:match('^[%g%s]+$') then
          return text
        end

        local cand = text:gsub('%s+', '')
        -- Prefer hex if it looks like hex (even length)
        if cand:match('^%x+$') and (#cand % 2 == 0) then
          output = fromhex(cand)
        else
          -- Try base64 (standard and urlsafe characters)
          if cand:match('^[A-Za-z0-9+/=_-]+$') and (#cand % 4 == 0) then
            local b64 = rspamd_util.decode_base64(cand)
            if b64 and b64 ~= '' then
              output = b64
            else
              -- Try base32 (check charset and length multiple of 8)
              local up = cand:upper()
              if up:match('^[A-Z2-7=]+$') and (#up % 8 == 0) then
                local b32 = rspamd_util.decode_base32(cand)
                if b32 and b32 ~= '' then
                  output = b32
                end
              end
            end
          else
            -- Try base32 directly if base64 pattern doesn't match
            local up = cand:upper()
            if up:match('^[A-Z2-7=]+$') and (#up % 8 == 0) then
              local b32 = rspamd_util.decode_base32(cand)
              if b32 and b32 ~= '' then
                output = b32
              end
            end
          end
        end
      end
    end
  end

  return output
end

local function read_all_stdin()
  local data = io.read('*a')
  if not data then return '' end
  return data
end

local function get_text_input(args)
  if args.text == nil or args.text == '-' then
    return read_all_stdin()
  end
  return args.text
end

local function write_output(args, text)
  if args.hex or args.base32 or args.base64 then
    print(set_up_encoding(args, 'encode', text))
  else
    io.write(text)
  end
end

-- Auto-detect key encoding (hex or base64) and return raw bytes string
local function decode_key_auto(key_str)
  if not key_str or key_str == '' then return key_str end

  local function fromhex(str)
    return (str:gsub('..', function(cc)
      return string.char(tonumber(cc, 16))
    end))
  end

  -- hex: only [0-9A-Fa-f], even length, and long enough to likely be a key (>=32 bytes)
  if key_str:match('^%x+$') and (#key_str % 2 == 0) and (#key_str >= 64) then
    return fromhex(key_str)
  end

  -- base64: only valid charset, length multiple of 4, and long enough (>= 44 for 32 bytes)
  if key_str:match('^[A-Za-z0-9+/=]+$') and (#key_str % 4 == 0) and (#key_str >= 44) then
    local decoded = rspamd_util.decode_base64(key_str)
    if decoded and decoded ~= '' then
      return decoded
    end
  end

  -- fallback: treat as raw
  return key_str
end

local function decryption_handler(args)
  local rspamd_secretbox = require 'rspamd_cryptobox_secretbox'
  local key = decode_key_auto(args.key)
  local box = rspamd_secretbox.create(key)

  local plaintext = nil
  local input_text = get_text_input(args)
  if (args.nonce ~= nil) then
    local decoded_text = set_up_encoding(args, 'decode', input_text)
    local decoded_nonce = set_up_encoding(args, 'decode', tostring(args.nonce))

    local ok, out = box:decrypt(decoded_text, decoded_nonce)
    if ok then plaintext = out end
  else
    local text_with_nonce = set_up_encoding(args, 'decode', input_text)
    local nonce, text
    if type(text_with_nonce) == 'userdata' then
      nonce = text_with_nonce:sub(1, 24)
      text = text_with_nonce:sub(25)
    else
      local s = tostring(text_with_nonce)
      nonce = string.sub(s, 1, 24)
      text = string.sub(s, 25)
    end

    local ok, out = box:decrypt(text, nonce)
    if ok then plaintext = out end
  end

  if plaintext ~= nil then
    -- Plaintext must be printed as-is to preserve legacy semantics
    print(tostring(plaintext))
  else
    print('The decryption failed. Please check the correctness of the arguments given.')
  end
end

local function encryption_handler(args)
  local rspamd_secretbox = require 'rspamd_cryptobox_secretbox'
  local key = decode_key_auto(args.key)
  local box = rspamd_secretbox.create(key)

  local combined
  local input_text = get_text_input(args)
  if args.nonce ~= nil then
    local decoded_nonce = set_up_encoding(args, 'decode', tostring(args.nonce))
    local ct = box:encrypt(input_text, decoded_nonce)
    combined = tostring(decoded_nonce) .. tostring(ct)
  else
    local ct, nonce = box:encrypt(input_text)
    combined = tostring(nonce) .. tostring(ct)
  end

  if combined ~= nil then
    write_output(args, tostring(combined))
  else
    print('The encryption failed. Please check the correctness of the arguments given.')
  end
end

local function keygen_handler(args)
  local len = tonumber(args.length) or 32
  if len <= 0 then len = 32 end

  local key = rspamd_text.randombytes(len)
  local raw = key:str()

  if not (args.hex or args.base32 or args.base64 or args.raw) then
    -- default to base64 for key output if not specified
    print(rspamd_util.encode_base64(raw))
  else
    print(set_up_encoding(args, 'encode', raw))
  end
end

local command_handlers = {
  decrypt = decryption_handler,
  encrypt = encryption_handler,
  keygen = keygen_handler,
}

local function handler(args)
  local cmd_opts = parser:parse(args)

  local f = command_handlers[cmd_opts.command]
  if not f then
    parser:error(string.format("command isn't implemented: %s",
      cmd_opts.command))
  end
  f(cmd_opts)
end


return {
  name = 'secret_box',
  aliases = { 'secretbox', 'secret_box' },
  handler = handler,
  description = parser._description
}
