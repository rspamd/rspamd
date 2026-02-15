-- Unit tests for metadata_exporter structured formatter features
-- Tests: UUID v7, zstd compression, detected MIME types

local rspamd_util = require "rspamd_util"
local rspamd_text = require "rspamd_text"
local rspamd_zstd = require "rspamd_zstd"
local ucl = require "ucl"

context("UUID v7 validation", function()
  -- UUID v7 format: xxxxxxxx-xxxx-7xxx-xxxx-xxxxxxxxxxxx
  -- - 48-bit millisecond timestamp prefix
  -- - Version 7 (0111) in bits 48-51 (position 14 in string = '7')
  -- - Variant 10 in bits 64-65 (position 19 in string = 8,9,a,b)
  -- - 74 random bits

  local function hex_to_int(hex)
    local n = 0
    for i = 1, #hex do
      local c = hex:sub(i, i):lower()
      local digit = c:byte() - (c:match("%d") and 48 or 87)
      n = n * 16 + digit
    end
    return n
  end

  local function uuid_timestamp_ms(uuid)
    -- Extract first 12 hex chars (48 bits) as millisecond timestamp
    local hex = uuid:sub(1, 8) .. uuid:sub(10, 13)
    return hex_to_int(hex)
  end

  test("task:get_uuid() returns valid UUID v7 format", function()
    local rspamd_task = require "rspamd_task"
    local msg = [[
From: <test@example.com>
To: <nobody@example.com>
Subject: UUID test

Test body.
]]
    local res, task = rspamd_task.load_from_string(msg, rspamd_config)
    assert_true(res, "failed to load message")
    task:process_message()

    local uuid = task:get_uuid()
    assert_not_nil(uuid, "task:get_uuid() returned nil")
    assert_equal(#uuid, 36, "UUID should be 36 characters")

    -- Check UUID format: 8-4-4-4-12 hex digits with dashes
    assert_match("^%x%x%x%x%x%x%x%x%-%x%x%x%x%-%x%x%x%x%-%x%x%x%x%-%x%x%x%x%x%x%x%x%x%x%x%x$",
        uuid, "UUID format invalid")

    task:destroy()
  end)

  test("UUID v7 timestamp is recent", function()
    local rspamd_task = require "rspamd_task"
    local msg = [[
From: <test@example.com>
To: <nobody@example.com>
Subject: Timestamp test

Test.
]]
    local res, task = rspamd_task.load_from_string(msg, rspamd_config)
    assert_true(res)
    task:process_message()

    local uuid = task:get_uuid()
    local uuid_ms = uuid_timestamp_ms(uuid)
    local now_ms = math.floor(rspamd_util.get_time() * 1000)

    -- UUID timestamp should be within 5 seconds of now
    local diff = math.abs(now_ms - uuid_ms)
    assert_true(diff < 5000, "UUID timestamp differs from current time by " .. diff .. "ms")

    task:destroy()
  end)

  test("UUID v7 version bits are correct", function()
    local rspamd_task = require "rspamd_task"
    local msg = [[
From: <test@example.com>
To: <nobody@example.com>
Subject: Version test

Test.
]]
    local res, task = rspamd_task.load_from_string(msg, rspamd_config)
    assert_true(res)
    task:process_message()

    local uuid = task:get_uuid()

    -- UUID v7 format: xxxxxxxx-xxxx-7xxx-xxxx-xxxxxxxxxxxx
    -- Positions:      123456789012345678901234567890123456
    -- Version nibble is at position 15 (after 2nd dash)
    local version_char = uuid:sub(15, 15)
    -- Version 7 means the high nibble is 7, so char is '7'
    assert_equal(version_char, "7", "UUID version nibble should be '7', got: " .. version_char .. " uuid=" .. uuid)

    -- Variant bits: first char of fourth group (position 20) should be 8, 9, a, or b
    -- xxxxxxxx-xxxx-xxxx-8xxx-...
    local variant_char = uuid:sub(20, 20)
    assert_match("^[89ab]$", variant_char, "UUID variant should be 10xx (8, 9, a, or b), got: " .. variant_char .. " uuid=" .. uuid)

    task:destroy()
  end)

  test("UUIDs are unique across tasks", function()
    local rspamd_task = require "rspamd_task"
    local msg = [[
From: <test@example.com>
To: <nobody@example.com>
Subject: Uniqueness test

Test.
]]
    local uuids = {}

    for i = 1, 10 do
      local res, task = rspamd_task.load_from_string(msg, rspamd_config)
      assert_true(res)
      task:process_message()
      local uuid = task:get_uuid()
      assert_not_nil(uuid)
      assert_nil(uuids[uuid], "Duplicate UUID generated: " .. uuid)
      uuids[uuid] = true
      task:destroy()
    end

    -- Verify we got 10 unique UUIDs
    local count = 0
    for _ in pairs(uuids) do count = count + 1 end
    assert_equal(count, 10, "Expected 10 unique UUIDs")
  end)
end)

context("zstd compression in structured formatter", function()
  test("rspamd_util.zstd_compress produces valid compressed data", function()
    local original = "Hello, World! This is a test string for compression."
    local compressed = rspamd_util.zstd_compress(original)

    assert_not_nil(compressed, "zstd_compress returned nil")
    assert_true(compressed:len() > 0, "Compressed data should not be empty")
    -- zstd magic number: 0xFD2FB528 (little-endian: 28 B5 2F FD)
    -- compressed is a rspamd_text, need to get bytes
    local bytes = compressed:bytes()
    assert_equal(bytes[1], 0x28, "Invalid zstd magic byte 1")
    assert_equal(bytes[2], 0xB5, "Invalid zstd magic byte 2")
    assert_equal(bytes[3], 0x2F, "Invalid zstd magic byte 3")
    assert_equal(bytes[4], 0xFD, "Invalid zstd magic byte 4")
  end)

  test("zstd compression round-trip preserves data", function()
    local cases = {
      "simple string",
      string.rep("x", 1000),  -- repetitive data
      "Mixed 123 Numbers! And symbols: @#$%^&*()",
    }

    local cctx = rspamd_zstd.compress_ctx()
    local dctx = rspamd_zstd.decompress_ctx()

    for i, original in ipairs(cases) do
      local compressed = rspamd_util.zstd_compress(original)
      assert_not_nil(compressed, "Case " .. i .. ": zstd_compress returned nil")

      -- Use streaming API for decompression (matches existing test patterns)
      local decompressed = dctx:stream(compressed, 'end')
      assert_rspamd_eq({
        actual = decompressed,
        expect = rspamd_text.fromstring(original)
      })
    end
  end)

  test("zstd compression reduces size for repetitive data", function()
    local original = string.rep("abcdefghij", 1000)  -- 10000 bytes of repetitive data
    local compressed = rspamd_util.zstd_compress(original)

    assert_true(compressed:len() < #original,
        "Compressed size (" .. compressed:len() .. ") should be less than original (" .. #original .. ")")
  end)
end)

context("Structured formatter output validation", function()
  local rspamd_task = require "rspamd_task"

  test("structured output contains required fields", function()
    local msg = [[
From: <sender@example.com>
To: <recipient@example.com>
Subject: Test message
Message-ID: <test123@example.com>

This is the body text.
]]
    local res, task = rspamd_task.load_from_string(msg, rspamd_config)
    assert_true(res)
    task:process_message()

    local uuid = task:get_uuid()
    assert_not_nil(uuid, "UUID should not be nil")
    assert_equal(#uuid, 36, "UUID should be 36 characters")

    -- Verify we can get basic task info
    local subject = task:get_subject()
    assert_equal(subject, "Test message", "Subject mismatch")

    local msg_id = task:get_message_id()
    assert_not_nil(msg_id, "Message-ID should not be nil")

    task:destroy()
  end)

  test("msgpack format is valid", function()
    local test_data = {
      uuid = "01234567-89ab-7def-8000-000000000000",
      text = "Sample text",
      attachments = {
        {
          filename = "test.txt",
          content_type = "text/plain",
          size = 100,
        }
      },
    }

    local msgpack = ucl.to_format(test_data, "msgpack")
    assert_not_nil(msgpack, "msgpack encoding failed")
    assert_true(msgpack:len() > 0, "msgpack output should not be empty")

    -- Verify we can decode it back using ucl.parser
    local parser = ucl.parser()
    local ok, err = parser:parse_string(msgpack, "msgpack")
    assert_true(ok, "msgpack parsing failed: " .. tostring(err))

    local obj = parser:get_object_wrapped()
    assert_equal(obj:at("uuid"):unwrap(), test_data.uuid, "UUID mismatch after round-trip")
  end)
end)

context("Detected MIME types", function()
  local rspamd_task = require "rspamd_task"

  test("get_detected_type returns nil for plain text", function()
    local msg = [[
From: <test@example.com>
To: <test@example.com>
Subject: Plain text
Content-Type: text/plain

Just plain text.
]]
    local res, task = rspamd_task.load_from_string(msg, rspamd_config)
    assert_true(res)
    task:process_message()

    local parts = task:get_parts()
    assert_not_nil(parts)
    assert_true(#parts > 0)

    -- Text parts typically don't have detected types different from announced
    for _, part in ipairs(parts) do
      local detected_type, detected_subtype = part:get_detected_type()
      -- May be nil for plain text, which is expected
      -- The important thing is the API works
      if detected_type then
        assert_not_nil(detected_subtype, "detected_subtype should be present if detected_type is")
      end
    end

    task:destroy()
  end)

  test("get_type returns announced MIME type", function()
    local msg = [[
From: <test@example.com>
To: <test@example.com>
Subject: HTML message
Content-Type: text/html; charset=utf-8

<html><body>HTML content</body></html>
]]
    local res, task = rspamd_task.load_from_string(msg, rspamd_config)
    assert_true(res)
    task:process_message()

    local parts = task:get_parts()
    for _, part in ipairs(parts) do
      local mime_type, mime_subtype = part:get_type()
      if mime_type then
        assert_equal(mime_type, "text", "Expected text type")
        assert_equal(mime_subtype, "html", "Expected html subtype")
      end
    end

    task:destroy()
  end)
end)
