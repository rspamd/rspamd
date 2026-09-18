-- lua_magic MHTML detection (lualib/lua_magic)

context("lua_magic MHTML detection", function()
  local lua_magic = require "lua_magic"

  local function fake_part(content)
    return {
      get_content = function()
        return content
      end,
      is_archive = function()
        return false
      end,
      get_filename = function()
        return nil
      end,
      get_type = function()
        return 'application', 'octet-stream'
      end,
    }
  end

  local function make_mht(boundary)
    return table.concat({
      "From: <Saved by Browser>\n",
      "Subject: Some page\n",
      "MIME-Version: 1.0\n",
      string.format('Content-Type: multipart/related; boundary="%s"\n\n', boundary),
      "--" .. boundary .. "\n",
      "Content-Type: text/html\n\n<html><body>hi</body></html>\n",
      "--" .. boundary .. "--\n",
    })
  end

  test("detects a genuine MHTML archive as mht", function()
    local ext, ty = lua_magic.detect(fake_part(make_mht("----MultipartBoundary--abc123")), rspamd_config)
    assert_equal(ext, 'mht')
    assert_not_nil(ty)
    assert_equal(ty.ct, 'application/x-mimearchive')
  end)

  test("does not detect a plain rfc822 message without multipart/related", function()
    local input = "From: a@example.com\nMIME-Version: 1.0\nContent-Type: text/plain\n\nhello world"
    local ext = lua_magic.detect(fake_part(input), rspamd_config)
    assert_nil(ext)
  end)

  test("does not detect plain text content", function()
    local ext = lua_magic.detect(fake_part("just some random text without mime markers"), rspamd_config)
    assert_nil(ext)
  end)

  -- MIME entity headers are unordered. Browsers emit MIME-Version first, but
  -- nothing requires that, and an archive whose Content-Type comes first must
  -- still be recognised or it will never be routed to the MHTML scanner.
  local function make_mht_reversed(boundary)
    return table.concat({
      "From: <Saved by Browser>\n",
      "Subject: Some page\n",
      string.format('Content-Type: multipart/related; boundary="%s"\n', boundary),
      "MIME-Version: 1.0\n\n",
      "--" .. boundary .. "\n",
      "Content-Type: text/html\n\n<html><body>hi</body></html>\n",
      "--" .. boundary .. "--\n",
    })
  end

  test("detects an MHTML archive with Content-Type before MIME-Version", function()
    local ext, ty = lua_magic.detect(fake_part(make_mht_reversed("----Boundary--abc123")), rspamd_config)
    assert_equal(ext, 'mht')
    assert_not_nil(ty)
    assert_equal(ty.ct, 'application/x-mimearchive')
  end)

  test("does not detect MIME-Version alone as mht", function()
    local input = table.concat({
      "From: a@example.com\n",
      "MIME-Version: 1.0\n",
      "Content-Type: multipart/alternative; boundary=\"X\"\n\n",
      "--X\nContent-Type: text/plain\n\nhello\n--X--\n",
    })
    local ext = lua_magic.detect(fake_part(input), rspamd_config)
    assert_nil(ext)
  end)

  -- Both markers must belong to the OUTER header block. These fixtures all
  -- contain a real "MIME-Version: 1.0" header and a real
  -- "Content-Type: multipart/related" header, just not on the same entity,
  -- which is what an ordinary forwarded message looks like.
  test("does not detect a forwarded message whose nested part is multipart/related", function()
    local input = table.concat({
      "Received: from mx.example.com; Mon, 1 Jan 2026 00:00:00 +0000\n",
      "From: <alice@example.com>\n",
      "To: <bob@example.com>\n",
      "Subject: Fwd: newsletter\n",
      "MIME-Version: 1.0\n",
      'Content-Type: multipart/mixed; boundary="OUT"\n\n',
      "--OUT\n",
      'Content-Type: multipart/related; boundary="INNER"\n\n',
      "--INNER\n",
      "Content-Type: text/html\n\n<html><body>hi</body></html>\n",
      "--INNER--\n--OUT--\n",
    })
    assert_nil(lua_magic.detect(fake_part(input), rspamd_config))
  end)

  test("does not detect multipart/related appearing in the body under text/plain", function()
    local input = table.concat({
      "From: <alice@example.com>\n",
      "MIME-Version: 1.0\n",
      "Content-Type: text/plain\n\n",
      "forwarded message below\n\n",
      'Content-Type: multipart/related; boundary="INNER"\n\n',
      "--INNER\nContent-Type: text/html\n\n<html>hi</html>\n--INNER--\n",
    })
    assert_nil(lua_magic.detect(fake_part(input), rspamd_config))
  end)

  test("does not detect a nested message/rfc822 that is itself multipart/related", function()
    local input = table.concat({
      "From: <alice@example.com>\n",
      "MIME-Version: 1.0\n",
      'Content-Type: multipart/mixed; boundary="OUT"\n\n',
      "--OUT\n",
      "Content-Type: message/rfc822\n\n",
      "From: <carol@example.com>\n",
      "MIME-Version: 1.0\n",
      'Content-Type: multipart/related; boundary="INNER"\n\n',
      "--INNER\nContent-Type: text/html\n\n<html>hi</html>\n--INNER--\n",
      "--OUT--\n",
    })
    assert_nil(lua_magic.detect(fake_part(input), rspamd_config))
  end)

  test("detects an archive using LF-only line endings", function()
    local input = table.concat({
      "From: <Saved by Browser>",
      "MIME-Version: 1.0",
      'Content-Type: multipart/related; boundary="B"',
      "",
      "--B",
      "Content-Type: text/html",
      "",
      "<html><body>hi</body></html>",
      "--B--",
      "",
    }, "\n")
    assert_equal(lua_magic.detect(fake_part(input), rspamd_config), 'mht')
  end)

  -- RFC 5322 permits folding between the colon and the media type. A fold is
  -- a newline followed by at least one space or tab, which is what keeps it
  -- distinguishable from the empty line that ends the header block.
  test("detects an archive with a CRLF-folded Content-Type", function()
    local input = "From: <Saved by Browser>\r\nMIME-Version: 1.0\r\n"
        .. "Content-Type:\r\n\tmultipart/related;\r\n\tboundary=\"B\"\r\n\r\n"
        .. "--B\r\nContent-Type: text/html\r\n\r\n<html><body>hi</body></html>\r\n--B--\r\n"
    local ext, ty = lua_magic.detect(fake_part(input), rspamd_config)
    assert_equal(ext, 'mht')
    assert_not_nil(ty)
    assert_equal(ty.ct, 'application/x-mimearchive')
  end)

  test("detects a fold continued with a space rather than a tab", function()
    local input = "From: <Saved by Browser>\r\nMIME-Version: 1.0\r\n"
        .. "Content-Type:\r\n multipart/related; boundary=\"B\"\r\n\r\n"
        .. "--B\r\nContent-Type: text/html\r\n\r\n<html>hi</html>\r\n--B--\r\n"
    assert_equal(lua_magic.detect(fake_part(input), rspamd_config), 'mht')
  end)

  test("detects a folded MIME-Version", function()
    local input = "From: <Saved by Browser>\r\nMIME-Version:\r\n 1.0\r\n"
        .. "Content-Type: multipart/related; boundary=\"B\"\r\n\r\n"
        .. "--B\r\nContent-Type: text/html\r\n\r\n<html>hi</html>\r\n--B--\r\n"
    assert_equal(lua_magic.detect(fake_part(input), rspamd_config), 'mht')
  end)

  test("detects a folded Content-Type before MIME-Version", function()
    local input = "From: <Saved by Browser>\r\n"
        .. "Content-Type:\r\n\tmultipart/related; boundary=\"B\"\r\nMIME-Version: 1.0\r\n\r\n"
        .. "--B\r\nContent-Type: text/html\r\n\r\n<html>hi</html>\r\n--B--\r\n"
    assert_equal(lua_magic.detect(fake_part(input), rspamd_config), 'mht')
  end)

  test("detects an LF-only fold", function()
    local input = "From: <Saved by Browser>\nMIME-Version: 1.0\n"
        .. "Content-Type:\n\tmultipart/related; boundary=\"B\"\n\n"
        .. "--B\nContent-Type: text/html\n\n<html>hi</html>\n--B--\n"
    assert_equal(lua_magic.detect(fake_part(input), rspamd_config), 'mht')
  end)

  -- Guard that folding support did not reopen the header-block hole: an empty
  -- line after the colon is a block terminator, never a continuation.
  test("an empty line after Content-Type: is not a fold", function()
    local input = "From: <a@example.com>\r\nMIME-Version: 1.0\r\n"
        .. "Content-Type:\r\n\r\nmultipart/related is only discussed in this body\r\n"
    assert_nil(lua_magic.detect(fake_part(input), rspamd_config))
  end)

  -- A MIME token ends at whitespace, a ';' parameter list, a comment or the
  -- end of the line. Without that boundary the signature also matches a
  -- *prefix* of some other, unrelated value.
  local function with_ct(ct)
    return "From: <Saved by Browser>\r\nMIME-Version: 1.0\r\n"
        .. "Content-Type: " .. ct .. "; boundary=\"B\"\r\n\r\n"
        .. "--B\r\nContent-Type: text/html\r\n\r\n<html>hi</html>\r\n--B--\r\n"
  end

  test("does not detect multipart/relatedness", function()
    assert_nil(lua_magic.detect(fake_part(with_ct("multipart/relatedness")), rspamd_config))
  end)

  test("does not detect a hyphenated subtype extending related", function()
    -- '-' is a token character, so multipart/related-x is a distinct subtype
    assert_nil(lua_magic.detect(fake_part(with_ct("multipart/related-x")), rspamd_config))
  end)

  test("does not detect a digit-suffixed subtype extending related", function()
    assert_nil(lua_magic.detect(fake_part(with_ct("multipart/related2")), rspamd_config))
  end)

  test("does not detect MIME-Version 1.00", function()
    local input = "From: <Saved by Browser>\r\nMIME-Version: 1.00\r\n"
        .. "Content-Type: multipart/related; boundary=\"B\"\r\n\r\n"
        .. "--B\r\nContent-Type: text/html\r\n\r\n<html>hi</html>\r\n--B--\r\n"
    assert_nil(lua_magic.detect(fake_part(input), rspamd_config))
  end)

  -- The boundary must not reject the legitimate ways a token can end
  test("detects a parameterless Content-Type", function()
    local input = "From: <Saved by Browser>\r\nMIME-Version: 1.0\r\n"
        .. "Content-Type: multipart/related\r\n\r\n"
        .. "--B\r\nContent-Type: text/html\r\n\r\n<html>hi</html>\r\n--B--\r\n"
    assert_equal(lua_magic.detect(fake_part(input), rspamd_config), 'mht')
  end)

  test("detects a parameterless Content-Type before MIME-Version, LF-only", function()
    local input = "From: <Saved by Browser>\nContent-Type: multipart/related\nMIME-Version: 1.0\n\n"
        .. "--B\nContent-Type: text/html\n\n<html>hi</html>\n--B--\n"
    assert_equal(lua_magic.detect(fake_part(input), rspamd_config), 'mht')
  end)

  test("detects whitespace before the parameter separator", function()
    local input = "From: <Saved by Browser>\r\nMIME-Version: 1.0\r\n"
        .. "Content-Type: multipart/related ; boundary=\"B\"\r\n\r\n"
        .. "--B\r\nContent-Type: text/html\r\n\r\n<html>hi</html>\r\n--B--\r\n"
    assert_equal(lua_magic.detect(fake_part(input), rspamd_config), 'mht')
  end)

  test("detects a MIME-Version carrying a trailing comment", function()
    local input = "From: <Saved by Browser>\r\nMIME-Version: 1.0 (Generated by Foo 1.2)\r\n"
        .. "Content-Type: multipart/related; boundary=\"B\"\r\n\r\n"
        .. "--B\r\nContent-Type: text/html\r\n\r\n<html>hi</html>\r\n--B--\r\n"
    assert_equal(lua_magic.detect(fake_part(input), rspamd_config), 'mht')
  end)
end)
