-- Unit tests for lualib/plugins/metadata_exporter.lua (rule/part schema)

context("metadata_exporter rule schema", function()
  local schema = require "plugins/metadata_exporter"
  local T = require "lua_shape.core"

  test("minimal http rule is valid", function()
    local res, err = schema.rule_schema:transform({
      backend = "http",
      url = "http://example.com/push",
    })
    assert_not_nil(res, err and T.format_error(err))
  end)

  test("minimal send_mail rule is valid", function()
    local res, err = schema.rule_schema:transform({
      backend = "send_mail",
      smtp = "127.0.0.1",
      mail_to = "postmaster@example.com",
    })
    assert_not_nil(res, err and T.format_error(err))
  end)

  test("mail_to accepts a single string or an array", function()
    local res = schema.rule_schema:transform({
      backend = "send_mail",
      smtp = "127.0.0.1",
      mail_to = { "a@example.com", "b@example.com" },
    })
    assert_not_nil(res)
    assert_equal(#res.mail_to, 2)
  end)

  test("unknown rule key is rejected", function()
    local res, err = schema.rule_schema:transform({
      backend = "send_mail",
      smtp = "127.0.0.1",
      mail_to = "postmaster@example.com",
      -- typo: not a real option
      email_alert_recipient = true,
    })
    assert_nil(res)
    assert_not_nil(err)
  end)

  test("rule without a backend is rejected", function()
    local res, err = schema.rule_schema:transform({
      url = "http://example.com/push",
    })
    assert_nil(res)
    assert_not_nil(err)
  end)

  test("backend_required_elements lists smtp and mail_to for send_mail", function()
    local reqset = schema.backend_required_elements.send_mail
    local has_smtp, has_mail_to = false, false
    for _, e in ipairs(reqset) do
      if e == 'smtp' then has_smtp = true end
      if e == 'mail_to' then has_mail_to = true end
    end
    assert_true(has_smtp)
    assert_true(has_mail_to)
  end)
end)

context("metadata_exporter email_parts schema", function()
  local schema = require "plugins/metadata_exporter"
  local T = require "lua_shape.core"

  local function with_parts(parts)
    return schema.rule_schema:transform({
      backend = "send_mail",
      smtp = "127.0.0.1",
      mail_to = "postmaster@example.com",
      email_parts = parts,
    })
  end

  test("a lone part object is normalized into a one-element array", function()
    local res, err = with_parts({
      content = "hello",
      content_type = "text/plain",
    })
    assert_not_nil(res, err and T.format_error(err))
    assert_equal(#res.email_parts, 1)
    assert_equal(res.email_parts[1].content, "hello")
  end)

  test("an explicit array of parts is accepted", function()
    local res, err = with_parts({
      { content = "one", content_type = "text/plain" },
      { content_from_variables = "some_var", content_type = "application/octet-stream" },
    })
    assert_not_nil(res, err and T.format_error(err))
    assert_equal(#res.email_parts, 2)
  end)

  test("content accepts a single string or an array of strings", function()
    local res, err = with_parts({
      { content = { "line one", "line two" }, content_type = "text/plain" },
    })
    assert_not_nil(res, err and T.format_error(err))
    assert_equal(#res.email_parts[1].content, 2)
  end)

  test("content_from_variables accepts a single name or an array of names", function()
    local res, err = with_parts({
      { content_from_variables = { "var_a", "var_b" }, content_type = "application/octet-stream" },
    })
    assert_not_nil(res, err and T.format_error(err))
    assert_equal(#res.email_parts[1].content_from_variables, 2)
  end)

  -- An empty table is array-like, so it fails the min_items=1 array variant and
  -- would otherwise fall through to the lone-object variant (every part field
  -- is optional) and be normalized into an array holding one empty part
  test("an empty email_parts value is rejected", function()
    local res, err = with_parts({})
    assert_nil(res)
    assert_not_nil(err)
  end)

  test("an unknown key inside a part is rejected", function()
    local res, err = with_parts({
      { content = "hello", content_type = "text/plain", oops = true },
    })
    assert_nil(res)
    assert_not_nil(err)
  end)

  test("a bad encoding value is rejected", function()
    local res, err = with_parts({
      { content = "hello", content_type = "text/plain", encoding = "uuencode" },
    })
    assert_nil(res)
    assert_not_nil(err)
  end)

  -- Reproduces the UCL duplicate-key-merge symptom: two `email_parts { ... }`
  -- blocks under a `duplicate=merge` include collapse into ONE object whose
  -- scalar fields become arrays (e.g. content_type = {"text/plain", "application/zip"}).
  -- content_type/filename/disposition must stay string-only so this is still
  -- caught here rather than silently accepted now that content/
  -- content_from_variables legitimately accept arrays.
  test("a merged-duplicate email_parts block (array-valued content_type) is rejected", function()
    local res, err = with_parts({
      content_from_variables = { "a", "b" },
      content_type = { "text/plain", "application/zip" },
    })
    assert_nil(res)
    assert_not_nil(err)
  end)
end)
