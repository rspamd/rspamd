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

context("metadata_exporter multipart/alternative layout planner", function()
  local schema = require "plugins/metadata_exporter"

  test("classify_text_kind recognizes inline text/plain and text/html", function()
    assert_equal(schema.classify_text_kind("text/plain; charset=utf-8", nil, nil), "plain")
    assert_equal(schema.classify_text_kind("text/html", nil, nil), "html")
    assert_equal(schema.classify_text_kind("TEXT/HTML", nil, nil), "html")
    assert_equal(schema.classify_text_kind("text/html", nil, "Inline"), "html")
  end)

  test("classify_text_kind treats an attached or filenamed text part as other", function()
    assert_equal(schema.classify_text_kind("text/plain", "report.txt", nil), "other")
    assert_equal(schema.classify_text_kind("text/plain", nil, "attachment"), "other")
    assert_equal(schema.classify_text_kind("text/html", nil, "ATTACHMENT"), "other")
    assert_equal(schema.classify_text_kind("application/zip", nil, nil), "other")
  end)

  -- The subtype must end where it ends: a prefix match alone would pull
  -- unrelated types such as text/plaintext into the alternative group
  test("classify_text_kind does not match a longer subtype sharing the prefix", function()
    assert_equal(schema.classify_text_kind("text/plaintext", nil, nil), "other")
    assert_equal(schema.classify_text_kind("text/htmlish", nil, nil), "other")
    assert_equal(schema.classify_text_kind("text/plain;charset=utf-8", nil, nil), "plain")
    assert_equal(schema.classify_text_kind("text/html", nil, nil), "html")
  end)

  test("plain + html with no other parts groups under a top-level alternative", function()
    local descriptors = {
      { kind = "plain", part = "P" },
      { kind = "html", part = "H" },
    }
    local subtype, tree = schema.plan_layout(descriptors, {})
    assert_equal(subtype, "alternative")
    assert_equal(#tree, 2)
    assert_equal(tree[1].part, "P")
    assert_equal(tree[2].part, "H")
  end)

  test("plain + html + attachment nests the alternative inside multipart/mixed", function()
    local descriptors = {
      { kind = "plain", part = "P" },
      { kind = "html", part = "H" },
      { kind = "other", part = "A" },
    }
    local subtype, tree = schema.plan_layout(descriptors, {})
    assert_equal(subtype, "mixed")
    assert_equal(#tree, 2)
    assert_not_nil(tree[1].alternative)
    assert_equal(tree[2].part, "A")
  end)

  test("html before plain is reordered so plain comes first inside the alternative", function()
    local descriptors = {
      { kind = "html", part = "H" },
      { kind = "plain", part = "P" },
    }
    local _, tree = schema.plan_layout(descriptors, {})
    assert_equal(tree[1].part, "P")
    assert_equal(tree[2].part, "H")
  end)

  test("attachment-only parts stay a flat multipart/mixed", function()
    local descriptors = {
      { kind = "other", part = "A" },
      { kind = "other", part = "B" },
    }
    local subtype, tree = schema.plan_layout(descriptors, {})
    assert_equal(subtype, "mixed")
    assert_equal(#tree, 2)
    assert_equal(tree[1].part, "A")
    assert_equal(tree[2].part, "B")
  end)

  test("auto_grouping = false keeps a flat layout even with plain + html", function()
    local descriptors = {
      { kind = "plain", part = "P" },
      { kind = "html", part = "H" },
    }
    local subtype, tree = schema.plan_layout(descriptors, { auto_grouping = false })
    assert_equal(subtype, "mixed")
    assert_equal(#tree, 2)
    assert_equal(tree[1].part, "P")
    assert_equal(tree[2].part, "H")
  end)

  test("an explicit email_parts_type wraps the alternative instead of collapsing it", function()
    local descriptors = {
      { kind = "plain", part = "P" },
      { kind = "html", part = "H" },
    }
    local subtype, tree = schema.plan_layout(descriptors, { email_parts_type = "related" })
    assert_equal(subtype, "related")
    assert_equal(#tree, 1)
    assert_not_nil(tree[1].alternative)
  end)

  test("two text/plain parts alongside one html part is rejected as ambiguous", function()
    local descriptors = {
      { kind = "plain", part = "P1" },
      { kind = "plain", part = "P2" },
      { kind = "html", part = "H" },
    }
    local subtype, err = schema.plan_layout(descriptors, {})
    assert_nil(subtype)
    assert_not_nil(err)
  end)

  test("two text/html parts alongside one plain part is rejected as ambiguous", function()
    local descriptors = {
      { kind = "plain", part = "P" },
      { kind = "html", part = "H1" },
      { kind = "html", part = "H2" },
    }
    local subtype, err = schema.plan_layout(descriptors, {})
    assert_nil(subtype)
    assert_not_nil(err)
  end)

  test("multiple plain parts with no html at all is not ambiguous", function()
    local descriptors = {
      { kind = "plain", part = "P1" },
      { kind = "plain", part = "P2" },
    }
    local subtype, tree = schema.plan_layout(descriptors, {})
    assert_equal(subtype, "mixed")
    assert_equal(#tree, 2)
  end)
end)
