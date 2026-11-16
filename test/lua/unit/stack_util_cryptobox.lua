context("Lua stack discipline: cryptobox hash update", function()
  local hash = require "rspamd_cryptobox_hash"
  local rspamd_text = require "rspamd_text"

  local function hash_value(value)
    local h = hash.create()
    h:update(value)
    return h:hex()
  end

  test("text userdata hashes like the equivalent string", function()
    assert_equal(hash_value(rspamd_text.fromstring("payload")), hash_value("payload"))
  end)

  test("text userdata nested in a table hashes like the equivalent string", function()
    assert_equal(hash_value({ rspamd_text.fromstring("payload") }), hash_value({ "payload" }))
    assert_equal(hash_value({ key = rspamd_text.fromstring("payload") }),
        hash_value({ key = "payload" }))
  end)

  test("different texts nested in a table hash differently", function()
    assert_not_equal(hash_value({ rspamd_text.fromstring("a") }),
        hash_value({ rspamd_text.fromstring("b") }))
  end)

  test("nested table array part is hashed fully", function()
    assert_equal(hash_value({ { "a", "b", "c" } }), hash_value({ { "a", "b", "c" } }))
    assert_not_equal(hash_value({ { "a", "b", "c" } }), hash_value({ { "a", "b", "d" } }))
    assert_not_equal(hash_value({ { "a", "b", "c" } }), hash_value({ { "a", "b" } }))
  end)
end)
