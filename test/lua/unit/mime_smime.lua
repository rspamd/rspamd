--[[
Opaque signed S/MIME content is parsed like any other MIME entity.

The content of an application/pkcs7-mime signed-data part lives in a buffer of
its own, but a multipart inside it used to look for its boundaries among those
of the outer message, so none of its parts were parsed or scanned for URLs.

The fixture signs this entity with a throwaway self-signed key:

  Content-Type: multipart/mixed; boundary="inner"

  --inner
  Content-Type: text/plain

  see http://smime-inner.example.org/ now
  --inner
  Content-Type: text/html

  <a href="http://smime-html.example.org/">x</a>
  --inner--
]]

context("S/MIME content", function()
  local rspamd_task = require "rspamd_task"

  local signed = {
    "MIIEFgYJKoZIhvcNAQcCoIIEBzCCBAMCAQExDzANBglghkgBZQMEAgEFADCB8QYJKoZIhvcNAQcB",
    "oIHjBIHgQ29udGVudC1UeXBlOiBtdWx0aXBhcnQvbWl4ZWQ7IGJvdW5kYXJ5PSJpbm5lciINCg0K",
    "LS1pbm5lcg0KQ29udGVudC1UeXBlOiB0ZXh0L3BsYWluDQoNCnNlZSBodHRwOi8vc21pbWUtaW5u",
    "ZXIuZXhhbXBsZS5vcmcvIG5vdw0KLS1pbm5lcg0KQ29udGVudC1UeXBlOiB0ZXh0L2h0bWwNCg0K",
    "PGEgaHJlZj0iaHR0cDovL3NtaW1lLWh0bWwuZXhhbXBsZS5vcmcvIj54PC9hPg0KLS1pbm5lci0t",
    "DQqgggF4MIIBdDCCARmgAwIBAgIUbk0+SgG4EQnkJDOF1cbozFoHqbcwCgYIKoZIzj0EAwIwDzEN",
    "MAsGA1UEAwwEdGVzdDAeFw0yNjExMDQxNTMzNTZaFw0zNjExMDExNTMzNTZaMA8xDTALBgNVBAMM",
    "BHRlc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAR5QzVv6vfsaPJpB/8JBk3yy/ld6LAZuCZA",
    "r81KJy3nArjNosWtR4O2EGWDCjpioHKEzMOpXrEvxBp4g7E/FJEEo1MwUTAdBgNVHQ4EFgQU/umK",
    "QN/m5crGTeBuexjZy1rxiU4wHwYDVR0jBBgwFoAU/umKQN/m5crGTeBuexjZy1rxiU4wDwYDVR0T",
    "AQH/BAUwAwEB/zAKBggqhkjOPQQDAgNJADBGAiEAonFGdLKhjTqB/5ufmQxyZ8FcrRNrNO4vSnMR",
    "noyPWsICIQDsPPWM4qv079MuZbGHTJ7WOefGr4Bc36KoWVPRzSiFzTGCAXswggF3AgEBMCcwDzEN",
    "MAsGA1UEAwwEdGVzdAIUbk0+SgG4EQnkJDOF1cbozFoHqbcwDQYJYIZIAWUDBAIBBQCggeQwGAYJ",
    "KoZIhvcNAQkDMQsGCSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMjYxMTA0MTUzMzU2WjAvBgkq",
    "hkiG9w0BCQQxIgQg88e/UJ8bNKpWuePYp5ffzdIM3HGC/sEl8AxvbUjNnQoweQYJKoZIhvcNAQkP",
    "MWwwajALBglghkgBZQMEASowCwYJYIZIAWUDBAEWMAsGCWCGSAFlAwQBAjAKBggqhkiG9w0DBzAO",
    "BggqhkiG9w0DAgICAIAwDQYIKoZIhvcNAwICAUAwBwYFKw4DAgcwDQYIKoZIhvcNAwICASgwCgYI",
    "KoZIzj0EAwIERzBFAiBOjwpMS6DeuceUjAkfR+2E5JwLaD6O2ZvjeZTxR1dbCwIhAP0Kvhdf/Hos",
    "GoHKTLOhHnThTSuz87QPYvANUyYL08xU",
  }

  test("parts of a multipart inside opaque signed data are parsed", function()
    local msg = table.concat({
      "From: sender@example.com",
      "To: rcpt@example.com",
      "Subject: signed",
      "MIME-Version: 1.0",
      "Content-Type: application/pkcs7-mime; smime-type=signed-data; name=\"smime.p7m\"",
      "Content-Transfer-Encoding: base64",
      "Content-Disposition: attachment; filename=\"smime.p7m\"",
      "",
      table.concat(signed, "\r\n"),
      "",
    }, "\r\n")

    local res, task = rspamd_task.load_from_string(msg, rspamd_config)
    assert_true(res, "failed to load message")
    task:process_message()

    local hosts = {}
    for _, u in ipairs(task:get_urls() or {}) do
      hosts[u:get_host()] = true
    end
    local texts = 0
    for _, p in ipairs(task:get_parts() or {}) do
      if p:is_text() then
        texts = texts + 1
      end
    end
    task:destroy()

    assert_equal(2, texts, "text parts of the signed multipart")
    assert_true(hosts["smime-inner.example.org"], "url of the text part is missing")
    assert_true(hosts["smime-html.example.org"], "url of the html part is missing")
  end)
end)
