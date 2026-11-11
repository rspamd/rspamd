-- Checks how the milter session reassembles headers on the way in.
--
-- The MTA hands us header names and values separately, so rspamd has to put
-- the `: ` back itself. Issue #6194: a header that is folded right after the
-- colon (`Message-ID:\r\n <id>`) has no space to restore, and inserting one
-- anyway breaks `simple` DKIM canonicalisation.
--
-- The expected reconstructions below are matched against the raw message and
-- reported back over SMTP so that miltertest can assert on them.

local expected = {
  -- SMFIP_HDR_LEADSPC not negotiated: the MTA ate one space after the colon,
  -- but there was none to eat here
  {'X-Fold-Test:\r\n <fold@example.org>\r\n', 'fold preserved'},
  -- SMFIP_HDR_LEADSPC negotiated: the value arrives verbatim, so we must not
  -- add a second space
  {'X-Fold-Test: <leadspc@example.org>\r\n', 'leadspc preserved'},
}

rspamd_config:register_symbol({
  name = 'MILTER_FOLD_CHECK',
  type = 'postfilter',
  priority = 10,
  callback = function(task)
    local content = task:get_content()

    if not content then
      return
    end

    content = tostring(content)

    if not content:find('X-Fold-Test:', 1, true) then
      return
    end

    for _, e in ipairs(expected) do
      if content:find(e[1], 1, true) then
        task:set_pre_result('reject', e[2])
        return
      end
    end

    task:set_pre_result('reject', 'fold mangled')
  end
})
