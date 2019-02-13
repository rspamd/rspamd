function setup(c_ip, helo, hn)
  if not c_ip then c_ip = "127.0.0.1" end
  if not helo then helo = "it.is.i" end
  if not hn then hn = "localhost" end
  conn = mt.connect("inet:" .. port .. "@" .. host)
  if conn == nil then
    error "mt.connect() failed"
  end
  if mt.conninfo(conn, hn, c_ip) then
    error "mt.conninfo() failed"
  end
  if mt.getreply(conn) ~= SMFIR_CONTINUE then
    error "mt.conninfo() unexpected reply"
  end
  if mt.helo(conn, helo) then
    error "mt.helo() failed"
  end
  if mt.getreply(conn) ~= SMFIR_CONTINUE then
    error "mt.helo() unexpected reply"
  end
end

function teardown()
  if conn then
    mt.disconnect(conn)
  end
  conn = nil
end

function send_message(body, hdrs, id, sender, rcpts)
  mt.macro(conn, SMFIC_MAIL, "i", id or "test-id")
  if mt.mailfrom(conn, sender or "sender@example.com") then
    error "mt.mailfrom() failed"
  end
  if mt.getreply(conn) ~= SMFIR_CONTINUE then
    error "mt.mailfrom() unexpected reply"
  end
  if not rcpts then
    rcpts = {"rcpt@example.com"}
  end
  for _, r in ipairs(rcpts) do
    mt.rcptto(conn, r)
  end
  if not hdrs then
    hdrs = default_hdrs
  end
  if not hdrs['From'] then
    hdrs['From'] = sender or "sender@example.com"
  end
  for k, v in pairs(hdrs) do
    if mt.header(conn, k, v) then
      error (string.format("mt.header(%s) failed", k))
    end
  end
  if mt.eoh(conn) then
    error "mt.eoh() failed"
  end
  if mt.getreply(conn) ~= SMFIR_CONTINUE then
    error "mt.eoh() unexpected reply"
  end
  if mt.bodystring(conn, body .. "\r\n") then
    error "mt.bodystring() failed"
  end
  if mt.getreply(conn) ~= SMFIR_CONTINUE then
    error "mt.bodystring() unexpected reply"
  end
  if mt.eom(conn) then
    error "mt.eom() failed"
  end
end

function check_accept()
  local rc = mt.getreply(conn)
  if rc ~= SMFIR_ACCEPT then
    error (string.format("mt.eom() unexpected reply: %s", rc))
  end
end

function check_gtube(code, ecode, msg)
  if not mt.eom_check(conn, MT_SMTPREPLY, code or '554', ecode or '5.7.1', msg or 'Gtube pattern') then
    error "mt.eom_check() failed"
  end
  local rc = mt.getreply(conn)
  if rc ~= SMFIR_REPLYCODE then
    error (string.format("mt.eom() unexpected reply: %s", rc))
  end
end

function check_defer(code, ecode, msg)
  if not mt.eom_check(conn, MT_SMTPREPLY, code or '451', ecode or '4.7.1', msg or 'Try much later') then
    error "mt.eom_check() failed"
  end
  local rc = mt.getreply(conn)
  if rc ~= SMFIR_REPLYCODE then
    error (string.format("mt.eom() unexpected reply: %s", rc))
  end
end

function check_subject_rw(subj, tmpl)
  if not subj then
    subj = default_hdrs['Subject']
  end
  if not tmpl then
    tmpl = "*** SPAM *** %s"
  end
  local new_subj = string.format(tmpl, subj)
  if not mt.eom_check(conn, MT_HDRCHANGE, "Subject", new_subj) then
    error "subject not rewritten"
  end
end

function check_headers(count)
  for i=0, count-1 do
    local hdr = mt.getheader(conn, "DKIM-Signature", i)
    if not hdr then
      error (string.format("Signature %s not added", i))
    end
  end
end
