-- Test one simple interaction

conn = mt.connect("inet:" .. port .. "@" .. host)
if conn == nil then
  error "mt.connect() failed"
end
if mt.conninfo(conn, "localhost", "127.0.0.1") then
  error "mt.conninfo() failed"
end
if mt.getreply(conn) ~= SMFIR_CONTINUE then
  error "mt.conninfo() unexpected reply"
end

if mt.helo(conn, "it.is.i") then
  error "mt.helo() failed"
end
if mt.getreply(conn) ~= SMFIR_CONTINUE then
  error "mt.helo() unexpected reply"
end
mt.macro(conn, SMFIC_MAIL, "i", "test-id")
if mt.mailfrom(conn, "sender@example.com") then
  error "mt.mailfrom() failed"
end
if mt.getreply(conn) ~= SMFIR_CONTINUE then
  error "mt.mailfrom() unexpected reply"
end
mt.rcptto(conn, "rcpt@example.com")

if mt.header(conn, "From", "honest@sender") then
  error "mt.header(From) failed"
end

if mt.getreply(conn) ~= SMFIR_CONTINUE then
  error "mt.header(From) unexpected reply"
end

if mt.eoh(conn) then
  error "mt.eoh() failed"
end

if mt.getreply(conn) ~= SMFIR_CONTINUE then
  error "mt.eoh() unexpected reply"
end

if mt.bodystring(conn, "This is a simple test!\r\n") then
  error "mt.bodystring() failed"
end
if mt.getreply(conn) ~= SMFIR_CONTINUE then
  error "mt.bodystring() unexpected reply"
end

if mt.eom(conn) then
  error "mt.eom() failed"
end
if mt.getreply(conn) ~= SMFIR_ACCEPT then
  error "mt.eom() unexpected reply"
end

mt.disconnect(conn)
