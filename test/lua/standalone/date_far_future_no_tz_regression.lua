-- Regression tests for DATE_FAR_FUTURE_NO_TZ using the Rspamd SMTP date parser.
-- Run explicitly from the repository root with rspamadm lua; this is a
-- standalone test, NOT a telescope unit test auto-discovered by tests.lua.
-- No scanning, no configuration changes, and no Bayes learning are performed.
local source_path = os.getenv('RSPAMD_MISC_TEST_SOURCE') or 'rules/misc.lua'
local f, ferr = io.open(source_path, 'rb')
assert(f, 'Falha ao abrir ' .. source_path .. ': ' .. tostring(ferr))
local source = f:read('*a')
f:close()
local begin_marker = 'local function far_future_date_without_tz('
local end_marker = '\nend\n\n-- Date issues'
local first = assert(source:find(begin_marker, 1, true), 'Funcao esperada nao encontrada no misc.lua')
local last = assert(source:find(end_marker, first, true), 'Fim da funcao nao encontrado no misc.lua')
local snippet = source:sub(first, last + #('\nend') - 1)
local parser = require 'rspamd_parsers'
local chunk, loaderr = load(snippet .. '\nreturn far_future_date_without_tz', 'patched-misc-date-function', 't', {
  rspamd_parsers = parser, os = os, type = type, tonumber = tonumber, tostring = tostring,
  math = math, pairs = pairs,
})
assert(chunk, 'Sintaxe invalida na funcao extraida: ' .. tostring(loaderr))
local check = assert(chunk(), 'Nao foi possivel carregar a funcao extraida')
local function ts(s)
  local stamp, err = parser.parse_smtp_date(s)
  assert(type(stamp) == 'number', 'Timestamp invalido: ' .. s .. ' / ' .. tostring(err))
  return stamp
end
local received = ts('Mon, 02 Nov 2026 19:47:52 -0300')
local tests = {
  {'caso original futuro 10d', 'Thu, 12 Nov 2026 19:47:48', received, true},
  {'data valida no futuro com timezone', 'Thu, 12 Nov 2026 19:47:48 -0300', received, false},
  {'data proxima do recebimento', 'Mon, 02 Nov 2026 19:47:48', received, false},
  {'futuro de 1 dia', 'Tue, 03 Nov 2026 19:47:48', received, false},
  {'futuro distante sem weekday', '12 Nov 2026 19:47:48', received, true},
  {'weekday incorreto', 'Fri, 12 Nov 2026 19:47:48', received, false},
  {'dia invalido 31 fevereiro', 'Tue, 31 Feb 2027 19:47:48', received, false},
  {'dia invalido 31 abril', 'Sat, 31 Apr 2027 19:47:48', received, false},
  {'hora invalida', 'Thu, 12 Nov 2026 25:47:48', received, false},
  {'data sem hora', 'Thu, 12 Nov 2026', received, false},
  {'texto nao e Date', 'qualquer coisa', received, false},
  {'Date ausente', nil, received, false},
  {'sem connect timestamp', 'Thu, 12 Nov 2026 19:47:48', nil, false},
  {'data bissexta legitima futura', 'Sat, 29 Feb 2020 12:00:00', ts('Thu, 20 Feb 2020 12:00:00 +0000'), true},
  {'data 29 fev ano nao bissexto', 'Mon, 29 Feb 2027 12:00:00', ts('Sat, 20 Feb 2027 12:00:00 +0000'), false},
  {'seculo nao bissexto', 'Mon, 29 Feb 2100 12:00:00', ts('Sat, 20 Feb 2100 12:00:00 +0000'), false},
  {'limiar exato 48h garantidas', 'Thu, 12 Nov 2026 19:47:48', ts('Tue, 10 Nov 2026 05:47:48 +0000'), false},
  {'acima do limiar 48h garantidas', 'Thu, 12 Nov 2026 19:47:48', ts('Tue, 10 Nov 2026 05:47:47 +0000'), true},
}
local passed, failed = 0, 0
for _, case in ipairs(tests) do
  local name, date, connected, positive = case[1], case[2], case[3], case[4]
  local ok, val = pcall(check, date, connected)
  local actual = ok and val ~= nil
  if ok and actual == positive then
    passed = passed + 1
    print('PASS', name, val or '')
  else
    failed = failed + 1
    print('FAIL', name, 'expected=' .. tostring(positive), 'actual=' .. tostring(val))
  end
end
print('RESULTADO', 'PASS=' .. passed, 'FAIL=' .. failed)
os.exit(failed == 0 and 0 or 1)
