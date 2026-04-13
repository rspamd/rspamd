local lua_stat = require 'lua_stat'
local filename_to_tokens = lua_stat._filename_to_tokens

context("lua_stat - filename_to_tokens", function()
  local cases = {
    {
      name = 'ASCII filename: numeric parts discarded',
      input = {'invoice_2024-03-15.pdf', '#f:', '#fe:', '#fp:'},
      result = {'#f:invoice_2024-03-15.pdf', '#fe:pdf', '#fp:invoice'},
    },
    {
      name = 'letter+digit boundary split',
      input = {'temp3617331711606037072.pdf', '#f:', '#fe:', '#fp:'},
      result = {'#f:temp3617331711606037072.pdf', '#fe:pdf', '#fp:temp'},
    },
    {
      name = 'CamelCase split',
      input = {'InvoiceReport.docx', '#f:', '#fe:', '#fp:'},
      result = {'#f:InvoiceReport.docx', '#fe:docx', '#fp:invoice', '#fp:report'},
    },
    {
      name = 'double extension: legitimate compound format',
      input = {'archive.tar.gz', '#f:', '#fe:', '#fp:'},
      result = {'#f:archive.tar.gz', '#fe:gz', '#fe:tar.gz', '#fp:archive', '#fp:tar'},
    },
    {
      name = 'double extension: malware disguise pattern',
      input = {'document.pdf.exe', '#f:', '#fe:', '#fp:'},
      result = {'#f:document.pdf.exe', '#fe:exe', '#fe:pdf.exe', '#fp:document', '#fp:pdf'},
    },
    {
      name = 'Cyrillic + CamelCase + single-char part discarded',
      input = {'Заполнение CodeStock в диадок.docx', '#f:', '#fe:', '#fp:'},
      result = {
        '#f:Заполнение CodeStock в диадок.docx',
        '#fe:docx',
        '#fp:заполнение',
        '#fp:code',
        '#fp:stock',
        '#fp:диадок',
      },
    },
    {
      name = 'Cyrillic + digit suffix split',
      input = {'апр26.pdf', '#f:', '#fe:', '#fp:'},
      result = {'#f:апр26.pdf', '#fe:pdf', '#fp:апр'},
    },
    {
      name = 'no extension',
      input = {'Makefile', '#f:', '#fe:', '#fp:'},
      result = {'#f:Makefile', '#fp:makefile'},
    },
    {
      name = 'single-char base part discarded',
      input = {'a.pdf', '#f:', '#fe:', '#fp:'},
      result = {'#f:a.pdf', '#fe:pdf'},
    },
    {
      name = 'numeric base parts discarded',
      input = {'DHL_Tracking_8473921.pdf', '#f:', '#fe:', '#fp:'},
      result = {'#f:DHL_Tracking_8473921.pdf', '#fe:pdf', '#fp:dhl', '#fp:tracking'},
    },
    {
      name = 'dot-prefixed filename (no extension extracted)',
      input = {'.gitignore', '#f:', '#fe:', '#fp:'},
      result = {'#f:.gitignore', '#fp:gitignore'},
    },
    {
      name = 'original token case-preserved',
      input = {'Invoice.PDF', '#f:', '#fe:', '#fp:'},
      result = {'#f:Invoice.PDF', '#fe:pdf', '#fp:invoice'},
    },
    {
      name = 'empty prefixes (image path, backward compatibility)',
      input = {'IMG_20260328_184333.jpg', '', '', ''},
      result = {'IMG_20260328_184333.jpg', 'jpg', 'img'},
    },
  }

  for _, c in ipairs(cases) do
    test(c.name, function()
      local tokens = filename_to_tokens(table.unpack(c.input))
      assert_equal(#c.result, #tokens,
          string.format('token count mismatch: expected %d, got %d: {%s}',
              #c.result, #tokens, table.concat(tokens, ', ')))
      for i, expected in ipairs(c.result) do
        assert_equal(expected, tokens[i])
      end
    end)
  end
end)
