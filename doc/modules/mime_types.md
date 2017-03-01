---
layout: doc_modules
title: Mime types modules
---

# Rspamd mime types module

This module is intended to do some mime types sanity checks. That includes the following:

1. Checks whether mime type is from the `good` list (e.g. `multipart/alternative` or `text/html`)
2. Checks if a mime type is from the `bad` list (e.g. `multipart/form-data`)
3. Checks if an attachement filename extension is different from the intended mime type
4. Checks for archives content (rar and zip are supported) and find certain bad files inside
5. Checks for some other bad patterns commonly used by spammers, e.g. extensions hiding (e.g. `.pdf.exe`)

## Configuration

`mime_types` module reads mime types map specified in `file` option. This map contains binding

```
type/subtype score
```

When score is more than `0` then it is considered as `bad` if it is less than `0` it is considered as `good` (with the corresponding multiplier).
When mime type is not listed then `MIME_UNKNOWN` symbol is inserted.

`extension_map` option allows to specify map from a known extension to a specific mime type:

~~~ucl
extension_map = {
  html = "text/html";
  txt = "text/plain";
  pdf = "application/pdf";
}
~~~

When an attachement extension matches left part but the content type does not match the right part then symbol `MIME_BAD_ATTACHMENT` is inserted.

### Archives support

Since 1.3, this module supports archives processing (rar and zip formats) and can check files inside archives. There are additional options added for more precise archives checks, for example, a special symbol for nested archives. Here is the default configuration of mime_types with comments:

~~~ucl
extension_map = { 
  html = 'text/html',
  txt = 'text/plain',
  pdf = 'application/pdf'
};

# Extensions that are treated as 'bad'
# Number is score multiply factor
bad_extensions = {
  scr = 4,
  lnk = 4,
  exe = 1,
  jar = 2,
  com = 2,
  bat = 2,
  ace = 4,
  arj = 4,
  cab = 3,
};

# Extensions that are particularly penalized for archives
bad_archive_extensions = {
  pptx = 0.1,
  docx = 0.1,
  xlsx = 0.1,
  pdf = 0.1,
  jar = 3,
  js = 0.5,
  vbs = 4,
};

# Used to detect another archive in archive
archive_extensions = {
  zip = 1,
  arj = 1,
  rar = 1,
  ace = 1,
  7z = 1,
  cab = 1,
};
~~~