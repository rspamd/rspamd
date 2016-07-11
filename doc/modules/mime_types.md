---
layout: doc_modules
title: Mime types modules
---
# Rspamd mime types module

This module is intended to do some mime types sanity checks. That includes the following:

1. Checks whether mime type is from the `good` list (e.g. `multipart/alternative` or `text/html`)
2. Checks if a mime type is from the `bad` list (e.g. `multipart/form-data`)
3. Checks if an attachement filename extension is different from the intended mime type

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
