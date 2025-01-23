
local reconf = config['regexp']

reconf['HAS_GUC_PROXY_URI'] = {
  re = '/\\.googleusercontent\\.com\\/proxy/{url}i',
  description = 'Has googleusercontent.com proxy URL',
  score = 1.0,
  group = 'url'
}

reconf['HAS_GOOGLE_REDIR'] = {
  re = '/[\\.\\/]google\\.([a-z]{2,3}(|\\.[a-z]{2,3})|info|jobs)\\/(amp\\/s\\/|url\\?)/{url}i',
  description = 'Has google.com/url or alike Google redirection URL',
  score = 1.0,
  group = 'url'
}

reconf['HAS_GOOGLE_FIREBASE_URL'] = {
  re = '/\\.firebasestorage\\.googleapis\\.com\\//{url}i',
  description = 'Contains firebasestorage.googleapis.com URL',
  score = 2.0,
  group = 'url'
}

reconf['HAS_FILE_URL'] = {
  re = '/^file:\\/\\//{url}i',
  description = 'Contains file:// URL',
  score = 2.0,
  group = 'url'
}

