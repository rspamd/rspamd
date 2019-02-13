multi_hdrs = {
  ['Message-ID'] = '<a44q4StVFY04V4_4gOMYXjTgMDvmlSFzZxnoyJPHFwM@cacophony.za.org>',
  ['From'] = 'Rspamd <foo@cacophony.za.org>',
  ['To'] = 'nerf@example.org',
  ['Subject'] = 'dkim test message',
  ['User-Agent'] = 'Vi IMproved 8.1',
  ['Content-Type'] = 'text/plain; charset=utf-8;',
  ['MIME-Version'] = '1.0',
  ['Date'] = 'Sat, 02 Feb 2019 10:34:54 +0000',
}

single_hdr = {
  ['Message-ID'] = '<a44q4StVFY04V4_4gOMYXjTgMDvmlSFzZxnoyJPHFwM@cacophony.za.org>',
  ['From'] = 'Rspamd <foo@invalid.za.org>',
  ['To'] = 'nerf@example.org',
  ['Subject'] = 'dkim test message',
  ['User-Agent'] = 'Vi IMproved 8.1',
  ['Content-Type'] = 'text/plain; charset=utf-8;',
  ['MIME-Version'] = '1.0',
  ['Date'] = 'Sat, 02 Feb 2019 10:34:54 +0000',
}

innocuous_msg = 'hello'
