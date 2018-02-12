innocuous_hdrs = {
  ['Message-ID'] = '<20180202155326.Horde.GfEWpxCo_Dip2xJswIpQNgK@example.org>',
  ['From'] = 'Andrew Lewis <nerf@example.org>',
  ['To'] = 'nerf@example.org',
  ['Subject'] = 'innocuous test message',
  ['User-Agent'] = 'Horde Application Framework 5',
  ['Content-Type'] = 'text/plain; charset=utf-8; format=flowed; DelSp=Yes',
  ['MIME-Version'] = '1.0',
  ['Content-Disposition'] = 'inline',
  ['Date'] = 'Fri, 02 Feb 2018 15:53:26 +0200',
}

default_hdrs = {
  ['Subject'] = 'spam message',
}

innocuous_msg = 'Hello Rupert'

gtube = [[lo

XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X

thx]]

gtube_add_header = string.gsub(gtube, "XJS", "YJS")
gtube_rw_subject = string.gsub(gtube, "XJS", "ZJS")
