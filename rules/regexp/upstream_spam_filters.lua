--[[
Copyright (c) 2011-2016, Vsevolod Stakhov <vsevolod@highsecure.ru>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
]]--

-- Rules for upstream services that have already run spam checks

local reconf = config['regexp']

reconf['PRECEDENCE_BULK'] = {
  re = 'Precedence=/bulk/Hi',
  score = 0.0,
  description = "Message marked as bulk",
  group = 'upstream_spam_filters'
}

reconf['MICROSOFT_SPAM'] = {
  -- https://technet.microsoft.com/en-us/library/dn205071(v=exchg.150).aspx
  re = 'X-Forefront-Antispam-Report=/SFV:SPM/H',
  score = 4.0,
  description = "Microsoft says the message is spam",
  group = 'upstream_spam_filters'
}

reconf['KLMS_SPAM'] = {
  re = 'X-KLMS-AntiSpam-Status=/^spam/H',
  score = 5.0,
  description = "Kaspersky Security for Mail Server says this message is spam",
  group = 'upstream_spam_filters'
}

reconf['SPAM_FLAG'] = {
  re = string.format('%s || %s || %s',
      'X-Spam-Flag=/^(?:yes|true)/Hi',
      'X-Spam=/^(?:yes|true)/Hi',
      'X-Spam-Status=/^(?:yes|true)/Hi'),
  score = 5.0,
  description = "Message was already marked as spam",
  group = 'upstream_spam_filters'
}

reconf['UNITEDINTERNET_SPAM'] = {
  re = string.format('%s || %s',
       'X-UI-Filterresults=/^junk:/H',
       'X-UI-Out-Filterresults=/^junk:/H'),
  score = 5.0,
  description = "United Internet says this message is spam",
  group = 'upstream_spam_filters'
}
