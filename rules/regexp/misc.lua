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


local reconf = config['regexp']

reconf['HTML_META_REFRESH_URL'] = {
  -- Requires options { check_attachements = true; }
  re = '/<meta\\s+http-equiv="refresh"\\s+content="\\d+\\s*;\\s*url=/{sa_raw_body}i',
  description = "Has HTML Meta refresh URL",
  score = 5.0,
  group = 'HTML'
}

reconf['HAS_DATA_URI'] = {
  -- Requires options { check_attachements = true; }
  re = '/data:[^\\/]+\\/[^; ]+;base64,/{sa_raw_body}i',
  description = "Has Data URI encoding",
  group = 'HTML'
}

reconf['DATA_URI_OBFU'] = {
  -- Requires options { check_attachements = true; }
  re = '/data:text\\/(?:plain|html);base64,/{sa_raw_body}i',
  description = "Uses Data URI encoding to obfuscate plain or HTML in base64",
  group = 'HTML',
  score = 2.0
}

reconf['INTRODUCTION'] = {
  re = '/\\b(?:my name is\\b|(?:i am|this is)\\s+(?:mr|mrs|ms|miss|master|sir|prof(?:essor)?|d(?:octo)?r|rev(?:erend)?)(?:\\.|\\b))/{sa_body}i',
  description = "Sender introduces themselves",
  score = 2.0,
  group = 'scams'
}

