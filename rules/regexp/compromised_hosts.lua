local reconf = config['regexp']
local rspamd_regexp = require 'rspamd_regexp'
local util = require 'rspamd_util'

reconf['HAS_PHPMAILER_SIG'] = {
  -- PHPMailer 6.0.0 and older used hex hash in boundary:
  -- boundary="b1_2a45d5e29f78d3408e318878b049f474"
  -- Since 6.0.1 it uses base64 (without =+/):
  -- boundary="b1_uBN0UPD3n6RU04VPxI54tENiDgaCGoh15l9s73oFnlM"
  -- boundary="b1_Ez5tmpb4bSqknyUZ1B1hIvLAfR1MlspDEKGioCOXc"
  -- https://github.com/PHPMailer/PHPMailer/blob/v6.4.0/src/PHPMailer.php#L2660
  re = [[X-Mailer=/^PHPMailer /H || Content-Type=/boundary="b1_[0-9a-zA-Z]+"/H]],
  description = "PHPMailer signature",
  group = "compromised_hosts"
}

reconf['PHP_SCRIPT_ROOT'] = {
  re = "X-PHP-Originating-Script=/^0:/Hi",
  description = "PHP Script executed by root UID",
  score = 1.0,
  group = "compromised_hosts"
}

reconf['HAS_X_POS'] = {
  re = "header_exists('X-PHP-Originating-Script')",
  description = "Has X-PHP-Originating-Script header",
  group = "compromised_hosts"
}

reconf['HAS_X_PHP_SCRIPT'] = {
  re = "header_exists('X-PHP-Script')",
  description = "Has X-PHP-Script header",
  group = "compromised_hosts"
}

-- X-Source:
-- X-Source-Args: /usr/sbin/proxyexec -q -d -s /var/run/proxyexec/cagefs.sock/socket /bin/cagefs.server
-- X-Source-Dir: silvianimberg.com:/public_html/wp-content/themes/ultimatum
reconf['HAS_X_SOURCE'] = {
  re = "header_exists('X-Source') || header_exists('X-Source-Args') || header_exists('X-Source-Dir')",
  description = "Has X-Source headers",
  group = "compromised_hosts"
}

-- X-Authenticated-Sender: accord.host-care.com: sales@cortaflex.si
rspamd_config.HAS_X_AS = {
  callback = function (task)
    local xas = task:get_header('X-Authenticated-Sender')
    if not xas then return false end
    local _,_,auth = xas:find('[^:]+:%s(.+)$')
    if auth then
      -- TODO: see if we can parse an e-mail address from auth
      --       and see if it matches the from address or not
      return true, auth
    else
      return true
    end
  end,
  description = 'Has X-Authenticated-Sender header',
  group = "compromised_hosts",
  score = 0.0
}

-- X-Get-Message-Sender-Via: accord.host-care.com: authenticated_id: sales@cortaflex.si
rspamd_config.HAS_X_GMSV = {
  callback = function (task)
    local xgmsv = task:get_header('X-Get-Message-Sender-Via')
    if not xgmsv then return false end
    local _,_,auth = xgmsv:find('authenticated_id: (.+)$')
    if auth then
      -- TODO: see if we can parse an e-mail address from auth
      --       and see if it matches the from address or not.
      return true, auth
    else
      return true
    end
  end,
  description = 'Has X-Get-Message-Sender-Via: header',
  group = "compromised_hosts",
  score = 0.0,
}

-- X-AntiAbuse: This header was added to track abuse, please include it with any abuse report
-- X-AntiAbuse: Primary Hostname - accord.host-care.com
-- X-AntiAbuse: Original Domain - swaney.com
-- X-AntiAbuse: Originator/Caller UID/GID - [47 12] / [47 12]
-- X-AntiAbuse: Sender Address Domain - dropbox.com
reconf['HAS_X_ANTIABUSE'] = {
  re = "header_exists('X-AntiAbuse')",
  description = "Has X-AntiAbuse headers",
  group = "compromised_hosts"
}

reconf['X_PHP_EVAL'] = {
  re = [[X-PHP-Script=/eval\(\)'d code/H || X-PHP-Originating-Script=/eval\(\)'d code/H]],
  description = "Message sent using eval'd PHP",
  score = 4.0,
  group = "compromised_hosts"
}

reconf['HAS_WP_URI'] = {
  re = '/\\/wp-[^\\/]+\\//Ui',
  description = "Contains WordPress URIs",
  one_shot = true,
  group = "compromised_hosts"
}

reconf['WP_COMPROMISED'] = {
  re = '/\\/wp-(?:content|includes)[^\\/]+\\//Ui',
  description = "URL that is pointing to a compromised WordPress installation",
  one_shot = true,
  group = "compromised_hosts"
}

reconf['PHP_XPS_PATTERN'] = {
  re = 'X-PHP-Script=/^[^\\. ]+\\.[^\\.\\/ ]+\\/sendmail\\.php\\b/Hi',
  description = "Message contains X-PHP-Script pattern",
  group = "compromised_hosts"
}

reconf['HAS_XAW'] = {
  re = "header_exists('X-Authentication-Warning')",
  description = "Has X-Authentication-Warning header",
  group = "compromised_hosts"
}

-- X-Authentication-Warning: localhost.localdomain: www-data set sender to info@globalstock.lv using -f
reconf['XAW_SERVICE_ACCT'] = {
  re = "X-Authentication-Warning=/\\b(?:www-data|anonymous|ftp|apache|nobody|guest|nginx|web|www) set sender to\\b/Hi",
  description = "Message originally from a service account",
  score = 1.0,
  group = "compromised_hosts"
}

reconf['ENVFROM_SERVICE_ACCT'] = {
  re = "check_smtp_data('from',/^(?:www-data|anonymous|ftp|apache|nobody|guest|nginx|web|www)@/i)",
  description = "Envelope from is a service account",
  score = 1.0,
  group = "compromised_hosts"
}

reconf['HIDDEN_SOURCE_OBJ'] = {
  re = "X-PHP-Script=/\\/\\..+/Hi || X-PHP-Originating-Script=/(?:^\\d+:|\\/)\\..+/Hi || X-Source-Args=/\\/\\..+/Hi",
  description = "UNIX hidden file/directory in path",
  score = 2.0,
  group = "compromised_hosts"
}

local hidden_uri_re = rspamd_regexp.create_cached('/(?!\\/\\.well[-_]known\\/)(?:^\\.[A-Za-z0-9]|\\/'..
    '\\.[A-Za-z0-9]|\\/\\.\\.\\/)/i')
rspamd_config.URI_HIDDEN_PATH = {
  callback = function (task)
    local urls = task:get_urls(false)
    if (urls) then
        for _, url in ipairs(urls) do
            if (not (url:is_subject() and url:is_html_displayed())) then
                local path = url:get_path()
                if (hidden_uri_re:match(path)) then
                    -- TODO: need url:is_schemeless() to improve this
                    return true, 1.0, url:get_text()
                end
            end
        end
    end
  end,
  description = 'Message contains URI with a hidden path',
  score = 1.0,
  group = 'compromised_hosts',
}

reconf['MID_RHS_WWW'] = {
  re = "Message-Id=/@www\\./Hi",
  description = "Message-ID from www host",
  score = 0.5,
  group = "compromised_hosts"
}

rspamd_config.FROM_SERVICE_ACCT = {
  callback = function (task)
    local re = rspamd_regexp.create_cached('/^(?:www-data|anonymous|ftp|apache|nobody|guest|nginx|web|www)@/i');
    -- From
    local from = task:get_from(2)
    if (from and from[1]) then
      if (re:match(from[1].addr)) then return true end
    end
    -- Sender
    local sender = task:get_header('Sender')
    if sender then
      local s = util.parse_mail_address(sender, task:get_mempool())
      if (s and s[1]) then
        if (re:match(s[1].addr)) then return true end
      end
    end
    -- Reply-To
    local replyto = task:get_header('Reply-To')
    if replyto then
      local rt = util.parse_mail_address(replyto, task:get_mempool())
      if (rt and rt[1]) then
        if (re:match(rt[1].addr)) then return true end
      end
    end
  end,
  description = "Sender/From/Reply-To is a service account",
  score = 1.0,
  group = "compromised_hosts"
}

reconf['WWW_DOT_DOMAIN'] = {
  re = "From=/@www\\./Hi || Sender=/@www\\./Hi || Reply-To=/@www\\./Hi || check_smtp_data('from',/@www\\./i)",
  description = "From/Sender/Reply-To or Envelope is @www.domain.com",
  score = 0.5,
  group = "compromised_hosts"
}

