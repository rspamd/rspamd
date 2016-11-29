local reconf = config['regexp']
local rspamd_regexp = require 'rspamd_regexp'
local util = require 'rspamd_util'

reconf['HAS_PHPMAILER_SIG'] = {
  re = "X-Mailer=/^PHPMailer/Hi || Content-Type=/boundary=\"b[123]_/Hi",
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
  group = "compromised_hosts"
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
  group = "compromised_hosts"
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
  re = "X-PHP-Script=/eval\\(\\)\\'d/Hi || X-PHP-Originating-Script=/eval\\(\\)\\'d/Hi",
  description = "Message sent using eval'd PHP",
  score = 4.0,
  group = "compromised_hosts"
}

reconf['HAS_WP_URI'] = {
  re = '/\\/wp-[^\\/]+\\//Ui',
  description = "Contains WordPress URIs",
  group = "compromised_hosts"
}

reconf['WP_COMPROMISED'] = {
  re = '/\\/wp-(?:content|includes)[^\\/]+\\//Ui',
  description = "URL that is pointing to a compromised WordPress installation",
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

reconf['URI_HIDDEN_PATH'] = {
  re = "/\\/\\..+/U",
  description = "URL contains a UNIX hidden file/directory",
  score = 1.0,
  group = "compromised_hosts"
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
      local s = util.parse_mail_address(sender)
      if (s and s[1]) then
        if (re:match(s[1].addr)) then return true end
      end
    end
    -- Reply-To
    local replyto = task:get_header('Reply-To')
    if replyto then
      local rt = util.parse_mail_address(replyto)
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

