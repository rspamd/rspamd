# URL Suspect Optional Maps

This directory contains **optional** map files for the URL Suspect plugin.

**Important**: These maps are **disabled by default**. The plugin works perfectly without them using built-in logic.

## When to Use Maps

Use maps only if you need to:
- Whitelist specific domains to skip checks
- Add custom user field patterns beyond built-in checks
- Blacklist specific user names
- Define additional suspicious TLDs beyond the built-in list
- Mark specific IP ranges as suspicious
- Define unusual ports as suspicious

For most users, the built-in logic is sufficient.

## Available Maps

### 1. whitelist_domains.map
**Purpose**: Skip all URL suspect checks for trusted domains

**Format**: One domain per line
```
google.com
microsoft.com
github.com
```

**Enable in** `local.d/url_suspect.conf`:
```lua
url_suspect {
  use_whitelist = true;
  whitelist_map = "$LOCAL_CONFDIR/local.d/maps.d/url_suspect/whitelist_domains.map";
}
```

### 2. user_patterns.map
**Purpose**: Regex patterns for suspicious user fields

**Format**: Regex pattern (one per line)
```
^admin$
^root$
^test$
^[0-9]{10,}$
```

**Enable in** `local.d/url_suspect.conf`:
```lua
url_suspect {
  checks {
    user_password {
      use_pattern_map = true;
      pattern_map = "$LOCAL_CONFDIR/local.d/maps.d/url_suspect/user_patterns.map";
    }
  }
}
```

### 3. user_blacklist.map
**Purpose**: Exact user names to penalize

**Format**: Exact match (one per line)
```
admin
root
administrator
webmaster
```

**Enable in** `local.d/url_suspect.conf`:
```lua
url_suspect {
  checks {
    user_password {
      use_blacklist = true;
      blacklist_map = "$LOCAL_CONFDIR/local.d/maps.d/url_suspect/user_blacklist.map";
    }
  }
}
```

### 4. suspicious_tlds.map
**Purpose**: Additional TLDs beyond built-in list (.tk, .ml, .ga, .cf, .gq)

**Format**: TLD with leading dot (one per line)
```
.xyz
.top
.work
.date
.loan
```

**Enable in** `local.d/url_suspect.conf`:
```lua
url_suspect {
  checks {
    tld {
      use_tld_map = true;
      tld_map = "$LOCAL_CONFDIR/local.d/maps.d/url_suspect/suspicious_tlds.map";
    }
  }
}
```

### 5. suspicious_ip_ranges.map
**Purpose**: IP ranges to mark as suspicious (beyond built-in private IP detection)

**Format**: CIDR notation (one per line)
```
203.0.113.0/24
198.51.100.0/24
```

**Enable in** `local.d/url_suspect.conf`:
```lua
url_suspect {
  checks {
    numeric_ip {
      use_range_map = true;
      range_map = "$LOCAL_CONFDIR/local.d/maps.d/url_suspect/suspicious_ip_ranges.map";
    }
  }
}
```

### 6. suspicious_ports.map
**Purpose**: Unusual ports that indicate suspicious URLs

**Format**: Port number (one per line)
```
8080
8443
3128
1080
```

**Enable in** `local.d/url_suspect.conf`:
```lua
url_suspect {
  checks {
    structure {
      use_port_map = true;
      port_map = "$LOCAL_CONFDIR/local.d/maps.d/url_suspect/suspicious_ports.map";
    }
  }
}
```

## Map File Locations

You can place map files in:
1. `$LOCAL_CONFDIR/local.d/maps.d/url_suspect/` (recommended)
2. `$LOCAL_CONFDIR/local.d/` (also works)
3. Any absolute path
4. Remote URL (e.g., `https://example.com/map.txt`)

## Example Files

See `.example` files in this directory for templates you can copy and modify.

## Performance Note

Maps are loaded once at startup and cached in memory. They don't add significant overhead even when enabled.

## Support

For questions or issues:
- Documentation: https://rspamd.com/doc/modules/url_suspect.html
- GitHub: https://github.com/rspamd/rspamd/issues
