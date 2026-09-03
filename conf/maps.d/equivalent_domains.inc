# Domains that deliver to the same mailbox namespace as another domain:
# user@<alias> and user@<canonical> reach one and the same account.
# Format: <alias domain> <canonical domain>
#
# This list is used to compare mailbox identities only (e.g. envelope vs
# header addresses in forged_recipients). The domains stay distinct for
# DNS-based checks (SPF, DKIM, DMARC), so nothing here rewrites addresses.
#
# Only providers documenting that the same local part is reachable under
# every listed domain belong here. Providers where the user picks one of
# several domains per address (yahoo.com/ymail.com, outlook.com/hotmail.com,
# mail.ru/bk.ru/list.ru/inbox.ru, gmx.*) do not.

# Google
googlemail.com gmail.com

# Proton
protonmail.com proton.me
protonmail.ch proton.me
pm.me proton.me

# Apple
me.com icloud.com
mac.com icloud.com

# Yandex
yandex.com yandex.ru
yandex.by yandex.ru
yandex.kz yandex.ru
yandex.ua yandex.ru
ya.ru yandex.ru
