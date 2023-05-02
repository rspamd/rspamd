# Language detection configuration
# Please don't modify this file as your changes might be overwritten with
# the next update.
#
# You can modify 'local.d/lang_detection.inc' to add and merge
# parameters defined inside this section
#
# You can modify 'override.d/lang_detection.inc' to strictly override all
# parameters defined inside this section

# Path to the languages shared data
# languages = "${RSPAMD_SHAREDIR}/languages"

# Limit in words to treat text as short for language detection
# short_text_limit = 10

# Enable only specific languages
# languages_enable = ["en", "de"]

# Disable specific languages
# languages_disable = ["fr", "es"]

# Use the following fasttext model for language detection (if Fasttext support is compiled in)
# fasttext_model = "${RSPAMD_SHAREDIR}/languages/fasttext_model.ftz"

# Prefer fasttext over all other methods
# prefer_fasttext = true;

