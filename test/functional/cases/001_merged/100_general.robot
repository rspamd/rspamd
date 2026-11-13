*** Settings ***
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${GTUBE}               ${RSPAMD_TESTDIR}/messages/gtube.eml
${ALT_RELATED}         ${RSPAMD_TESTDIR}/messages/alternative-related.eml
${MIXED_RELATED_HTML}  ${RSPAMD_TESTDIR}/messages/mixed-related-html-only.eml
${ALT_NESTED_RFC822}   ${RSPAMD_TESTDIR}/messages/alternative-nested-rfc822.eml
${ALT_EMPTY_RELATED}   ${RSPAMD_TESTDIR}/messages/alternative-empty-related.eml
${MIXED_HTML_ZIP}      ${RSPAMD_TESTDIR}/messages/mixed-html-zip.eml
${ALT_HTML_CALENDAR}   ${RSPAMD_TESTDIR}/messages/alt-html-calendar.eml
${SETTINGS_NOSYMBOLS}  {symbols_enabled = []}

*** Test Cases ***
GTUBE
  Scan File  ${GTUBE}
  ...  Settings=${SETTINGS_NOSYMBOLS}
  Expect Symbol  GTUBE

GTUBE - Encrypted
  ${result} =  Run Rspamc  -p  -h  ${RSPAMD_LOCAL_ADDR}:${RSPAMD_PORT_NORMAL}  --key  ${RSPAMD_KEY_PUB1}
  ...  ${GTUBE}  --header=Settings=${SETTINGS_NOSYMBOLS}
  Check Rspamc  ${result}  GTUBE (

GTUBE - Scan File feature
  Scan File By Reference  ${GTUBE}
  ...  Settings=${SETTINGS_NOSYMBOLS}
  Expect Symbol  GTUBE

GTUBE - Scan File feature (encoded)
  ${encoded} =  Encode Filename  ${GTUBE}
  Scan File By Reference  ${encoded}
  ...  Settings=${SETTINGS_NOSYMBOLS}
  Expect Symbol  GTUBE

GTUBE - SPAMC
  ${result} =  Spamc  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_NORMAL}  ${GTUBE}
  Should Contain  ${result}  GTUBE

GTUBE - RSPAMC
  ${result} =  Rspamc  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_NORMAL}  ${GTUBE}
  Should Contain  ${result}  GTUBE

EMAILS DETECTION 1
  Scan File  ${RSPAMD_TESTDIR}/messages/emails1.eml
  ...  URL-Format=Extended  Settings=${SETTINGS_NOSYMBOLS}
  Expect Email  jim@example.net
  Expect Email  bob@example.net
  Expect Email  rupert@example.net

EMAILS DETECTION ZEROFONT
  Scan File  ${RSPAMD_TESTDIR}/messages/zerofont.eml
  ...  Settings={symbols_enabled = [MANY_INVISIBLE_PARTS, ZERO_FONT]}
  Expect Symbol  MANY_INVISIBLE_PARTS
  Expect Symbol  ZERO_FONT

HTML VISIBILITY - Layout whitespace
  Scan File  ${RSPAMD_TESTDIR}/messages/html_visibility_layout.eml
  ...  Settings={symbols_enabled = [MANY_INVISIBLE_PARTS, ZERO_FONT, R_WHITE_ON_WHITE, HIDDEN_TEXT]}
  Do Not Expect Symbol  ZERO_FONT
  Do Not Expect Symbol  MANY_INVISIBLE_PARTS
  Do Not Expect Symbol  R_WHITE_ON_WHITE
  Do Not Expect Symbol  HIDDEN_TEXT

HTML VISIBILITY - Preview and dividers
  Scan File  ${RSPAMD_TESTDIR}/messages/html_visibility_preview.eml
  ...  Settings={symbols_enabled = [MANY_INVISIBLE_PARTS, ZERO_FONT, HIDDEN_TEXT]}
  Expect Symbol With Score And Exact Options  ZERO_FONT  0.1  1
  Expect Symbol With Score And Exact Options  MANY_INVISIBLE_PARTS  0.05  1
  Do Not Expect Symbol  HIDDEN_TEXT

HTML VISIBILITY - Hidden text with padding
  Scan File  ${RSPAMD_TESTDIR}/messages/html_visibility_hidden.eml
  ...  Settings={symbols_enabled = [MANY_INVISIBLE_PARTS, ZERO_FONT]}
  Expect Symbol With Score And Exact Options  ZERO_FONT  0.2  2
  Expect Symbol With Score And Exact Options  MANY_INVISIBLE_PARTS  0.2  3

HTML VISIBILITY - Transparent text
  Scan File  ${RSPAMD_TESTDIR}/messages/html_visibility_transparent.eml
  ...  Settings={symbols_enabled = [MANY_INVISIBLE_PARTS, R_WHITE_ON_WHITE]}
  Expect Symbol With Score And Exact Options  MANY_INVISIBLE_PARTS  0.05  1
  Expect Symbol With Exact Options  R_WHITE_ON_WHITE  span color #ffffff bgcolor #ffffff

HTML VISIBILITY - Significant hidden content
  [Template]  Check Hidden Content Amount
  large_zero  5  500
  large_nested  5  500
  boundary  2  200
  intermediate  3  300
  multipart  2  200
  stylesheet_over_inline  5  500
  max_zero_width  5  500
  zero_max_none  5  500
  zero_percent_max  5  500
  auto_max_zero  5  500
  auto_max_other_rule  5  500
  invalid_unit  5  500

HTML VISIBILITY - No significant hidden content
  [Template]  Check No Significant Hidden Content
  below_threshold
  padding
  react_email_padding
  visible
  font_shorthand
  relative_font
  grouped_selector
  auto_overflow
  auto_beats_zero
  auto_real_width
  none_max_unflatten
  none_max_invalidate

HTML ONLY - TRUE POSITIVE
  Scan File  ${RSPAMD_TESTDIR}/messages/zerofont.eml
  ...  Settings={symbols_enabled = [MIME_HTML_ONLY]}
  Expect Symbol  MIME_HTML_ONLY

HTML ONLY - TRUE NEGATIVE
  Scan File  ${RSPAMD_TESTDIR}/messages/btc.eml
  ...  Settings={symbols_enabled = [MIME_HTML_ONLY]}
  Do Not Expect Symbol  MIME_HTML_ONLY

HTML ONLY - multipart/related inside alternative
  Scan File  ${ALT_RELATED}
  ...  Settings={symbols_enabled = [MIME_HTML_ONLY]}
  Do Not Expect Symbol  MIME_HTML_ONLY

HTML ONLY - multipart/mixed with related (html only)
  Scan File  ${MIXED_RELATED_HTML}
  ...  Settings={symbols_enabled = [MIME_HTML_ONLY]}
  Expect Symbol  MIME_HTML_ONLY

PARTS DIFFER - multipart/related inside alternative
  Scan File  ${ALT_RELATED}
  ...  Settings={symbols_enabled = [R_PARTS_DIFFER]}
  Expect Symbol  R_PARTS_DIFFER

HTML ONLY - nested message/rfc822 with alternative
  Scan File  ${ALT_NESTED_RFC822}
  ...  Settings={symbols_enabled = [MIME_HTML_ONLY]}
  Expect Symbol  MIME_HTML_ONLY

HTML ONLY - malformed related with no children
  Scan File  ${ALT_EMPTY_RELATED}
  ...  Settings={symbols_enabled = [MIME_HTML_ONLY]}
  Expect Symbol  MIME_HTML_ONLY

HTML ONLY - multipart/mixed with html and non-text attachment
  Scan File  ${MIXED_HTML_ZIP}
  ...  Settings={symbols_enabled = [MIME_HTML_ONLY]}
  Expect Symbol  MIME_HTML_ONLY

HTML ONLY - multipart/alternative with html and text/calendar
  Scan File  ${ALT_HTML_CALENDAR}
  ...  Settings={symbols_enabled = [MIME_HTML_ONLY]}
  Do Not Expect Symbol  MIME_HTML_ONLY

TINY PIXEL TRACKER - TRUE POSITIVE
  # A bounce probe: a short HTML part with a random token and a hidden
  # 1x1 external tracking pixel as the only image and no links at all
  Scan File  ${RSPAMD_TESTDIR}/messages/html_tiny_pixel_probe.eml
  ...  Settings={symbols_enabled = [HTML_TINY_PIXEL_TRACKER]}
  Expect Symbol With Score  HTML_TINY_PIXEL_TRACKER  3.0

TINY PIXEL TRACKER - LOGO HAM
  # A real image alongside the pixel makes the part not pixel-only
  Scan File  ${RSPAMD_TESTDIR}/messages/html_tiny_pixel_logo_ham.eml
  ...  Settings={symbols_enabled = [HTML_TINY_PIXEL_TRACKER]}
  Do Not Expect Symbol  HTML_TINY_PIXEL_TRACKER

TINY PIXEL TRACKER - LINK HAM
  # A link in a short pixel-bearing part marks it as a normal
  # transactional message, not a contentless probe
  Scan File  ${RSPAMD_TESTDIR}/messages/html_tiny_pixel_link_ham.eml
  ...  Settings={symbols_enabled = [HTML_TINY_PIXEL_TRACKER]}
  Do Not Expect Symbol  HTML_TINY_PIXEL_TRACKER

TINY PIXEL TRACKER - MIN-WIDTH/MIN-HEIGHT STYLE HAM
  # min-width/min-height are not image dimensions: a normal external
  # image styled this way must not be classified as a tiny pixel
  Scan File  ${RSPAMD_TESTDIR}/messages/html_tiny_pixel_min_size_ham.eml
  ...  Settings={symbols_enabled = [HTML_TINY_PIXEL_TRACKER]}
  Do Not Expect Symbol  HTML_TINY_PIXEL_TRACKER

TINY PIXEL TRACKER - EM-SIZED ICON STYLE HAM
  # Relative CSS units are not pixel dimensions: an icon styled
  # width:1em;height:1em must not be classified as a tiny pixel
  Scan File  ${RSPAMD_TESTDIR}/messages/html_tiny_pixel_em_size_ham.eml
  ...  Settings={symbols_enabled = [HTML_TINY_PIXEL_TRACKER]}
  Do Not Expect Symbol  HTML_TINY_PIXEL_TRACKER

TINY PIXEL TRACKER - CSS OVERRIDE STYLE HAM
  # CSS dimensions override the attribute ones: an image declared as
  # 1x1 attributes but stretched by style must not be a tiny pixel
  Scan File  ${RSPAMD_TESTDIR}/messages/html_tiny_pixel_css_override_ham.eml
  ...  Settings={symbols_enabled = [HTML_TINY_PIXEL_TRACKER]}
  Do Not Expect Symbol  HTML_TINY_PIXEL_TRACKER

TINY PIXEL TRACKER - BARE URL IN HTML HAM
  # A bare URL in HTML text without an <a> tag is content as well:
  # only image sources may remain in a contentless probe
  Scan File  ${RSPAMD_TESTDIR}/messages/html_tiny_pixel_bare_url_ham.eml
  ...  Settings={symbols_enabled = [HTML_TINY_PIXEL_TRACKER]}
  Do Not Expect Symbol  HTML_TINY_PIXEL_TRACKER

TINY PIXEL TRACKER - BARE EMAIL IN HTML HAM
  # A bare email address in HTML text is content as well; mailto URLs
  # must be included when checking part URLs
  Scan File  ${RSPAMD_TESTDIR}/messages/html_tiny_pixel_mailto_ham.eml
  ...  Settings={symbols_enabled = [HTML_TINY_PIXEL_TRACKER]}
  Do Not Expect Symbol  HTML_TINY_PIXEL_TRACKER

TINY PIXEL TRACKER - AUTO SIZE STYLE HAM
  # width:auto;height:auto means the intrinsic image size: attribute
  # dimensions must not classify the image as a tiny pixel
  Scan File  ${RSPAMD_TESTDIR}/messages/html_tiny_pixel_auto_size_ham.eml
  ...  Settings={symbols_enabled = [HTML_TINY_PIXEL_TRACKER]}
  Do Not Expect Symbol  HTML_TINY_PIXEL_TRACKER

TINY PIXEL TRACKER - RELATIVE CSS KEEPS ATTRIBUTE DIMENSIONS
  # A relative style value must not overwrite the attribute size,
  # so the existing image rules keep seeing the attribute dimensions
  Scan File  ${RSPAMD_TESTDIR}/messages/html_tiny_pixel_relative_attrs.eml
  ...  Settings={symbols_enabled = [HTML_TINY_PIXEL_TRACKER, R_EMPTY_IMAGE]}
  Do Not Expect Symbol  HTML_TINY_PIXEL_TRACKER
  Expect Symbol  R_EMPTY_IMAGE

TINY PIXEL TRACKER - CSS CASCADE HAM
  # The last declaration of a property wins in CSS: duplicated
  # width/height must not classify a large image as a tiny pixel
  Scan File  ${RSPAMD_TESTDIR}/messages/html_tiny_pixel_css_cascade_ham.eml
  ...  Settings={symbols_enabled = [HTML_TINY_PIXEL_TRACKER, R_EMPTY_IMAGE]}
  Do Not Expect Symbol  HTML_TINY_PIXEL_TRACKER
  Expect Symbol  R_EMPTY_IMAGE

TINY PIXEL TRACKER - UPPERCASE CID HAM
  # URI schemes are case-insensitive: CID: images are embedded, not
  # external trackers
  Scan File  ${RSPAMD_TESTDIR}/messages/html_tiny_pixel_cid_case_ham.eml
  ...  Settings={symbols_enabled = [HTML_TINY_PIXEL_TRACKER]}
  Do Not Expect Symbol  HTML_TINY_PIXEL_TRACKER

TINY PIXEL TRACKER - IMPORTANT CSS WINS HAM
  # A !important declaration beats the later normal ones: a large
  # image must not be classified as a tiny pixel
  Scan File  ${RSPAMD_TESTDIR}/messages/html_tiny_pixel_important_ham.eml
  ...  Settings={symbols_enabled = [HTML_TINY_PIXEL_TRACKER, R_EMPTY_IMAGE]}
  Do Not Expect Symbol  HTML_TINY_PIXEL_TRACKER
  Expect Symbol  R_EMPTY_IMAGE

TINY PIXEL TRACKER - MIN-SIZE FLOOR STYLE HAM
  # Absolute min-width/min-height raise the rendered size above the
  # tiny threshold even when the attributes are 1x1
  Scan File  ${RSPAMD_TESTDIR}/messages/html_tiny_pixel_min_floor_ham.eml
  ...  Settings={symbols_enabled = [HTML_TINY_PIXEL_TRACKER]}
  Do Not Expect Symbol  HTML_TINY_PIXEL_TRACKER

TINY PIXEL TRACKER - MIN-SIZE CLAMP HAM
  # min-width clamps the effective size from below, so the rendered
  # 4x2 image is above the tiny threshold
  Scan File  ${RSPAMD_TESTDIR}/messages/html_tiny_pixel_min_clamp_ham.eml
  ...  Settings={symbols_enabled = [HTML_TINY_PIXEL_TRACKER]}
  Do Not Expect Symbol  HTML_TINY_PIXEL_TRACKER

TINY PIXEL TRACKER - STYLESHEET RULE HAM
  # Stylesheet rules beat the attribute dimensions: a class-sized
  # image must not be classified as a tiny pixel
  Scan File  ${RSPAMD_TESTDIR}/messages/html_tiny_pixel_stylesheet_ham.eml
  ...  Settings={symbols_enabled = [HTML_TINY_PIXEL_TRACKER, R_EMPTY_IMAGE]}
  Do Not Expect Symbol  HTML_TINY_PIXEL_TRACKER
  Expect Symbol  R_EMPTY_IMAGE

TINY PIXEL TRACKER - STYLESHEET AFTER IMAGE HAM
  # Style sheets are reconciled after parsing, so a <style> tag
  # following the image still resizes it
  Scan File  ${RSPAMD_TESTDIR}/messages/html_tiny_pixel_style_after_img_ham.eml
  ...  Settings={symbols_enabled = [HTML_TINY_PIXEL_TRACKER, R_EMPTY_IMAGE]}
  Do Not Expect Symbol  HTML_TINY_PIXEL_TRACKER
  Expect Symbol  R_EMPTY_IMAGE

TINY PIXEL TRACKER - STYLESHEET SHRINK PROBE
  # A stylesheet rule shrinking a large declared image to a pixel is
  # a tracking pixel and must be detected
  Scan File  ${RSPAMD_TESTDIR}/messages/html_tiny_pixel_css_shrink_probe.eml
  ...  Settings={symbols_enabled = [HTML_TINY_PIXEL_TRACKER]}
  Expect Symbol With Score  HTML_TINY_PIXEL_TRACKER  3.0

TINY PIXEL TRACKER - STYLESHEET ONLY DIMENSIONS PROBE
  # An image sized by a stylesheet alone, without any attribute or
  # inline dimensions, is classified as well
  Scan File  ${RSPAMD_TESTDIR}/messages/html_tiny_pixel_css_only_probe.eml
  ...  Settings={symbols_enabled = [HTML_TINY_PIXEL_TRACKER]}
  Expect Symbol With Score  HTML_TINY_PIXEL_TRACKER  3.0

TINY PIXEL TRACKER - STYLESHEET MAX BOUND KEEPS PIXEL
  # max-width/max-height are upper bounds, not sizes: a 1x1 image
  # constrained by large maximums is still a pixel
  Scan File  ${RSPAMD_TESTDIR}/messages/html_tiny_pixel_css_max_probe.eml
  ...  Settings={symbols_enabled = [HTML_TINY_PIXEL_TRACKER]}
  Expect Symbol With Score  HTML_TINY_PIXEL_TRACKER  3.0

TINY PIXEL TRACKER - STYLESHEET MAX SURVIVES RULE MERGE
  # The max provenance must survive merging of matched CSS rules
  Scan File  ${RSPAMD_TESTDIR}/messages/html_tiny_pixel_css_max_merge_probe.eml
  ...  Settings={symbols_enabled = [HTML_TINY_PIXEL_TRACKER]}
  Expect Symbol With Score  HTML_TINY_PIXEL_TRACKER  3.0

TINY PIXEL TRACKER - STYLESHEET MAX CAPS INLINE SIZE
  # A max bound dictates the effective size even when a real width is
  # also present, and caps the inline style too
  Scan File  ${RSPAMD_TESTDIR}/messages/html_tiny_pixel_css_max_wins_probe.eml
  ...  Settings={symbols_enabled = [HTML_TINY_PIXEL_TRACKER]}
  Expect Symbol With Score  HTML_TINY_PIXEL_TRACKER  3.0

TINY PIXEL TRACKER - STYLESHEET MIN-SIZE HAM
  # Stylesheet min-width/min-height raise the rendered size above the
  # tiny threshold even when the attributes are 1x1
  Scan File  ${RSPAMD_TESTDIR}/messages/html_tiny_pixel_css_min_ham.eml
  ...  Settings={symbols_enabled = [HTML_TINY_PIXEL_TRACKER]}
  Do Not Expect Symbol  HTML_TINY_PIXEL_TRACKER

TINY PIXEL TRACKER - STYLESHEET MIN SURVIVES RULE MERGE
  # A minimum from a losing rule must still fill the winner block,
  # which is allocated zeroed and not value-initialized
  Scan File  ${RSPAMD_TESTDIR}/messages/html_tiny_pixel_css_min_merge_ham.eml
  ...  Settings={symbols_enabled = [HTML_TINY_PIXEL_TRACKER]}
  Do Not Expect Symbol  HTML_TINY_PIXEL_TRACKER

TINY PIXEL TRACKER - INLINE ZERO MIN OVERRIDES STYLESHEET
  # An inline min-width/min-height overrides a stylesheet one
  # entirely, so zero minimums keep the image a pixel
  Scan File  ${RSPAMD_TESTDIR}/messages/html_tiny_pixel_inline_min_zero_probe.eml
  ...  Settings={symbols_enabled = [HTML_TINY_PIXEL_TRACKER]}
  Expect Symbol With Score  HTML_TINY_PIXEL_TRACKER  3.0

TINY PIXEL TRACKER - STYLESHEET WIDTH CAPPED BY MAX HAM
  # A real stylesheet width capped by max-width is still a real size:
  # it must override the 1x1 attributes with the capped value
  Scan File  ${RSPAMD_TESTDIR}/messages/html_tiny_pixel_css_capped_ham.eml
  ...  Settings={symbols_enabled = [HTML_TINY_PIXEL_TRACKER]}
  Do Not Expect Symbol  HTML_TINY_PIXEL_TRACKER

TINY PIXEL TRACKER - STYLESHEET ZERO MIN WINS MERGE
  # An explicit zero minimum in the winning rule resets the floor:
  # the loser's large minimum must not fill it
  Scan File  ${RSPAMD_TESTDIR}/messages/html_tiny_pixel_css_min_zero_merge_probe.eml
  ...  Settings={symbols_enabled = [HTML_TINY_PIXEL_TRACKER]}
  Expect Symbol With Score  HTML_TINY_PIXEL_TRACKER  3.0

TINY PIXEL TRACKER - STYLESHEET ZERO MAX PROBE
  # An explicit zero bound collapses the image to 0x0: an invisible
  # tracker must be detected
  Scan File  ${RSPAMD_TESTDIR}/messages/html_tiny_pixel_css_max_zero_probe.eml
  ...  Settings={symbols_enabled = [HTML_TINY_PIXEL_TRACKER]}
  Expect Symbol With Score  HTML_TINY_PIXEL_TRACKER  3.0

TINY PIXEL TRACKER - INLINE NONE MAX REMOVES BOUND
  # An inline max-width/max-height none overrides the stylesheet
  # bounds, so a large inline-sized image is not a pixel
  Scan File  ${RSPAMD_TESTDIR}/messages/html_tiny_pixel_inline_max_none_ham.eml
  ...  Settings={symbols_enabled = [HTML_TINY_PIXEL_TRACKER]}
  Do Not Expect Symbol  HTML_TINY_PIXEL_TRACKER

TINY PIXEL TRACKER - WIDTH AND MAX FROM DIFFERENT RULES
  # A real width from a losing rule beats the max-flattened width of
  # the winner, so a 600x200 image shrunk to 1x1 is detected
  Scan File  ${RSPAMD_TESTDIR}/messages/html_tiny_pixel_css_mixed_rules_probe.eml
  ...  Settings={symbols_enabled = [HTML_TINY_PIXEL_TRACKER]}
  Expect Symbol With Score  HTML_TINY_PIXEL_TRACKER  3.0

TINY PIXEL TRACKER - INLINE MAX WITHOUT STYLESHEET
  # Inline max-width/max-height cap the attribute dimensions even
  # when the message has no stylesheet at all
  Scan File  ${RSPAMD_TESTDIR}/messages/html_tiny_pixel_inline_max_only_probe.eml
  ...  Settings={symbols_enabled = [HTML_TINY_PIXEL_TRACKER]}
  Expect Symbol With Score  HTML_TINY_PIXEL_TRACKER  3.0

TINY PIXEL TRACKER - STYLESHEET NONE MAX REMOVES BOUND
  # A more specific max-width/max-height none removes the bound
  # declared by a less specific rule, so a large image is not a pixel
  Scan File  ${RSPAMD_TESTDIR}/messages/html_tiny_pixel_css_max_none_ham.eml
  ...  Settings={symbols_enabled = [HTML_TINY_PIXEL_TRACKER]}
  Do Not Expect Symbol  HTML_TINY_PIXEL_TRACKER

TINY PIXEL TRACKER - CLAMPED WIDTH WITH LARGER MAX
  # The real width clamped by the max bound of its own rule is applied
  # when a more specific rule raises the bound, so a 100x100 image
  # with tiny attributes is not a pixel
  Scan File  ${RSPAMD_TESTDIR}/messages/html_tiny_pixel_css_clamp_cascade_ham.eml
  ...  Settings={symbols_enabled = [HTML_TINY_PIXEL_TRACKER]}
  Do Not Expect Symbol  HTML_TINY_PIXEL_TRACKER

TINY PIXEL TRACKER - PERCENT SIZE WINS CASCADE
  # A percent width/height in the winning rule has no absolute value,
  # so a less specific absolute size must not classify a large image
  # as a pixel
  Scan File  ${RSPAMD_TESTDIR}/messages/html_tiny_pixel_css_percent_wins_ham.eml
  ...  Settings={symbols_enabled = [HTML_TINY_PIXEL_TRACKER]}
  Do Not Expect Symbol  HTML_TINY_PIXEL_TRACKER

TINY PIXEL TRACKER - PERCENT SIZE BEATS MAX FLATTEN
  # A percent width/height from a losing rule overrides the attribute
  # dimensions and a width flattened from the winning max bound, so
  # the effective size is unknown rather than the tiny attributes
  Scan File  ${RSPAMD_TESTDIR}/messages/html_tiny_pixel_percent_max_merge_ham.eml
  ...  Settings={symbols_enabled = [HTML_TINY_PIXEL_TRACKER]}
  Do Not Expect Symbol  HTML_TINY_PIXEL_TRACKER

TINY PIXEL TRACKER - STYLESHEET PERCENT MINIMUM
  # A percent minimum resolves against the container and may raise
  # the size above the tiny threshold, so tiny attributes cannot be
  # classified as a pixel
  Scan File  ${RSPAMD_TESTDIR}/messages/html_tiny_pixel_percent_min_sheet_ham.eml
  ...  Settings={symbols_enabled = [HTML_TINY_PIXEL_TRACKER]}
  Do Not Expect Symbol  HTML_TINY_PIXEL_TRACKER

TINY PIXEL TRACKER - INLINE PERCENT MINIMUM
  # An inline percent minimum has the same effect as a stylesheet one
  Scan File  ${RSPAMD_TESTDIR}/messages/html_tiny_pixel_percent_min_inline_ham.eml
  ...  Settings={symbols_enabled = [HTML_TINY_PIXEL_TRACKER]}
  Do Not Expect Symbol  HTML_TINY_PIXEL_TRACKER

TINY PIXEL TRACKER - INLINE MINIMUM OVERRIDES PERCENT
  # An inline absolute minimum overrides a stylesheet percent one
  # entirely, so tiny attributes stay classified as a pixel
  Scan File  ${RSPAMD_TESTDIR}/messages/html_tiny_pixel_inline_min_overrides_percent_probe.eml
  ...  Settings={symbols_enabled = [HTML_TINY_PIXEL_TRACKER]}
  Expect Symbol With Score  HTML_TINY_PIXEL_TRACKER  3.0

TINY PIXEL TRACKER - INLINE ZERO PERCENT MINIMUM
  # A zero percent minimum is an absolute zero floor, not a percent
  # one, so tiny attributes stay classified as a pixel
  Scan File  ${RSPAMD_TESTDIR}/messages/html_tiny_pixel_inline_zero_percent_min_probe.eml
  ...  Settings={symbols_enabled = [HTML_TINY_PIXEL_TRACKER]}
  Expect Symbol With Score  HTML_TINY_PIXEL_TRACKER  3.0

TINY PIXEL TRACKER - INLINE ZERO PERCENT MAXIMUM
  # A zero percent maximum is an absolute zero bound, so a large
  # image is capped to zero and detected
  Scan File  ${RSPAMD_TESTDIR}/messages/html_tiny_pixel_inline_zero_percent_max_probe.eml
  ...  Settings={symbols_enabled = [HTML_TINY_PIXEL_TRACKER]}
  Expect Symbol With Score  HTML_TINY_PIXEL_TRACKER  3.0

TINY PIXEL TRACKER - AUTO SIZE WINS CASCADE
  # A width/height auto in the winning rule means the intrinsic size,
  # so a less specific absolute size must not classify a large image
  # as a pixel
  Scan File  ${RSPAMD_TESTDIR}/messages/html_tiny_pixel_css_auto_wins_ham.eml
  ...  Settings={symbols_enabled = [HTML_TINY_PIXEL_TRACKER]}
  Do Not Expect Symbol  HTML_TINY_PIXEL_TRACKER

TINY PIXEL TRACKER - STYLE COMMENT IGNORED
  # CSS comments carry no declarations, so sizes inside one must not
  # override the attribute dimensions
  Scan File  ${RSPAMD_TESTDIR}/messages/html_tiny_pixel_style_comment_ham.eml
  ...  Settings={symbols_enabled = [HTML_TINY_PIXEL_TRACKER]}
  Do Not Expect Symbol  HTML_TINY_PIXEL_TRACKER

TINY PIXEL TRACKER - IMPORTANT STYLE SHEET SIZE
  # An !important stylesheet width/height beats the inline style, so
  # an inline-sized pixel is not classified as one
  Scan File  ${RSPAMD_TESTDIR}/messages/html_tiny_pixel_css_important_ham.eml
  ...  Settings={symbols_enabled = [HTML_TINY_PIXEL_TRACKER]}
  Do Not Expect Symbol  HTML_TINY_PIXEL_TRACKER

TINY PIXEL TRACKER - FRACTIONAL INLINE SIZE
  # A fractional pixel size is an absolute dimension, so a 1.0px one
  # is detected
  Scan File  ${RSPAMD_TESTDIR}/messages/html_tiny_pixel_inline_fraction_probe.eml
  ...  Settings={symbols_enabled = [HTML_TINY_PIXEL_TRACKER]}
  Expect Symbol With Score  HTML_TINY_PIXEL_TRACKER  3.0

TINY PIXEL TRACKER - ZERO PERCENT INLINE SIZE
  # A zero percent size is an absolute zero, so the image is detected
  Scan File  ${RSPAMD_TESTDIR}/messages/html_tiny_pixel_inline_zero_percent_size_probe.eml
  ...  Settings={symbols_enabled = [HTML_TINY_PIXEL_TRACKER]}
  Expect Symbol With Score  HTML_TINY_PIXEL_TRACKER  3.0

TINY PIXEL TRACKER - FRACTIONAL PERCENT MINIMUM
  # A fractional percent minimum is not a zero one, so it marks the
  # size unknown rather than keeping tiny attributes
  Scan File  ${RSPAMD_TESTDIR}/messages/html_tiny_pixel_percent_min_fraction_ham.eml
  ...  Settings={symbols_enabled = [HTML_TINY_PIXEL_TRACKER]}
  Do Not Expect Symbol  HTML_TINY_PIXEL_TRACKER

TINY PIXEL TRACKER - QUOTED URL BEFORE SIZES
  # A comment opening inside a quoted url does not start a comment,
  # so the sizes after the url still apply
  Scan File  ${RSPAMD_TESTDIR}/messages/html_tiny_pixel_style_quoted_url_ham.eml
  ...  Settings={symbols_enabled = [HTML_TINY_PIXEL_TRACKER]}
  Do Not Expect Symbol  HTML_TINY_PIXEL_TRACKER

TINY PIXEL TRACKER - PROPERTIES INSIDE URL IGNORED
  # Property-looking substrings inside a quoted url are not CSS, so
  # the attribute dimensions stay in effect
  Scan File  ${RSPAMD_TESTDIR}/messages/html_tiny_pixel_style_url_props_ham.eml
  ...  Settings={symbols_enabled = [HTML_TINY_PIXEL_TRACKER]}
  Do Not Expect Symbol  HTML_TINY_PIXEL_TRACKER

TINY PIXEL TRACKER - INLINE IMPORTANT BEATS SHEET IMPORTANT
  # An !important inline size beats an !important stylesheet one, so
  # a large inline-sized image is not classified as a pixel
  Scan File  ${RSPAMD_TESTDIR}/messages/html_tiny_pixel_important_loses_inline_ham.eml
  ...  Settings={symbols_enabled = [HTML_TINY_PIXEL_TRACKER]}
  Do Not Expect Symbol  HTML_TINY_PIXEL_TRACKER

TINY PIXEL TRACKER - IMPORTANT SURVIVES LATER NORMAL
  # An !important declaration beats later normal ones of the same
  # property, so the important size stays in effect
  Scan File  ${RSPAMD_TESTDIR}/messages/html_tiny_pixel_important_then_normal_ham.eml
  ...  Settings={symbols_enabled = [HTML_TINY_PIXEL_TRACKER]}
  Do Not Expect Symbol  HTML_TINY_PIXEL_TRACKER

TINY PIXEL TRACKER - FRACTIONAL SIZE WITH UNITS
  # A fractional value is converted in double precision, so 0.4in is
  # well above the tiny threshold
  Scan File  ${RSPAMD_TESTDIR}/messages/html_tiny_pixel_inline_fraction_units_ham.eml
  ...  Settings={symbols_enabled = [HTML_TINY_PIXEL_TRACKER]}
  Do Not Expect Symbol  HTML_TINY_PIXEL_TRACKER

TINY PIXEL TRACKER - FRACTIONAL PIXELS ROUNDED
  # A fractional pixel value is rounded, not truncated, so 2.9px is
  # above the tiny threshold
  Scan File  ${RSPAMD_TESTDIR}/messages/html_tiny_pixel_inline_fraction_round_ham.eml
  ...  Settings={symbols_enabled = [HTML_TINY_PIXEL_TRACKER]}
  Do Not Expect Symbol  HTML_TINY_PIXEL_TRACKER

TINY PIXEL TRACKER - PROPERTIES IN URL WITHOUT SLASHES
  # Property-looking substrings inside a quoted url are blanked out
  # even when the style has no comment opening at all
  Scan File  ${RSPAMD_TESTDIR}/messages/html_tiny_pixel_style_url_no_slash_ham.eml
  ...  Settings={symbols_enabled = [HTML_TINY_PIXEL_TRACKER]}
  Do Not Expect Symbol  HTML_TINY_PIXEL_TRACKER

TINY PIXEL TRACKER - IMPORTANT SHEET MINIMUM
  # An !important stylesheet minimum beats a non-important inline
  # one, raising the floor above the tiny threshold
  Scan File  ${RSPAMD_TESTDIR}/messages/html_tiny_pixel_min_important_sheet_ham.eml
  ...  Settings={symbols_enabled = [HTML_TINY_PIXEL_TRACKER]}
  Do Not Expect Symbol  HTML_TINY_PIXEL_TRACKER

TINY PIXEL TRACKER - IMPORTANT SHEET MAXIMUM
  # An !important stylesheet maximum beats a non-important inline
  # one, so the tiny inline bound does not cap a large image
  Scan File  ${RSPAMD_TESTDIR}/messages/html_tiny_pixel_max_important_sheet_ham.eml
  ...  Settings={symbols_enabled = [HTML_TINY_PIXEL_TRACKER]}
  Do Not Expect Symbol  HTML_TINY_PIXEL_TRACKER

TINY PIXEL TRACKER - PROPERTIES IN UNQUOTED URL IGNORED
  # Property-looking substrings inside an unquoted url(...) are not
  # CSS, so the attribute dimensions stay in effect
  Scan File  ${RSPAMD_TESTDIR}/messages/html_tiny_pixel_style_url_unquoted_ham.eml
  ...  Settings={symbols_enabled = [HTML_TINY_PIXEL_TRACKER]}
  Do Not Expect Symbol  HTML_TINY_PIXEL_TRACKER

TINY PIXEL TRACKER - STYLESHEET FRACTIONAL SIZE
  # A fractional stylesheet size is rounded, not truncated, so
  # 0.9px x 100px is above the tiny threshold
  Scan File  ${RSPAMD_TESTDIR}/messages/html_tiny_pixel_sheet_fraction_ham.eml
  ...  Settings={symbols_enabled = [HTML_TINY_PIXEL_TRACKER]}
  Do Not Expect Symbol  HTML_TINY_PIXEL_TRACKER

TINY PIXEL TRACKER - IMPORTANT ZERO MINIMUM WINS
  # The minimum floor is applied after the cascade completes, so an
  # !important stylesheet zero minimum restores tiny attributes
  # raised by an inline minimum
  Scan File  ${RSPAMD_TESTDIR}/messages/html_tiny_pixel_min_zero_important_probe.eml
  ...  Settings={symbols_enabled = [HTML_TINY_PIXEL_TRACKER]}
  Expect Symbol With Score  HTML_TINY_PIXEL_TRACKER  3.0

TINY PIXEL TRACKER - LEADING DOT FRACTION
  # A fraction without a leading zero is a valid length, so bounds
  # of .5px detect the pixel they cap
  Scan File  ${RSPAMD_TESTDIR}/messages/html_tiny_pixel_leading_dot_probe.eml
  ...  Settings={symbols_enabled = [HTML_TINY_PIXEL_TRACKER]}
  Expect Symbol With Score  HTML_TINY_PIXEL_TRACKER  3.0

TINY PIXEL TRACKER - ATTACHMENT IS CONTENT
  # A message carrying an attachment is not a contentless probe,
  # even when all its text parts are short
  Scan File  ${RSPAMD_TESTDIR}/messages/html_tiny_pixel_pdf_ham.eml
  ...  Settings={symbols_enabled = [HTML_TINY_PIXEL_TRACKER]}
  Do Not Expect Symbol  HTML_TINY_PIXEL_TRACKER

TINY PIXEL TRACKER - NAMELESS ATTACHMENT IS CONTENT
  # Content-Disposition attachment without a filename marks the
  # message as carrying content too
  Scan File  ${RSPAMD_TESTDIR}/messages/html_tiny_pixel_attachment_no_name_ham.eml
  ...  Settings={symbols_enabled = [HTML_TINY_PIXEL_TRACKER]}
  Do Not Expect Symbol  HTML_TINY_PIXEL_TRACKER

TINY PIXEL TRACKER - IMPORTANT MAX FROM LOSING RULE
  # An !important maximum of a losing rule wins the cascade and its
  # flattened size replaces the winner's one, so a large image is
  # not capped by the losing bound
  Scan File  ${RSPAMD_TESTDIR}/messages/html_tiny_pixel_max_important_type_ham.eml
  ...  Settings={symbols_enabled = [HTML_TINY_PIXEL_TRACKER]}
  Do Not Expect Symbol  HTML_TINY_PIXEL_TRACKER

TINY PIXEL TRACKER - STYLESHEET FRACTIONAL AREA
  # A fractional stylesheet size is rounded up, so a 0.4px x 100px
  # image is above the tiny threshold
  Scan File  ${RSPAMD_TESTDIR}/messages/html_tiny_pixel_sheet_fraction_area_ham.eml
  ...  Settings={symbols_enabled = [HTML_TINY_PIXEL_TRACKER]}
  Do Not Expect Symbol  HTML_TINY_PIXEL_TRACKER

TINY PIXEL TRACKER - ESCAPED PAREN IN URL
  # An escaped parenthesis does not close an unquoted url, so the
  # properties after it stay inside the blanked argument
  Scan File  ${RSPAMD_TESTDIR}/messages/html_tiny_pixel_style_url_escaped_paren_ham.eml
  ...  Settings={symbols_enabled = [HTML_TINY_PIXEL_TRACKER]}
  Do Not Expect Symbol  HTML_TINY_PIXEL_TRACKER

TINY PIXEL TRACKER - IMPORTANT ZERO BEATS PERCENT MIN
  # An !important stylesheet zero minimum defeats an inline percent
  # one, so its unknown marking does not apply either
  Scan File  ${RSPAMD_TESTDIR}/messages/html_tiny_pixel_percent_min_loses_important_probe.eml
  ...  Settings={symbols_enabled = [HTML_TINY_PIXEL_TRACKER]}
  Expect Symbol With Score  HTML_TINY_PIXEL_TRACKER  3.0

TINY PIXEL TRACKER - INLINE MAX WITHOUT ATTRIBUTE DIMENSIONS
  # Inline max bounds within the tiny threshold prove the size is
  # tiny even when no attribute dimensions are known
  Scan File  ${RSPAMD_TESTDIR}/messages/html_tiny_pixel_inline_max_no_dims_probe.eml
  ...  Settings={symbols_enabled = [HTML_TINY_PIXEL_TRACKER]}
  Expect Symbol With Score  HTML_TINY_PIXEL_TRACKER  3.0

TINY PIXEL TRACKER - INLINE MAX WITH UNMATCHED SELECTOR
  # Inline max bounds apply even when the stylesheet has no rule
  # matching the image tag
  Scan File  ${RSPAMD_TESTDIR}/messages/html_tiny_pixel_inline_max_unmatched_probe.eml
  ...  Settings={symbols_enabled = [HTML_TINY_PIXEL_TRACKER]}
  Expect Symbol With Score  HTML_TINY_PIXEL_TRACKER  3.0

TINY PIXEL TRACKER - NONE MAX KEEPS TINY ATTRIBUTES
  # A stylesheet max-width/max-height none imposes no bound, so tiny
  # attribute dimensions keep the image classified as a pixel
  Scan File  ${RSPAMD_TESTDIR}/messages/html_tiny_pixel_css_max_none_probe.eml
  ...  Settings={symbols_enabled = [HTML_TINY_PIXEL_TRACKER]}
  Expect Symbol With Score  HTML_TINY_PIXEL_TRACKER  3.0

TINY PIXEL TRACKER - RELATIVE MIN-SIZE HAM
  # Font-relative minimums resolve against the inherited font size
  # and cannot raise the floor as an absolute value, so they mark
  # the size unknown instead
  Scan File  ${RSPAMD_TESTDIR}/messages/html_tiny_pixel_relative_min_ham.eml
  ...  Settings={symbols_enabled = [HTML_TINY_PIXEL_TRACKER]}
  Do Not Expect Symbol  HTML_TINY_PIXEL_TRACKER

TINY PIXEL TRACKER - URL IN TEXT PART HAM
  # A URL in a short text alternative is content: the message is not
  # contentless even if its HTML part carries only a pixel
  Scan File  ${RSPAMD_TESTDIR}/messages/html_tiny_pixel_text_url_ham.eml
  ...  Settings={symbols_enabled = [HTML_TINY_PIXEL_TRACKER]}
  Do Not Expect Symbol  HTML_TINY_PIXEL_TRACKER

TINY PIXEL TRACKER - EXPLICITLY ZERO-SIZED PIXEL
  # Explicitly zero dimensions also render nothing, so such pixels
  # must be counted as tiny external ones
  Scan File  ${RSPAMD_TESTDIR}/messages/html_tiny_pixel_zero_dims.eml
  ...  Settings={symbols_enabled = [HTML_TINY_PIXEL_TRACKER]}
  Expect Symbol With Score  HTML_TINY_PIXEL_TRACKER  3.0

TINY PIXEL TRACKER - FRACTIONAL AREA
  # The tiny check multiplies the unrounded dimensions, so a
  # 2.5px x 1.5px image of area 3.75 is detected as a pixel
  Scan File  ${RSPAMD_TESTDIR}/messages/html_tiny_pixel_fraction_area_probe.eml
  ...  Settings={symbols_enabled = [HTML_TINY_PIXEL_TRACKER]}
  Expect Symbol With Score  HTML_TINY_PIXEL_TRACKER  3.0

TINY PIXEL TRACKER - FRACTIONAL MAX AREA
  # A fractional stylesheet maximum keeps the unrounded bound, so a
  # 0.4px x 100px cap gives an area of 40 rather than a tiny one
  Scan File  ${RSPAMD_TESTDIR}/messages/html_tiny_pixel_max_fraction_area_ham.eml
  ...  Settings={symbols_enabled = [HTML_TINY_PIXEL_TRACKER]}
  Do Not Expect Symbol  HTML_TINY_PIXEL_TRACKER

TINY PIXEL TRACKER - NAMELESS BINARY PART IS CONTENT
  # A binary part without a name and a disposition carries a document
  # the text parts do not represent, so the message is not a probe
  Scan File  ${RSPAMD_TESTDIR}/messages/html_tiny_pixel_attachment_no_disposition_ham.eml
  ...  Settings={symbols_enabled = [HTML_TINY_PIXEL_TRACKER]}
  Do Not Expect Symbol  HTML_TINY_PIXEL_TRACKER

TINY PIXEL TRACKER - SHEET AREA AT THE BOUNDARY
  # The area is compared at float precision, as that is what the
  # stylesheet dimensions are stored with, so a 0.1px x 40px size
  # is the exact area of 4 and is detected
  Scan File  ${RSPAMD_TESTDIR}/messages/html_tiny_pixel_sheet_area_boundary_probe.eml
  ...  Settings={symbols_enabled = [HTML_TINY_PIXEL_TRACKER]}
  Expect Symbol With Score  HTML_TINY_PIXEL_TRACKER  3.0

TINY PIXEL TRACKER - HUGE WIDTH
  # A dimension beyond the unsigned integer range is clamped to it
  # rather than wrapping around, so the image stays large
  Scan File  ${RSPAMD_TESTDIR}/messages/html_tiny_pixel_huge_width_ham.eml
  ...  Settings={symbols_enabled = [HTML_TINY_PIXEL_TRACKER]}
  Do Not Expect Symbol  HTML_TINY_PIXEL_TRACKER

TINY PIXEL TRACKER - FONT-RELATIVE SIZE UNITS
  # Font-relative units resolve against the inherited font size, so
  # they cannot be treated as fixed pixels and mark the size unknown
  Scan File  ${RSPAMD_TESTDIR}/messages/html_tiny_pixel_relative_units_ham.eml
  ...  Settings={symbols_enabled = [HTML_TINY_PIXEL_TRACKER]}
  Do Not Expect Symbol  HTML_TINY_PIXEL_TRACKER

TINY PIXEL TRACKER - BOUND PROOF ACROSS SIDES
  # A max bound of one side proves the size tiny when multiplied by
  # a known other side, even though the bounded side itself is auto
  Scan File  ${RSPAMD_TESTDIR}/messages/html_tiny_pixel_cross_side_bound_probe.eml
  ...  Settings={symbols_enabled = [HTML_TINY_PIXEL_TRACKER]}
  Expect Symbol With Score  HTML_TINY_PIXEL_TRACKER  3.0

TINY PIXEL TRACKER - CALC SIZE IN STYLESHEET
  # A function value such as calc() cannot be resolved to an
  # absolute size, so it marks the effective size unknown rather
  # than leaving the attribute dimensions in effect
  Scan File  ${RSPAMD_TESTDIR}/messages/html_tiny_pixel_css_calc_ham.eml
  ...  Settings={symbols_enabled = [HTML_TINY_PIXEL_TRACKER]}
  Do Not Expect Symbol  HTML_TINY_PIXEL_TRACKER

TINY PIXEL TRACKER - RELATIVE UNITS IN STYLESHEET
  # Font-relative units in a stylesheet resolve against the
  # inherited font size, so they mark the size unknown instead of
  # counting as fixed pixels
  Scan File  ${RSPAMD_TESTDIR}/messages/html_tiny_pixel_sheet_relative_units_ham.eml
  ...  Settings={symbols_enabled = [HTML_TINY_PIXEL_TRACKER]}
  Do Not Expect Symbol  HTML_TINY_PIXEL_TRACKER

TINY PIXEL TRACKER - FRAGMENT SOURCE IS NOT EXTERNAL
  # A source that does not resolve to a URL, such as a same-document
  # fragment, is not an external image, so no pixel is counted
  Scan File  ${RSPAMD_TESTDIR}/messages/html_tiny_pixel_fragment_src_ham.eml
  ...  Settings={symbols_enabled = [HTML_TINY_PIXEL_TRACKER]}
  Do Not Expect Symbol  HTML_TINY_PIXEL_TRACKER

TINY PIXEL TRACKER - IMAGE AFTER THE TAGS LIMIT
  # Images past the tags limit are still counted, so a pixel parsed
  # before the limit cannot remain the only image of the message
  Scan File  ${RSPAMD_TESTDIR}/messages/html_tiny_pixel_after_tags_limit_ham.eml
  ...  Settings={symbols_enabled = [HTML_TINY_PIXEL_TRACKER]}
  Do Not Expect Symbol  HTML_TINY_PIXEL_TRACKER

TINY PIXEL TRACKER - SRCSET IMAGE AFTER THE TAGS LIMIT
  # An image with a srcset and no source counts as well, so it still
  # prevents a pixel parsed before the limit from being the only image
  Scan File  ${RSPAMD_TESTDIR}/messages/html_tiny_pixel_srcset_after_limit_ham.eml
  ...  Settings={symbols_enabled = [HTML_TINY_PIXEL_TRACKER]}
  Do Not Expect Symbol  HTML_TINY_PIXEL_TRACKER

TINY PIXEL TRACKER - RELATIVE SOURCE WITH BASE
  # A relative image source is resolved against the base url of the
  # document, as browsers do, so the pixel it points to is external
  Scan File  ${RSPAMD_TESTDIR}/messages/html_tiny_pixel_base_relative_probe.eml
  ...  Settings={symbols_enabled = [HTML_TINY_PIXEL_TRACKER]}
  Expect Symbol With Score  HTML_TINY_PIXEL_TRACKER  3.0

TINY PIXEL TRACKER - CALC MAXIMUM
  # A maximum replaced by an unresolvable calc() one is removed
  # instead of keeping the earlier bound, so a large image is not
  # capped into a pixel
  Scan File  ${RSPAMD_TESTDIR}/messages/html_tiny_pixel_max_calc_ham.eml
  ...  Settings={symbols_enabled = [HTML_TINY_PIXEL_TRACKER]}
  Do Not Expect Symbol  HTML_TINY_PIXEL_TRACKER

TINY PIXEL TRACKER - CH UNITS IN STYLESHEET
  # The ch unit is font-relative and unresolvable, so it marks the
  # size unknown instead of dropping the declaration
  Scan File  ${RSPAMD_TESTDIR}/messages/html_tiny_pixel_ch_units_ham.eml
  ...  Settings={symbols_enabled = [HTML_TINY_PIXEL_TRACKER]}
  Do Not Expect Symbol  HTML_TINY_PIXEL_TRACKER

TINY PIXEL TRACKER - INHERITED SIZE
  # The inherit keyword resolves against the parent and is
  # unresolvable here, so it marks the size unknown
  Scan File  ${RSPAMD_TESTDIR}/messages/html_tiny_pixel_inherit_ham.eml
  ...  Settings={symbols_enabled = [HTML_TINY_PIXEL_TRACKER]}
  Do Not Expect Symbol  HTML_TINY_PIXEL_TRACKER

TINY PIXEL TRACKER - PATH-RELATIVE SOURCE WITH BASE
  # A path-relative source is resolved against the directory part of
  # the base url, so the pixel it points to is external
  Scan File  ${RSPAMD_TESTDIR}/messages/html_tiny_pixel_base_path_probe.eml
  ...  Settings={symbols_enabled = [HTML_TINY_PIXEL_TRACKER]}
  Expect Symbol With Score  HTML_TINY_PIXEL_TRACKER  3.0

TINY PIXEL TRACKER - UNKNOWN VIEWPORT UNITS
  # A unit the tokeniser does not know, such as svw, is a valid
  # unresolvable size, so it marks the size unknown instead of
  # dropping the declaration
  Scan File  ${RSPAMD_TESTDIR}/messages/html_tiny_pixel_svw_units_ham.eml
  ...  Settings={symbols_enabled = [HTML_TINY_PIXEL_TRACKER]}
  Do Not Expect Symbol  HTML_TINY_PIXEL_TRACKER

TINY PIXEL TRACKER - CUSTOM PROPERTY VALUES
  # Property-looking substrings inside custom property values are
  # not declarations, so the attribute dimensions stay in effect
  Scan File  ${RSPAMD_TESTDIR}/messages/html_tiny_pixel_custom_props_ham.eml
  ...  Settings={symbols_enabled = [HTML_TINY_PIXEL_TRACKER]}
  Do Not Expect Symbol  HTML_TINY_PIXEL_TRACKER

TINY PIXEL TRACKER - CUSTOM PROPERTY VALUE WITH BRACES
  # A braced custom property value is not a declaration block
  # either, so the attribute dimensions stay in effect
  Scan File  ${RSPAMD_TESTDIR}/messages/html_tiny_pixel_custom_props_braces_ham.eml
  ...  Settings={symbols_enabled = [HTML_TINY_PIXEL_TRACKER]}
  Do Not Expect Symbol  HTML_TINY_PIXEL_TRACKER

TINY PIXEL TRACKER - BASE WITHOUT A PATH
  # A path-relative source under a base without a path resolves
  # against the root of its host, so the pixel is still external
  Scan File  ${RSPAMD_TESTDIR}/messages/html_tiny_pixel_base_nopath_probe.eml
  ...  Settings={symbols_enabled = [HTML_TINY_PIXEL_TRACKER]}
  Expect Symbol With Score  HTML_TINY_PIXEL_TRACKER  3.0

TINY PIXEL TRACKER - BASE WITH A PORT
  # The port of the base belongs to its authority and stays when a
  # relative source is resolved against it
  Scan File  ${RSPAMD_TESTDIR}/messages/html_tiny_pixel_base_port_probe.eml
  ...  Settings={symbols_enabled = [HTML_TINY_PIXEL_TRACKER]}
  Expect Symbol With Score  HTML_TINY_PIXEL_TRACKER  3.0

TINY PIXEL TRACKER - CONTAINER QUERY UNITS
  # Container query units resolve against the container and are
  # unresolvable, so they mark the size unknown instead of dropping
  # the declaration
  Scan File  ${RSPAMD_TESTDIR}/messages/html_tiny_pixel_container_units_ham.eml
  ...  Settings={symbols_enabled = [HTML_TINY_PIXEL_TRACKER]}
  Do Not Expect Symbol  HTML_TINY_PIXEL_TRACKER

TINY PIXEL TRACKER - INVALID INLINE DECLARATION
  # A number in an unknown unit is invalid CSS, which browsers drop,
  # so the attribute dimensions stay in effect and the pixel counts
  Scan File  ${RSPAMD_TESTDIR}/messages/html_tiny_pixel_invalid_inline_probe.eml
  ...  Settings={symbols_enabled = [HTML_TINY_PIXEL_TRACKER]}
  Expect Symbol With Score  HTML_TINY_PIXEL_TRACKER  3.0

TINY PIXEL TRACKER - CUSTOM PROPERTY VALUE WITH SEMICOLONS
  # Semicolons inside the braces of a custom property value do not
  # start declarations, so the attribute dimensions stay in effect
  Scan File  ${RSPAMD_TESTDIR}/messages/html_tiny_pixel_custom_props_semicolons_ham.eml
  ...  Settings={symbols_enabled = [HTML_TINY_PIXEL_TRACKER]}
  Do Not Expect Symbol  HTML_TINY_PIXEL_TRACKER

TINY PIXEL TRACKER - QUARTER-MILLIMETRE UNITS
  # The q unit is an absolute one of a quarter of a millimetre, so
  # a 1q x 1q image is a pixel of area 0.89
  Scan File  ${RSPAMD_TESTDIR}/messages/html_tiny_pixel_q_units_probe.eml
  ...  Settings={symbols_enabled = [HTML_TINY_PIXEL_TRACKER]}
  Expect Symbol With Score  HTML_TINY_PIXEL_TRACKER  3.0

TINY PIXEL TRACKER - RELATIVE INLINE UNITS
  # Font-relative units in an inline style are valid and mark the
  # size unknown, overriding the attribute dimensions
  Scan File  ${RSPAMD_TESTDIR}/messages/html_tiny_pixel_relative_inline_ham.eml
  ...  Settings={symbols_enabled = [HTML_TINY_PIXEL_TRACKER]}
  Do Not Expect Symbol  HTML_TINY_PIXEL_TRACKER

TINY PIXEL TRACKER - INVALID DECLARATION AFTER VALID
  # A declaration with an unknown unit is dropped, so the previous
  # valid one stays in effect rather than the attribute dimensions
  Scan File  ${RSPAMD_TESTDIR}/messages/html_tiny_pixel_invalid_after_valid_ham.eml
  ...  Settings={symbols_enabled = [HTML_TINY_PIXEL_TRACKER]}
  Do Not Expect Symbol  HTML_TINY_PIXEL_TRACKER

TINY PIXEL TRACKER - UPPERCASE UNITS IN STYLESHEET
  # CSS units are case-insensitive, so 100PX is a valid absolute
  # size overriding the attribute dimensions
  Scan File  ${RSPAMD_TESTDIR}/messages/html_tiny_pixel_uppercase_units_ham.eml
  ...  Settings={symbols_enabled = [HTML_TINY_PIXEL_TRACKER]}
  Do Not Expect Symbol  HTML_TINY_PIXEL_TRACKER

TINY PIXEL TRACKER - MANY DECLARATIONS
  # The style is parsed in a single pass, and the last valid
  # declaration of the property wins
  Scan File  ${RSPAMD_TESTDIR}/messages/html_tiny_pixel_many_declarations_probe.eml
  ...  Settings={symbols_enabled = [HTML_TINY_PIXEL_TRACKER]}
  Expect Symbol With Score  HTML_TINY_PIXEL_TRACKER  3.0

TINY PIXEL TRACKER - SPACE BEFORE COLON
  # Spaces are allowed between a declaration name and its colon,
  # so the sizes stay in effect
  Scan File  ${RSPAMD_TESTDIR}/messages/html_tiny_pixel_space_before_colon_ham.eml
  ...  Settings={symbols_enabled = [HTML_TINY_PIXEL_TRACKER]}
  Do Not Expect Symbol  HTML_TINY_PIXEL_TRACKER

TINY PIXEL TRACKER - SEMICOLONS INSIDE VAR
  # Semicolons inside the parentheses of a var() value do not end
  # the declaration, so the property-looking substrings inside are
  # not declarations
  Scan File  ${RSPAMD_TESTDIR}/messages/html_tiny_pixel_var_semicolons_ham.eml
  ...  Settings={symbols_enabled = [HTML_TINY_PIXEL_TRACKER]}
  Do Not Expect Symbol  HTML_TINY_PIXEL_TRACKER

TINY PIXEL TRACKER - INVALID IDENTIFIER VALUE
  # An unknown identifier is invalid CSS, so the declaration is
  # dropped and the previous valid one stays in effect
  Scan File  ${RSPAMD_TESTDIR}/messages/html_tiny_pixel_bogus_ident_probe.eml
  ...  Settings={symbols_enabled = [HTML_TINY_PIXEL_TRACKER]}
  Expect Symbol With Score  HTML_TINY_PIXEL_TRACKER  3.0

TINY PIXEL TRACKER - EXPONENTIAL NOTATION
  # A number with an exponent, such as 1e2, is a valid CSS number
  # of 100 pixels
  Scan File  ${RSPAMD_TESTDIR}/messages/html_tiny_pixel_exponent_ham.eml
  ...  Settings={symbols_enabled = [HTML_TINY_PIXEL_TRACKER]}
  Do Not Expect Symbol  HTML_TINY_PIXEL_TRACKER

TINY PIXEL TRACKER - PLUS SIGN
  # A leading plus sign is part of a valid CSS number, so the inline sizes
  # of 1 pixel override the large attribute ones
  Scan File  ${RSPAMD_TESTDIR}/messages/html_tiny_pixel_plus_sign_probe.eml
  ...  Settings={symbols_enabled = [HTML_TINY_PIXEL_TRACKER]}
  Expect Symbol With Score  HTML_TINY_PIXEL_TRACKER  3.0

TINY PIXEL TRACKER - TWO VALUES
  # Two values are invalid for a width, so the declaration is dropped and
  # the previous large width stays in effect
  Scan File  ${RSPAMD_TESTDIR}/messages/html_tiny_pixel_two_values_ham.eml
  ...  Settings={symbols_enabled = [HTML_TINY_PIXEL_TRACKER]}
  Do Not Expect Symbol  HTML_TINY_PIXEL_TRACKER

TINY PIXEL TRACKER - TWO VALUES CONTROL
  # The same message with a plain pixel size is a tracking pixel, so
  # the test above is not vacuous
  Scan File  ${RSPAMD_TESTDIR}/messages/html_tiny_pixel_two_values_plain_probe.eml
  ...  Settings={symbols_enabled = [HTML_TINY_PIXEL_TRACKER]}
  Expect Symbol With Score  HTML_TINY_PIXEL_TRACKER  3.0

TINY PIXEL TRACKER - UNKNOWN PRIORITY
  # Anything but important after an exclamation mark makes the declaration
  # invalid, so the previous large width stays in effect
  Scan File  ${RSPAMD_TESTDIR}/messages/html_tiny_pixel_bang_junk_ham.eml
  ...  Settings={symbols_enabled = [HTML_TINY_PIXEL_TRACKER]}
  Do Not Expect Symbol  HTML_TINY_PIXEL_TRACKER

TINY PIXEL TRACKER - UNKNOWN PRIORITY CONTROL
  # The same message with a plain pixel size is a tracking pixel, so
  # the test above is not vacuous
  Scan File  ${RSPAMD_TESTDIR}/messages/html_tiny_pixel_bang_junk_plain_probe.eml
  ...  Settings={symbols_enabled = [HTML_TINY_PIXEL_TRACKER]}
  Expect Symbol With Score  HTML_TINY_PIXEL_TRACKER  3.0

TINY PIXEL TRACKER - LEADING ZEROS
  # Leading zeros do not change a number, so the width is 100 pixels
  Scan File  ${RSPAMD_TESTDIR}/messages/html_tiny_pixel_leading_zeros_ham.eml
  ...  Settings={symbols_enabled = [HTML_TINY_PIXEL_TRACKER]}
  Do Not Expect Symbol  HTML_TINY_PIXEL_TRACKER

TINY PIXEL TRACKER - LEADING ZEROS CONTROL
  # The same message with a plain pixel size is a tracking pixel, so
  # the test above is not vacuous
  Scan File  ${RSPAMD_TESTDIR}/messages/html_tiny_pixel_leading_zeros_plain_probe.eml
  ...  Settings={symbols_enabled = [HTML_TINY_PIXEL_TRACKER]}
  Expect Symbol With Score  HTML_TINY_PIXEL_TRACKER  3.0

TINY PIXEL TRACKER - ESCAPED PROPERTY NAME
  # An escape in a property name is resolved, so this is a 100 pixel width
  Scan File  ${RSPAMD_TESTDIR}/messages/html_tiny_pixel_escaped_name_ham.eml
  ...  Settings={symbols_enabled = [HTML_TINY_PIXEL_TRACKER]}
  Do Not Expect Symbol  HTML_TINY_PIXEL_TRACKER

TINY PIXEL TRACKER - ESCAPED PROPERTY NAME CONTROL
  # The same message with a plain pixel size is a tracking pixel, so
  # the test above is not vacuous
  Scan File  ${RSPAMD_TESTDIR}/messages/html_tiny_pixel_escaped_name_plain_probe.eml
  ...  Settings={symbols_enabled = [HTML_TINY_PIXEL_TRACKER]}
  Expect Symbol With Score  HTML_TINY_PIXEL_TRACKER  3.0

TINY PIXEL TRACKER - ESCAPED QUOTE IN STRING
  # An escaped quote does not end a string, so the declarations inside it
  # are not declarations and the attribute sizes stay in effect
  Scan File  ${RSPAMD_TESTDIR}/messages/html_tiny_pixel_string_leak_ham.eml
  ...  Settings={symbols_enabled = [HTML_TINY_PIXEL_TRACKER]}
  Do Not Expect Symbol  HTML_TINY_PIXEL_TRACKER

TINY PIXEL TRACKER - ESCAPED QUOTE IN STRING CONTROL
  # The same message with a plain pixel size is a tracking pixel, so
  # the test above is not vacuous
  Scan File  ${RSPAMD_TESTDIR}/messages/html_tiny_pixel_string_leak_plain_probe.eml
  ...  Settings={symbols_enabled = [HTML_TINY_PIXEL_TRACKER]}
  Expect Symbol With Score  HTML_TINY_PIXEL_TRACKER  3.0

TINY PIXEL PROBE COMPOSITE - TRUE POSITIVE
  # Per-recipient tracking in Message-Id and a tracker token in the
  # body corroborate the contentless probe shape
  Scan File  ${RSPAMD_TESTDIR}/messages/html_tiny_pixel_probe.eml
  ...  Settings={symbols_enabled = [HTML_TINY_PIXEL_TRACKER, MID_CONTAINS_TO, TRACKER_ID, HTML_TINY_PIXEL_PROBE]}
  Expect Symbol  HTML_TINY_PIXEL_TRACKER
  Expect Symbol  MID_CONTAINS_TO
  Expect Symbol  TRACKER_ID
  Expect Symbol With Score  HTML_TINY_PIXEL_PROBE  3.0

TINY PIXEL PROBE COMPOSITE - BULK MARKERS ALONE DO NOT TRIGGER
  # The base rule fires and bulk headers are present, but without
  # per-recipient tracking evidence the composite must stay silent
  Scan File  ${RSPAMD_TESTDIR}/messages/html_tiny_pixel_bulk_only.eml
  ...  Settings={symbols_enabled = [HTML_TINY_PIXEL_TRACKER, MID_CONTAINS_TO, TRACKER_ID, HAS_LIST_UNSUB, PRECEDENCE_BULK, HTML_TINY_PIXEL_PROBE]}
  Expect Symbol  HTML_TINY_PIXEL_TRACKER
  Expect Symbol  HAS_LIST_UNSUB
  Expect Symbol  PRECEDENCE_BULK
  Do Not Expect Symbol  MID_CONTAINS_TO
  Do Not Expect Symbol  TRACKER_ID
  Do Not Expect Symbol  HTML_TINY_PIXEL_PROBE

*** Keywords ***
Check Hidden Content Amount
  [Arguments]  ${fixture}  ${score}  ${characters}
  Scan File  ${RSPAMD_TESTDIR}/messages/html_hidden_${fixture}.eml
  ...  Settings={symbols_enabled = [HIDDEN_TEXT]}
  Expect Symbol With Score And Exact Options  HIDDEN_TEXT  ${score}  ${characters}

Check No Significant Hidden Content
  [Arguments]  ${fixture}
  Scan File  ${RSPAMD_TESTDIR}/messages/html_hidden_${fixture}.eml
  ...  Settings={symbols_enabled = [HIDDEN_TEXT]}
  Do Not Expect Symbol  HIDDEN_TEXT

TEXT WORDS TRUNCATED - Long text
  [Documentation]  The words of a long part are a sample, and that is told
  Scan File  ${RSPAMD_TESTDIR}/messages/words_sampled.eml
  ...  Settings={symbols_enabled = [TEXT_WORDS_TRUNCATED]}
  Expect Symbol With Exact Options  TEXT_WORDS_TRUNCATED  sampled=1

TEXT WORDS TRUNCATED - Short text
  Scan File  ${RSPAMD_TESTDIR}/messages/zerofont.eml
  ...  Settings={symbols_enabled = [TEXT_WORDS_TRUNCATED]}
  Do Not Expect Symbol  TEXT_WORDS_TRUNCATED
