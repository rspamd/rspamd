/*-
 * Copyright 2016 Vsevolod Stakhov
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef SRC_LIBSERVER_HTML_TAGS_H_
#define SRC_LIBSERVER_HTML_TAGS_H_

#ifdef  __cplusplus
extern "C" {
#endif

/* Known HTML tags */
typedef enum {
	Tag_UNKNOWN, /**< Unknown tag! */
	Tag_A,      /**< A */
	Tag_ABBR,   /**< ABBR */
	Tag_ACRONYM, /**< ACRONYM */
	Tag_ADDRESS, /**< ADDRESS */
	Tag_ALIGN,  /**< ALIGN */
	Tag_APPLET, /**< APPLET */
	Tag_AREA,   /**< AREA */
	Tag_B,      /**< B */
	Tag_BASE,   /**< BASE */
	Tag_BASEFONT, /**< BASEFONT */
	Tag_BDO,    /**< BDO */
	Tag_BGSOUND, /**< BGSOUND */
	Tag_BIG,    /**< BIG */
	Tag_BLINK,  /**< BLINK */
	Tag_BLOCKQUOTE, /**< BLOCKQUOTE */
	Tag_BODY,   /**< BODY */
	Tag_BR,     /**< BR */
	Tag_BUTTON, /**< BUTTON */
	Tag_CAPTION, /**< CAPTION */
	Tag_CENTER, /**< CENTER */
	Tag_CITE,   /**< CITE */
	Tag_CODE,   /**< CODE */
	Tag_COL,    /**< COL */
	Tag_COLGROUP, /**< COLGROUP */
	Tag_COMMENT, /**< COMMENT */
	Tag_DD,     /**< DD */
	Tag_DEL,    /**< DEL */
	Tag_DFN,    /**< DFN */
	Tag_DIR,    /**< DIR */
	Tag_DIV,    /**< DIF */
	Tag_DL,     /**< DL */
	Tag_DT,     /**< DT */
	Tag_EM,     /**< EM */
	Tag_EMBED,  /**< EMBED */
	Tag_FIELDSET, /**< FIELDSET */
	Tag_FONT,   /**< FONT */
	Tag_FORM,   /**< FORM */
	Tag_FRAME,  /**< FRAME */
	Tag_FRAMESET, /**< FRAMESET */
	Tag_H1,     /**< H1 */
	Tag_H2,     /**< H2 */
	Tag_H3,     /**< H3 */
	Tag_H4,     /**< H4 */
	Tag_H5,     /**< H5 */
	Tag_H6,     /**< H6 */
	Tag_HEAD,   /**< HEAD */
	Tag_HR,     /**< HR */
	Tag_HTML,   /**< HTML */
	Tag_I,      /**< I */
	Tag_IFRAME, /**< IFRAME */
	Tag_ILAYER, /**< ILAYER */
	Tag_IMG,    /**< IMG */
	Tag_INPUT,  /**< INPUT */
	Tag_INS,    /**< INS */
	Tag_ISINDEX, /**< ISINDEX */
	Tag_KBD,    /**< KBD */
	Tag_KEYGEN, /**< KEYGEN */
	Tag_LABEL,  /**< LABEL */
	Tag_LAYER,  /**< LAYER */
	Tag_LEGEND, /**< LEGEND */
	Tag_LI,     /**< LI */
	Tag_LINK,   /**< LINK */
	Tag_LISTING, /**< LISTING */
	Tag_MAP,    /**< MAP */
	Tag_MARQUEE, /**< MARQUEE */
	Tag_MENU,   /**< MENU */
	Tag_META,   /**< META */
	Tag_MULTICOL, /**< MULTICOL */
	Tag_NOBR,   /**< NOBR */
	Tag_NOEMBED, /**< NOEMBED */
	Tag_NOFRAMES, /**< NOFRAMES */
	Tag_NOLAYER, /**< NOLAYER */
	Tag_NOSAVE, /**< NOSAVE */
	Tag_NOSCRIPT, /**< NOSCRIPT */
	Tag_OBJECT, /**< OBJECT */
	Tag_OL,     /**< OL */
	Tag_OPTGROUP, /**< OPTGROUP */
	Tag_OPTION, /**< OPTION */
	Tag_P,      /**< P */
	Tag_PARAM,  /**< PARAM */
	Tag_PLAINTEXT, /**< PLAINTEXT */
	Tag_PRE,    /**< PRE */
	Tag_Q,      /**< Q */
	Tag_RB,     /**< RB */
	Tag_RBC,    /**< RBC */
	Tag_RP,     /**< RP */
	Tag_RT,     /**< RT */
	Tag_RTC,    /**< RTC */
	Tag_RUBY,   /**< RUBY */
	Tag_S,      /**< S */
	Tag_SAMP,   /**< SAMP */
	Tag_SCRIPT, /**< SCRIPT */
	Tag_SELECT, /**< SELECT */
	Tag_SERVER, /**< SERVER */
	Tag_SERVLET, /**< SERVLET */
	Tag_SMALL,  /**< SMALL */
	Tag_SPACER, /**< SPACER */
	Tag_SPAN,   /**< SPAN */
	Tag_STRIKE, /**< STRIKE */
	Tag_STRONG, /**< STRONG */
	Tag_STYLE,  /**< STYLE */
	Tag_SUB,    /**< SUB */
	Tag_SUP,    /**< SUP */
	Tag_TABLE,  /**< TABLE */
	Tag_TBODY,  /**< TBODY */
	Tag_TD,     /**< TD */
	Tag_TEXTAREA, /**< TEXTAREA */
	Tag_TFOOT,  /**< TFOOT */
	Tag_TH,     /**< TH */
	Tag_THEAD,  /**< THEAD */
	Tag_TITLE,  /**< TITLE */
	Tag_TR,     /**< TR */
	Tag_TT,     /**< TT */
	Tag_U,      /**< U */
	Tag_UL,     /**< UL */
	Tag_VAR,    /**< VAR */
	Tag_WBR,    /**< WBR */
	Tag_XMP,    /**< XMP */
	Tag_XML,    /**< XML */
	Tag_NEXTID, /**< NEXTID */

	N_TAGS      /**< Must be last */
} tag_id_t;

#define CM_UNKNOWN      0
/* Elements with no content. Map to HTML specification. */
#define CM_EMPTY        (1 << 0)
/* Elements that appear outside of "BODY". */
#define CM_HTML         (1 << 1)
/* Elements that can appear within HEAD. */
#define CM_HEAD         (1 << 2)
/* HTML "block" elements. */
#define CM_BLOCK        (1 << 3)
/* HTML "inline" elements. */
#define CM_INLINE       (1 << 4)
/* Elements that mark list item ("LI"). */
#define CM_LIST         (1 << 5)
/* Elements that mark definition list item ("DL", "DT"). */
#define CM_DEFLIST      (1 << 6)
/* Elements that can appear inside TABLE. */
#define CM_TABLE        (1 << 7)
/* Used for "THEAD", "TFOOT" or "TBODY". */
#define CM_ROWGRP       (1 << 8)
/* Used for "TD", "TH" */
#define CM_ROW          (1 << 9)
/* Elements whose content must be protected against white space movement.
   Includes some elements that can found in forms. */
#define CM_FIELD        (1 << 10)
/* Used to avoid propagating inline emphasis inside some elements
   such as OBJECT or APPLET. */
#define CM_OBJECT       (1 << 11)
/* Elements that allows "PARAM". */
#define CM_PARAM        (1 << 12)
/* "FRAME", "FRAMESET", "NOFRAMES". Used in ParseFrameSet. */
#define CM_FRAMES       (1 << 13)
/* Heading elements (h1, h2, ...). */
#define CM_HEADING      (1 << 14)
/* Elements with an optional end tag. */
#define CM_OPT          (1 << 15)
/* Elements that use "align" attribute for vertical position. */
#define CM_IMG          (1 << 16)
/* Elements with inline and block model. Used to avoid calling InlineDup. */
#define CM_MIXED        (1 << 17)
/* Elements whose content needs to be indented only if containing one
   CM_BLOCK element. */
#define CM_NO_INDENT    (1 << 18)
/* Elements that are obsolete (such as "dir", "menu"). */
#define CM_OBSOLETE     (1 << 19)
/* User defined elements. Used to determine how attributes without value
   should be printed. */
#define CM_NEW          (1 << 20)
/* Elements that cannot be omitted. */
#define CM_OMITST       (1 << 21)
/* Unique elements */
#define CM_UNIQUE       (1 << 22)

#ifdef  __cplusplus
}
#endif

#endif /* SRC_LIBSERVER_HTML_TAGS_H_ */
