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
	Tag_UNKNOWN = 0, /**< Unknown tag! */
	Tag_A,      /**< A */
	Tag_ABBR,   /**< ABBR */
	Tag_ACRONYM, /**< ACRONYM */
	Tag_ADDRESS, /**< ADDRESS */
	Tag_APPLET, /**< APPLET */
	Tag_AREA,   /**< AREA */
	Tag_B,      /**< B */
	Tag_BASE,   /**< BASE */
	Tag_BASEFONT, /**< BASEFONT */
	Tag_BDO,    /**< BDO */
	Tag_BIG,    /**< BIG */
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
	Tag_DD,     /**< DD */
	Tag_DEL,    /**< DEL */
	Tag_DFN,    /**< DFN */
	Tag_DIR,    /**< DIR */
	Tag_DIV,    /**< DIF */
	Tag_DL,     /**< DL */
	Tag_DT,     /**< DT */
	Tag_EM,     /**< EM */
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
	Tag_IMG,    /**< IMG */
	Tag_INPUT,  /**< INPUT */
	Tag_INS,    /**< INS */
	Tag_ISINDEX, /**< ISINDEX */
	Tag_KBD,    /**< KBD */
	Tag_KEYGEN, /**< KEYGEN */
	Tag_LABEL,  /**< LABEL */
	Tag_LEGEND, /**< LEGEND */
	Tag_LI,     /**< LI */
	Tag_LINK,   /**< LINK */
	Tag_LISTING, /**< LISTING */
	Tag_MAP,    /**< MAP */
	Tag_MENU,   /**< MENU */
	Tag_META,   /**< META */
	Tag_NOFRAMES, /**< NOFRAMES */
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
	Tag_SMALL,  /**< SMALL */
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
	Tag_XMP,    /**< XMP */
	Tag_NEXTID, /**< NEXTID */
	Tag_MAX,

	N_TAGS  = -1 /**< Must be -1 */
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
#define CM_RAW          (1 << 11)
/* Elements that allows "PARAM". */
#define CM_PARAM        (1 << 12)
/* Elements with an optional end tag. */
#define CM_OPT          (1 << 13)
/* Elements that use "align" attribute for vertical position. */
#define CM_IMG          (1 << 14)
#define CM_NO_INDENT    (1 << 15)
/* Elements that cannot be omitted. */
#define CM_OMITST       (1 << 16)
/* Unique elements */
#define CM_UNIQUE       (1 << 17)

#define CM_USER_SHIFT   (18)

#ifdef  __cplusplus
}
#endif

#endif /* SRC_LIBSERVER_HTML_TAGS_H_ */
