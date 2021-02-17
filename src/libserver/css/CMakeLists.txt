SET(RAGEL_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/css_syntax.rl")
RAGEL_TARGET(ragel_css_selector_parser
        INPUTS ${CMAKE_CURRENT_SOURCE_DIR}/css_selector_parser.rl
        DEPENDS ${RAGEL_DEPENDS}
        COMPILE_FLAGS -G2
        OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/css_selector_parser.rl.cxx)
RAGEL_TARGET(ragel_css_rule_parser
        INPUTS ${CMAKE_CURRENT_SOURCE_DIR}/css_rule_parser.rl
        DEPENDS ${RAGEL_DEPENDS}
        COMPILE_FLAGS -G2
        OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/css_rule_parser.rl.cxx)

SET(LIBCSSSRC    "${CMAKE_CURRENT_SOURCE_DIR}/css.cxx"
                 "${CMAKE_CURRENT_SOURCE_DIR}/css_property.cxx"
                 "${CMAKE_CURRENT_SOURCE_DIR}/css_value.cxx"
                 "${CMAKE_CURRENT_SOURCE_DIR}/css_selector.cxx"
                 "${CMAKE_CURRENT_SOURCE_DIR}/css_tokeniser.cxx"
                 "${CMAKE_CURRENT_SOURCE_DIR}/css_util.cxx"
                 "${CMAKE_CURRENT_SOURCE_DIR}/css_rule.cxx"
                 "${CMAKE_CURRENT_SOURCE_DIR}/css_parser.cxx"
                 "${RAGEL_ragel_css_selector_parser_OUTPUTS}"
                 "${RAGEL_ragel_css_rule_parser_OUTPUTS}"
                 PARENT_SCOPE)
SET(LIBCSS_DEPENDS "ragel_css_selector_parser;ragel_css_rule_parser" PARENT_SCOPE)
SET(LIBCSS_GENERATED
        "${RAGEL_ragel_css_selector_parser_OUTPUTS};${RAGEL_ragel_css_rule_parser_OUTPUTS}" PARENT_SCOPE)