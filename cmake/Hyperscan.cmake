option (ENABLE_HYPERSCAN    "Enable hyperscan for fast regexp processing [default: OFF]" OFF)

if (ENABLE_HYPERSCAN MATCHES "ON")
    ProcessPackage (HYPERSCAN LIBRARY hs INCLUDE hs.h INCLUDE_SUFFIXES
            hs include/hs
            ROOT ${HYPERSCAN_ROOT_DIR} MODULES libhs)
    set (WITH_HYPERSCAN 1)

    # For static linking with Hyperscan we need to link using CXX
    if (ENABLE_HYPERSCAN MATCHES "ON")
        if (${HYPERSCAN_LIBRARY} MATCHES ".*[.]a$" OR STATIC_HYPERSCAN)
            enable_language (CXX)
        endif ()
    endif ()
endif ()
