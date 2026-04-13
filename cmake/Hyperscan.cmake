option (ENABLE_HYPERSCAN    "Enable hyperscan for fast regexp processing [default: OFF]" OFF)

if (ENABLE_HYPERSCAN MATCHES "ON")
    ProcessPackage (HYPERSCAN LIBRARY hs INCLUDE hs.h INCLUDE_SUFFIXES
            hs include/hs
            ROOT ${HYPERSCAN_ROOT_DIR} MODULES libhs)
    set (WITH_HYPERSCAN 1)
else ()
    unset (WITH_HYPERSCAN)
    unset (WITH_HYPERSCAN CACHE)
endif ()
