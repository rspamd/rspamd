include(CheckIncludeFiles)
include(CheckLibraryExists)

# Function to check for URL include support (libcurl or libfetch)
function(CheckURLIncludeSupport)
    # First try to find libfetch
    find_library(LIBFETCH_LIBRARY HINTS "${RSPAMD_SEARCH_PATH}"
            NAMES fetch PATHS PATH_SUFFIXES lib64 lib
            PATHS ${RSPAMD_DEFAULT_LIBRARY_PATHS}
            DOC "Path where the libfetch library can be found")

    if (LIBFETCH_LIBRARY)
        # Found libfetch library, now check for header
        find_file(HAVE_FETCH_H HINTS "${RSPAMD_SEARCH_PATH}"
                NAMES fetch.h
                PATH_SUFFIXES include
                PATHS ${RSPAMD_DEFAULT_INCLUDE_PATHS}
                DOC "Path to libfetch header")

        if (HAVE_FETCH_H)
            message(STATUS "Found libfetch: ${LIBFETCH_LIBRARY}")
            list(APPEND RSPAMD_REQUIRED_LIBRARIES "fetch")
            set(WITH_FETCH 1)
            set(WITH_FETCH ${WITH_FETCH} PARENT_SCOPE)
        else ()
            message(STATUS "Found libfetch library but missing fetch.h header")
        endif ()
    else ()
        # Try to find libcurl as an alternative
        ProcessPackage(CURL LIBRARY curl INCLUDE curl.h INCLUDE_SUFFIXES include/curl
                ROOT ${CURL_ROOT})

        if (WITH_CURL)
            message(STATUS "Found libcurl for URL includes")
            set(WITH_CURL ${WITH_CURL} PARENT_SCOPE)
        else ()
            message(WARNING "Neither libcurl nor libfetch were found, no support of URL includes in configuration")
        endif ()
    endif ()

    # Propagate variables to parent scope
    if (HAVE_FETCH_H)
        set(HAVE_FETCH_H ${HAVE_FETCH_H} PARENT_SCOPE)
        set(LIBFETCH_LIBRARY ${LIBFETCH_LIBRARY} PARENT_SCOPE)
    endif ()

    # Update the global RSPAMD_REQUIRED_LIBRARIES list
    if (HAVE_FETCH_H)
        set(RSPAMD_REQUIRED_LIBRARIES ${RSPAMD_REQUIRED_LIBRARIES} PARENT_SCOPE)
    endif ()
endfunction()
