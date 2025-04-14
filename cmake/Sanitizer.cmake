# Sanitizer configuration
# Ported from Clickhouse: https://github.com/ClickHouse/ClickHouse/blob/master/cmake/sanitize.cmake

# Define a function to configure sanitizers
function(configure_sanitizers)
    # Skip configuration if no sanitizer is specified
    if (NOT SANITIZE)
        return()
    endif ()

    # Base sanitizer flags
    add_compile_options(-g -fno-omit-frame-pointer)
    add_compile_definitions(SANITIZER)

    # Set optimization level based on compiler and debug settings
    if (CMAKE_C_COMPILER_ID MATCHES "GNU")
        if (ENABLE_FULL_DEBUG)
            add_compile_options(-O0)
        else ()
            add_compile_options(-Og)
        endif ()
    else ()
        if (ENABLE_FULL_DEBUG)
            add_compile_options(-O0)
        else ()
            add_compile_options(-O1)
        endif ()
    endif ()

    # Jemalloc conflicts with sanitizers
    if (ENABLE_JEMALLOC)
        message(STATUS "Disabling jemalloc as it's incompatible with sanitizers")
        set(ENABLE_JEMALLOC OFF PARENT_SCOPE)
    endif ()

    # Process the specified sanitizers
    string(REPLACE "," ";" SANITIZE_LIST "${SANITIZE}")

    foreach (SANITIZER_TYPE IN LISTS SANITIZE_LIST)
        if (SANITIZER_TYPE STREQUAL "address")
            # Address Sanitizer (ASan)
            add_compile_options(-fsanitize=address -fsanitize-address-use-after-scope)
            add_link_options(-fsanitize=address -fsanitize-address-use-after-scope)

            if (CMAKE_C_COMPILER_ID MATCHES "GNU")
                add_compile_options(-static-libasan)
                add_link_options(-static-libasan)
            endif ()

        elseif (SANITIZER_TYPE STREQUAL "leak")
            # Leak Sanitizer (LSan)
            add_compile_options(-fsanitize=leak)
            add_link_options(-fsanitize=leak)

        elseif (SANITIZER_TYPE STREQUAL "memory")
            # Memory Sanitizer (MSan)
            add_compile_options(
                    -fsanitize=memory
                    -fsanitize-memory-track-origins
                    -fno-optimize-sibling-calls
            )
            add_link_options(-fsanitize=memory)

            if (CMAKE_C_COMPILER_ID MATCHES "GNU")
                add_compile_options(-static-libmsan)
                add_link_options(-static-libmsan)
            endif ()

        elseif (SANITIZER_TYPE STREQUAL "undefined")
            # Undefined Behavior Sanitizer (UBSan)
            add_compile_options(-fsanitize=undefined -fno-sanitize-recover=all)
            add_link_options(-fsanitize=undefined)

            if (CMAKE_C_COMPILER_ID MATCHES "GNU")
                add_compile_options(-static-libubsan)
                add_link_options(-static-libubsan)
            endif ()

        else ()
            message(FATAL_ERROR "Unknown sanitizer type: ${SANITIZER_TYPE}")
        endif ()

        message(STATUS "Configured sanitizer: ${SANITIZER_TYPE}")
    endforeach ()

    # Set environment variable to disable leak detection during the build phase
    set(ENV{ASAN_OPTIONS} "detect_leaks=0")

    # Log the final configuration
    get_directory_property(COMPILE_OPTIONS COMPILE_OPTIONS)
    get_directory_property(LINK_OPTIONS LINK_OPTIONS)
    message(STATUS "Sanitizer compile options: ${COMPILE_OPTIONS}")
    message(STATUS "Sanitizer link options: ${LINK_OPTIONS}")

    # Propagate the modified variable to parent scope
    set(ENABLE_JEMALLOC ${ENABLE_JEMALLOC} PARENT_SCOPE)
endfunction()

# Execute the configuration
configure_sanitizers()
