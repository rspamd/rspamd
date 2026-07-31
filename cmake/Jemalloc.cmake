# jemalloc integration.
#
# The allocator must exist exactly once in the process image. Every copy keeps its
# own arenas and extent map, so a chunk obtained from one copy and handed to
# another one is not recognised and crashes inside jemalloc instead of being freed
# (issue #6153). Keeping that true in a shared build needs two properties:
#
#  * Only the *shared* libjemalloc may be linked. Debian's libjemalloc-dev also
#    ships libjemalloc_pic.a, and searching for "jemalloc_pic" ahead of "jemalloc"
#    used to prefer it, which embedded a complete private allocator into every
#    single rspamd shared object.
#
#  * libjemalloc must be a direct dependency of each executable so that it
#    precedes libc in the dynamic linker's global lookup scope, which is built
#    breadth-first. Reaching it only through librspamd-server puts it one level
#    too deep and libc wins the lookup for malloc(). rspamd binaries reference no
#    jemalloc symbol of their own, so --as-needed (a Debian and Ubuntu default)
#    would also drop the DT_NEEDED entry outright, silently leaving the process on
#    the system allocator.
#
# Ordering matters as well: librspamd-server must come *before* libjemalloc in a
# binary's DT_NEEDED list. Both define malloc_conf (see libserver/allocator_conf.c)
# and the dynamic linker takes the first definition it finds in the scope,
# regardless of weak versus global binding. RspamdLinkJemalloc() must therefore be
# called after the target has been linked against rspamd-server.
#
# A fully static build has no shared objects at all, so the static archive is both
# required and safe there.

if (ENABLE_JEMALLOC AND NOT SANITIZE)
    ProcessPackage(JEMALLOC LIBRARY jemalloc INCLUDE jemalloc/jemalloc.h
            ROOT ${JEMALLOC_ROOT_DIR} LIB_OUTPUT JEMALLOC_LIBRARIES)
    set(WITH_JEMALLOC "1")

    if (NOT BUILD_STATIC)
        foreach (_jemalloc_lib IN LISTS JEMALLOC_LIBRARIES)
            if (_jemalloc_lib MATCHES "\\${CMAKE_STATIC_LIBRARY_SUFFIX}$")
                message(FATAL_ERROR
                        "Found a static jemalloc (${_jemalloc_lib}), but a shared build of rspamd "
                        "requires the shared library: a static allocator is duplicated into every "
                        "rspamd shared object, and memory allocated through one copy cannot be "
                        "released through another one. Install the shared libjemalloc, point "
                        "JEMALLOC_ROOT_DIR at it, or configure with -DENABLE_JEMALLOC=OFF.")
            endif ()
        endforeach ()

        # --push-state/--pop-state is GNU ld >= 2.25, gold and lld; ld64 has neither.
        include(CheckCSourceCompiles)
        set(CMAKE_REQUIRED_LINK_OPTIONS "-Wl,--push-state,--no-as-needed" "-Wl,--pop-state")
        check_c_source_compiles("int main(void) { return 0; }" LINKER_HAS_PUSH_STATE)
        unset(CMAKE_REQUIRED_LINK_OPTIONS)
    endif ()
else ()
    unset(WITH_JEMALLOC)
    unset(WITH_JEMALLOC CACHE)
    set(JEMALLOC_LIBRARIES "")
endif ()

# Link a target against jemalloc, pinning the DT_NEEDED entry against --as-needed.
# Call this *after* the target has been linked against rspamd-server.
function(RspamdLinkJemalloc TARGET)
    if (NOT WITH_JEMALLOC)
        return()
    endif ()

    if (LINKER_HAS_PUSH_STATE)
        target_link_libraries(${TARGET} PRIVATE
                "-Wl,--push-state,--no-as-needed"
                ${JEMALLOC_LIBRARIES}
                "-Wl,--pop-state")
    else ()
        target_link_libraries(${TARGET} PRIVATE ${JEMALLOC_LIBRARIES})
    endif ()
endfunction()
