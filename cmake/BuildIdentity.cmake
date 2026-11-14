# Build identity: which release tag a build descends from and how far it is.
#
# Inputs:
#   RSPAMD_VERSION, RSPAMD_RELEASE_BASE  - set in the top-level CMakeLists.txt
#   GIT_DESCRIBE (optional cache string) - "<tag>-<n>-g<hash>", for builds
#                                          from a source tarball or a shallow
#                                          clone; auto-detected otherwise
#   GIT_ID (optional)                    - build id, see RSPAMD_ID
#
# Outputs (normal variables):
#   RSPAMD_VERSION_DEV      - TRUE/FALSE
#   RSPAMD_VERSION_DEV_INT  - 1/0
#   RSPAMD_BUILD_DESCRIBE   - describe string, empty if unknown
#   RSPAMD_BUILD_DISTANCE   - commits since the release tag, empty if unknown
#   RSPAMD_BUILD_*_DEFINE   - preprocessed lines for rspamd_build_id.h.in
#   RSPAMD_ID_NUM           - at most 7 hex chars of RSPAMD_ID, for the
#                             numeric version macro only
#
# This is evaluated at configure time. The git HEAD, its branch ref,
# packed-refs and the HEAD reflog are registered as configure dependencies, so
# a new commit or checkout re-runs cmake (and refreshes rspamd_build_id.h) on
# the next build. The reflog matters once the branch ref has been packed
# (git gc / pack-refs): the next commit recreates a loose ref that was not
# known at configure time, but always appends to logs/HEAD.
# Creating a new tag on the same commit does not trigger it; re-run cmake.
# It never fails the configuration.

set(GIT_DESCRIBE "" CACHE STRING
    "Output of 'git describe --tags --long' (<tag>-<n>-g<hash>) for builds outside a full git checkout")

set(RSPAMD_BUILD_DESCRIBE "")
set(RSPAMD_BUILD_DISTANCE "")

# Version is a development one unless it equals the last release tag
if (RSPAMD_VERSION VERSION_EQUAL RSPAMD_RELEASE_BASE)
    set(RSPAMD_VERSION_DEV FALSE)
else ()
    set(RSPAMD_VERSION_DEV TRUE)
endif ()

set(_rspamd_describe_raw "${GIT_DESCRIBE}")

if (NOT _rspamd_describe_raw)
    find_package(Git QUIET)
    if (GIT_FOUND)
        execute_process(
                COMMAND "${GIT_EXECUTABLE}" rev-parse --is-shallow-repository
                WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
                OUTPUT_VARIABLE _rspamd_shallow
                OUTPUT_STRIP_TRAILING_WHITESPACE
                ERROR_QUIET
                RESULT_VARIABLE _rspamd_shallow_rc)
        # The source dir must be the top of the repository, not a subdirectory
        # of some unrelated enclosing checkout
        execute_process(
                COMMAND "${GIT_EXECUTABLE}" rev-parse --show-toplevel
                WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
                OUTPUT_VARIABLE _rspamd_toplevel
                OUTPUT_STRIP_TRAILING_WHITESPACE
                ERROR_QUIET
                RESULT_VARIABLE _rspamd_toplevel_rc)
        set(_rspamd_is_top FALSE)
        if (_rspamd_toplevel_rc EQUAL 0 AND _rspamd_toplevel)
            get_filename_component(_rspamd_toplevel_real "${_rspamd_toplevel}" REALPATH)
            get_filename_component(_rspamd_src_real "${CMAKE_SOURCE_DIR}" REALPATH)
            if (_rspamd_toplevel_real STREQUAL _rspamd_src_real)
                set(_rspamd_is_top TRUE)
            endif ()
        endif ()
        # Only a non-shallow git repository has reliable describe data
        if (_rspamd_is_top AND _rspamd_shallow_rc EQUAL 0 AND _rspamd_shallow STREQUAL "false")
            # Re-run cmake when HEAD moves. Only existing files are
            # registered. logs/HEAD is the one that changes on every
            # commit: the branch ref file disappears once refs are packed.
            set(_rspamd_dep_names HEAD packed-refs logs/HEAD)
            execute_process(
                    COMMAND "${GIT_EXECUTABLE}" symbolic-ref -q HEAD
                    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
                    OUTPUT_VARIABLE _rspamd_head_ref
                    OUTPUT_STRIP_TRAILING_WHITESPACE
                    ERROR_QUIET)
            if (_rspamd_head_ref)
                list(APPEND _rspamd_dep_names "${_rspamd_head_ref}")
            endif ()
            # 'git rev-parse --git-path' resolves per-worktree files (HEAD,
            # logs/HEAD) in the worktree git dir and shared ones (packed-refs,
            # refs/heads/*) in the common dir
            foreach (_rspamd_dep_name IN LISTS _rspamd_dep_names)
                execute_process(
                        COMMAND "${GIT_EXECUTABLE}" rev-parse --git-path "${_rspamd_dep_name}"
                        WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
                        OUTPUT_VARIABLE _rspamd_dep_path
                        OUTPUT_STRIP_TRAILING_WHITESPACE
                        ERROR_QUIET)
                if (_rspamd_dep_path)
                    if (NOT IS_ABSOLUTE "${_rspamd_dep_path}")
                        set(_rspamd_dep_path "${CMAKE_SOURCE_DIR}/${_rspamd_dep_path}")
                    endif ()
                    if (EXISTS "${_rspamd_dep_path}")
                        set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
                                "${_rspamd_dep_path}")
                    endif ()
                endif ()
            endforeach ()

            execute_process(
                    COMMAND "${GIT_EXECUTABLE}" describe --tags --long --abbrev=12
                    --match "[0-9]*.[0-9]*" --exclude "*-*"
                    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
                    OUTPUT_VARIABLE _rspamd_describe_raw
                    OUTPUT_STRIP_TRAILING_WHITESPACE
                    ERROR_QUIET
                    RESULT_VARIABLE _rspamd_describe_rc)
            if (NOT _rspamd_describe_rc EQUAL 0)
                set(_rspamd_describe_raw "")
            endif ()
        endif ()
    endif ()
endif ()

set(_rspamd_have_git_info FALSE)
if (_rspamd_describe_raw)
    set(_rspamd_have_git_info TRUE)
    if (_rspamd_describe_raw MATCHES "^([0-9]+\\.[0-9]+\\.[0-9]+)-([0-9]+)-g([0-9a-f]+)$")
        set(_rspamd_describe_tag "${CMAKE_MATCH_1}")
        set(_rspamd_describe_dist "${CMAKE_MATCH_2}")
        if (_rspamd_describe_tag VERSION_EQUAL RSPAMD_RELEASE_BASE)
            set(RSPAMD_BUILD_DESCRIBE "${_rspamd_describe_raw}")
            set(RSPAMD_BUILD_DISTANCE "${_rspamd_describe_dist}")
            # A release commit that is not exactly at the tag is not a release
            if (NOT RSPAMD_VERSION_DEV AND RSPAMD_BUILD_DISTANCE GREATER 0)
                set(RSPAMD_VERSION_DEV TRUE)
            endif ()
        else ()
            message(WARNING "git describe tag ${_rspamd_describe_tag} does not match "
                    "RSPAMD_RELEASE_BASE ${RSPAMD_RELEASE_BASE}; build distance is unknown")
        endif ()
    else ()
        message(WARNING "Cannot parse git describe output '${_rspamd_describe_raw}'; "
                "build distance is unknown")
    endif ()
endif ()

if (RSPAMD_VERSION_DEV)
    set(RSPAMD_VERSION_DEV_INT 1)
else ()
    set(RSPAMD_VERSION_DEV_INT 0)
endif ()

# Lines for rspamd_build_id.h.in (a distance of 0 must stay defined, so
# #cmakedefine cannot be used)
if (RSPAMD_BUILD_DESCRIBE)
    set(RSPAMD_BUILD_DESCRIBE_DEFINE "#define RSPAMD_GIT_DESCRIBE \"${RSPAMD_BUILD_DESCRIBE}\"")
    set(RSPAMD_BUILD_DISTANCE_DEFINE "#define RSPAMD_GIT_DISTANCE ${RSPAMD_BUILD_DISTANCE}")
elseif (NOT RSPAMD_VERSION_DEV AND NOT _rspamd_have_git_info)
    # An exact release with no git information at all (a tarball) is at its
    # release tag. If git information exists but is unusable (names another
    # tag, cannot be parsed), the distance stays unknown.
    set(RSPAMD_BUILD_DESCRIBE_DEFINE "/* RSPAMD_GIT_DESCRIBE is unknown */")
    set(RSPAMD_BUILD_DISTANCE_DEFINE "#define RSPAMD_GIT_DISTANCE 0")
else ()
    set(RSPAMD_BUILD_DESCRIBE_DEFINE "/* RSPAMD_GIT_DESCRIBE is unknown */")
    set(RSPAMD_BUILD_DISTANCE_DEFINE "/* RSPAMD_GIT_DISTANCE is unknown */")
endif ()

# Numeric version macro: 0x<major><minor>00<id> must fit 64 bits, so use at
# most the first 7 hex characters of the build id there (RID keeps it all)
set(RSPAMD_ID_NUM "")
if (RSPAMD_ID)
    if (RSPAMD_ID MATCHES "^[0-9a-fA-F]+$")
        # 7 chars (as git's short hash) keep the value below 2^53, exact
        # as a double under LuaJIT
        string(SUBSTRING "${RSPAMD_ID}" 0 7 RSPAMD_ID_NUM)
    else ()
        message(WARNING "GIT_ID '${RSPAMD_ID}' is not a hex string; "
                "using zeros in the numeric version")
        set(RSPAMD_ID_NUM "0000000")
    endif ()
endif ()

message(STATUS "Build identity: release base ${RSPAMD_RELEASE_BASE}, "
        "dev=${RSPAMD_VERSION_DEV}, describe='${RSPAMD_BUILD_DESCRIBE}', "
        "distance='${RSPAMD_BUILD_DISTANCE}'")
