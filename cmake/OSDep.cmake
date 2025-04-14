# OSDep.cmake - Platform-specific configuration as a function

function(ConfigurePlatformSpecifics)
    # Configure for BSD systems
    if (CMAKE_SYSTEM_NAME MATCHES "^.*BSD$|DragonFly")
        # Add BSD-specific compiler flags
        add_compile_definitions(FREEBSD _BSD_SOURCE)
        set(CMAKE_REQUIRED_DEFINITIONS "${CMAKE_REQUIRED_DEFINITIONS} -D_BSD_SOURCE" PARENT_SCOPE)

        # Configure FreeBSD startup script
        configure_file(freebsd/rspamd.sh.in freebsd/rspamd @ONLY)
        message(STATUS "Configuring for BSD system")

        # Find util library
        ProcessPackage(LIBUTIL LIBRARY util INCLUDE libutil.h
                ROOT ${LIBUTIL_ROOT_DIR} OPTIONAL)

        if (WITH_LIBUTIL)
            set(HAVE_LIBUTIL_H 1)
            list(APPEND CMAKE_REQUIRED_LIBRARIES util)
            list(APPEND RSPAMD_REQUIRED_LIBRARIES util)

            # Check for pidfile functions
            check_function_exists(pidfile_open HAVE_PIDFILE)
            check_function_exists(pidfile_fileno HAVE_PIDFILE_FILENO)

            # Propagate variables to parent scope
            set(HAVE_PIDFILE ${HAVE_PIDFILE} PARENT_SCOPE)
            set(HAVE_PIDFILE_FILENO ${HAVE_PIDFILE_FILENO} PARENT_SCOPE)
            set(HAVE_LIBUTIL_H ${HAVE_LIBUTIL_H} PARENT_SCOPE)
        endif ()

        # NetBSD-specific libraries
        if (CMAKE_SYSTEM_NAME MATCHES "^NetBSD$")
            list(APPEND CMAKE_REQUIRED_LIBRARIES rt)
            list(APPEND RSPAMD_REQUIRED_LIBRARIES rt)
        endif ()

        set(TAR "gtar" PARENT_SCOPE)
    endif ()

    # Configure for macOS (Darwin)
    if (CMAKE_SYSTEM_NAME STREQUAL "Darwin")
        # Add macOS-specific compiler flags
        add_compile_definitions(_BSD_SOURCE DARWIN)

        # Configure dynamic linking behavior
        set(CMAKE_SHARED_LIBRARY_CREATE_C_FLAGS "${CMAKE_SHARED_LIBRARY_CREATE_C_FLAGS} -undefined dynamic_lookup" PARENT_SCOPE)

        # Special handling for LUAJIT on x86_64 macOS
        if (ENABLE_LUAJIT AND "${ARCH}" STREQUAL "x86_64")
            set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -pagezero_size 10000 -image_base 100000000" PARENT_SCOPE)
        endif ()

        message(STATUS "Configuring for Darwin")
        set(TAR "gnutar" PARENT_SCOPE)
        set(CMAKE_FIND_FRAMEWORK "NEVER" PARENT_SCOPE)
    endif ()

    # Configure for Linux systems
    if (CMAKE_SYSTEM_NAME STREQUAL "Linux")
        # Add Linux-specific compiler flags
        add_compile_definitions(_GNU_SOURCE LINUX)
        set(CMAKE_REQUIRED_DEFINITIONS "${CMAKE_REQUIRED_DEFINITIONS} -D_GNU_SOURCE" PARENT_SCOPE)

        # Required Linux libraries
        set(LINUX_REQUIRED_LIBS dl rt resolv)
        foreach (lib ${LINUX_REQUIRED_LIBS})
            list(APPEND CMAKE_REQUIRED_LIBRARIES ${lib})
            list(APPEND RSPAMD_REQUIRED_LIBRARIES ${lib})
        endforeach ()

        message(STATUS "Configuring for Linux")

        # Determine init script based on distribution
        if (EXISTS "/etc/debian_version")
            set(LINUX_START_SCRIPT "rspamd_debian.in" PARENT_SCOPE)
        else ()
            set(LINUX_START_SCRIPT "rspamd_rh.in" PARENT_SCOPE)
        endif ()
    endif ()

    # Configure for Solaris systems
    if (CMAKE_SYSTEM_NAME STREQUAL "SunOS")
        # Add Solaris-specific compiler flags
        add_compile_definitions(__EXTENSIONS__ SOLARIS _POSIX_SOURCE _POSIX_C_SOURCE=200112)

        # Required Solaris libraries
        set(SOLARIS_REQUIRED_LIBS rt dl resolv nsl socket umem)
        foreach (lib ${SOLARIS_REQUIRED_LIBS})
            list(APPEND CMAKE_REQUIRED_LIBRARIES ${lib})
            list(APPEND RSPAMD_REQUIRED_LIBRARIES ${lib})
        endforeach ()

        # Configure Solaris-specific build settings
        set(CMAKE_VERBOSE_MAKEFILE ON PARENT_SCOPE)
        set(CMAKE_INSTALL_RPATH_USE_LINK_PATH FALSE PARENT_SCOPE)
        set(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/lib:${RSPAMD_LIBDIR}" PARENT_SCOPE)
    endif ()

    # Always propagate required libraries to parent scope
    set(RSPAMD_REQUIRED_LIBRARIES ${RSPAMD_REQUIRED_LIBRARIES} PARENT_SCOPE)
    set(CMAKE_REQUIRED_LIBRARIES ${CMAKE_REQUIRED_LIBRARIES} PARENT_SCOPE)

    # Log platform-specific configuration
    message(STATUS "Platform: ${CMAKE_SYSTEM_NAME}")
    message(STATUS "Platform-specific required libraries: ${RSPAMD_REQUIRED_LIBRARIES}")
endfunction()
