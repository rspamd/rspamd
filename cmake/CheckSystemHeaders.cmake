# CheckSystemHeaders.cmake
# Checks for the existence of system headers

# Check platform specific includes
function(CheckSystemHeaders)
    # Basic system headers
    check_include_files(sys/types.h HAVE_SYS_TYPES_H)
    check_include_files(sys/uio.h HAVE_SYS_UIO_H)

    # Standard C headers
    check_include_files(fcntl.h HAVE_FCNTL_H)
    check_include_files(math.h HAVE_MATH_H)
    check_include_files(stdio.h HAVE_STDIO_H)
    check_include_files(stdlib.h HAVE_STDLIB_H)
    check_include_files(string.h HAVE_STRING_H)
    check_include_files(strings.h HAVE_STRINGS_H)
    check_include_files(time.h HAVE_TIME_H)
    check_include_files(unistd.h HAVE_UNISTD_H)

    # Data type headers
    check_include_files(stdint.h HAVE_STDINT_H)
    check_include_files(inttypes.h HAVE_INTTYPES_H)
    check_include_files(stdbool.h HAVE_STDBOOL_H)

    # Endian-related headers
    check_include_files(endian.h HAVE_ENDIAN_H)
    check_include_files(sys/endian.h HAVE_SYS_ENDIAN_H)
    check_include_files(machine/endian.h HAVE_MACHINE_ENDIAN_H)

    # System utility headers
    check_include_files(sys/socket.h HAVE_SYS_SOCKET_H)
    check_include_files(sys/mman.h HAVE_SYS_MMAN_H)
    check_include_files(sys/un.h HAVE_SYS_UN_H)
    check_include_files(sys/stat.h HAVE_SYS_STAT_H)
    check_include_files(sys/wait.h HAVE_SYS_WAIT_H)
    check_include_files(sys/param.h HAVE_SYS_PARAM_H)
    check_include_files(sys/file.h HAVE_SYS_FILE_H)
    check_include_files(sys/resource.h HAVE_SYS_RESOURCE_H)

    # Network-related headers
    check_include_files(netinet/in.h HAVE_NETINET_IN_H)
    check_include_files(netinet/tcp.h HAVE_NETINET_TCP_H)
    check_include_files(arpa/inet.h HAVE_ARPA_INET_H)
    check_include_files(netdb.h HAVE_NETDB_H)

    # System logging and signal handling
    check_include_files(syslog.h HAVE_SYSLOG_H)
    check_include_files(siginfo.h HAVE_SIGINFO_H)

    # Internationalization and user/groups
    check_include_files(locale.h HAVE_LOCALE_H)
    check_include_files(libgen.h HAVE_LIBGEN_H)
    check_include_files(pwd.h HAVE_PWD_H)
    check_include_files(grp.h HAVE_GRP_H)

    # File and path handling
    check_include_files(glob.h HAVE_GLOB_H)
    check_include_files(poll.h HAVE_POLL_H)
    check_include_files(readpassphrase.h HAVE_READPASSPHRASE_H)
    check_include_files(termios.h HAVE_TERMIOS_H)
    check_include_files(paths.h HAVE_PATHS_H)

    # Other utilities
    check_include_files(ctype.h HAVE_CTYPE_H)
    check_include_files(cpuid.h HAVE_CPUID_H)
    check_include_files(dirent.h HAVE_DIRENT_H)

    # Context-related headers
    check_include_files(ucontext.h HAVE_UCONTEXT_H)
    check_include_files(sys/ucontext.h HAVE_SYS_UCONTEXT_H) # OSX specific

    # Time and memory
    check_include_files(sys/timeb.h HAVE_SYS_TIMEB_H)

    # Log the results for important headers
    if (NOT HAVE_SYS_TYPES_H)
        message(WARNING "sys/types.h not found - this may cause problems")
    endif ()

    if (NOT HAVE_SYS_SOCKET_H)
        message(WARNING "sys/socket.h not found - networking functionality may be limited")
    endif ()

    # Return results to parent scope
    foreach (var
            HAVE_SYS_TYPES_H
            HAVE_SYS_UIO_H
            HAVE_FCNTL_H
            HAVE_MATH_H
            HAVE_STDIO_H
            HAVE_STDLIB_H
            HAVE_STRING_H
            HAVE_STRINGS_H
            HAVE_TIME_H
            HAVE_UNISTD_H
            HAVE_STDINT_H
            HAVE_INTTYPES_H
            HAVE_STDBOOL_H
            HAVE_ENDIAN_H
            HAVE_SYS_ENDIAN_H
            HAVE_MACHINE_ENDIAN_H
            HAVE_SYS_SOCKET_H
            HAVE_SYS_MMAN_H
            HAVE_SYS_UN_H
            HAVE_SYS_STAT_H
            HAVE_SYS_WAIT_H
            HAVE_SYS_PARAM_H
            HAVE_SYS_FILE_H
            HAVE_SYS_RESOURCE_H
            HAVE_NETINET_IN_H
            HAVE_NETINET_TCP_H
            HAVE_ARPA_INET_H
            HAVE_NETDB_H
            HAVE_SYSLOG_H
            HAVE_SIGINFO_H
            HAVE_LOCALE_H
            HAVE_LIBGEN_H
            HAVE_PWD_H
            HAVE_GRP_H
            HAVE_GLOB_H
            HAVE_POLL_H
            HAVE_READPASSPHRASE_H
            HAVE_TERMIOS_H
            HAVE_PATHS_H
            HAVE_CTYPE_H
            HAVE_UNISTD_H
            HAVE_CPUID_H
            HAVE_DIRENT_H
            HAVE_UCONTEXT_H
            HAVE_SYS_UCONTEXT_H
            HAVE_SYS_TIMEB_H)
        if (${var})
            set(${var} ${${var}} PARENT_SCOPE)
        endif ()
    endforeach ()
endfunction()

# Execute the function
CheckSystemHeaders()
