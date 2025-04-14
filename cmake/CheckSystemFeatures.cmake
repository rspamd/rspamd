# CheckSystemFeatures.cmake
# Checks for various system features, functions, and functionality

# Check platform API and features
function(CheckSystemFeatures)
    # Process-related functions
    if (NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
        # setproctitle is broken badly in Linux, never try it
        check_function_exists(setproctitle HAVE_SETPROCTITLE)
    endif ()

    # Memory and file management
    check_function_exists(getpagesize HAVE_GETPAGESIZE)
    check_function_exists(nanosleep HAVE_NANOSLEEP)
    check_function_exists(flock HAVE_FLOCK)
    check_library_exists(m tanh "" HAVE_TANH)
    check_function_exists(mkstemp HAVE_MKSTEMP)
    check_function_exists(clock_gettime HAVE_CLOCK_GETTIME)

    # Check macros and constants
    check_symbol_exists(PATH_MAX limits.h HAVE_PATH_MAX)
    check_symbol_exists(MAXPATHLEN sys/param.h HAVE_MAXPATHLEN)
    check_symbol_exists(MAP_ANON sys/mman.h HAVE_MMAP_ANON)
    check_symbol_exists(IPV6_V6ONLY "sys/socket.h;netinet/in.h" HAVE_IPV6_V6ONLY)
    check_symbol_exists(posix_fallocate fcntl.h HAVE_POSIX_FALLOCATE)
    check_symbol_exists(fallocate fcntl.h HAVE_FALLOCATE)
    check_symbol_exists(_SC_NPROCESSORS_ONLN unistd.h HAVE_SC_NPROCESSORS_ONLN)
    check_symbol_exists(setbit sys/param.h PARAM_H_HAS_BITSET)
    check_symbol_exists(getaddrinfo "sys/types.h;sys/socket.h;netdb.h" HAVE_GETADDRINFO)
    check_symbol_exists(sched_yield "sched.h" HAVE_SCHED_YIELD)
    check_symbol_exists(nftw "sys/types.h;ftw.h" HAVE_NFTW)
    check_symbol_exists(memrchr "string.h" HAVE_MEMRCHR)

    # Check if PCRE has JIT support
    if (ENABLE_PCRE2)
        list(APPEND CMAKE_REQUIRED_INCLUDES "${PCRE_INCLUDE}")
        check_symbol_exists(PCRE2_CONFIG_JIT "pcre2.h" HAVE_PCRE_JIT)
    else ()
        list(APPEND CMAKE_REQUIRED_INCLUDES "${PCRE_INCLUDE}")
        check_symbol_exists(PCRE_CONFIG_JIT "pcre.h" HAVE_PCRE_JIT)
    endif ()

    # Socket features
    check_symbol_exists(SOCK_SEQPACKET "sys/types.h;sys/socket.h" HAVE_SOCK_SEQPACKET)

    # File handling features
    check_symbol_exists(O_NOFOLLOW "sys/types.h;sys/fcntl.h" HAVE_ONOFOLLOW)
    check_symbol_exists(O_CLOEXEC "sys/types.h;sys/fcntl.h" HAVE_OCLOEXEC)

    # OpenSSL specific stuff
    list(APPEND CMAKE_REQUIRED_INCLUDES "${LIBSSL_INCLUDE}")
    if (LIBCRYPT_LIBRARY_PATH)
        set(CMAKE_REQUIRED_LIBRARIES "${CMAKE_REQUIRED_LIBRARIES};-L${LIBCRYPT_LIBRARY_PATH};${LIBCRYPT_LIBRARY}")
        set(CMAKE_REQUIRED_LIBRARIES "${CMAKE_REQUIRED_LIBRARIES};-L${LIBSSL_LIBRARY_PATH};${LIBSSL_LIBRARY}")
    else ()
        set(CMAKE_REQUIRED_LIBRARIES "${CMAKE_REQUIRED_LIBRARIES};-lcrypt;-lssl")
    endif ()

    check_symbol_exists(SSL_set_tlsext_host_name "openssl/ssl.h" HAVE_SSL_TLSEXT_HOSTNAME)
    check_symbol_exists(FIPS_mode "openssl/crypto.h" HAVE_FIPS_MODE)

    # Directory and file path operations
    check_symbol_exists(dirfd "sys/types.h;unistd.h;dirent.h" HAVE_DIRFD)
    check_symbol_exists(fpathconf "sys/types.h;unistd.h" HAVE_FPATHCONF)

    # Signal handling and memory operations
    check_symbol_exists(sigaltstack "signal.h" HAVE_SIGALTSTACK)
    check_symbol_exists(open_memstream "stdio.h" HAVE_OPENMEMSTREAM)
    check_symbol_exists(fmemopen "stdio.h" HAVE_FMEMOPEN)
    check_symbol_exists(clock_getcpuclockid "sys/types.h;time.h" HAVE_CLOCK_GETCPUCLOCKID)
    check_symbol_exists(RUSAGE_SELF "sys/types.h;sys/resource.h" HAVE_RUSAGE_SELF)
    check_symbol_exists(ffsll "strings.h" HAVE_FFSLL)

    # Check for PCRE JIT fast path
    if (ENABLE_PCRE2)
        if (HAVE_PCRE_JIT)
            set(HAVE_PCRE_JIT_FAST 1)
            message(STATUS "PCRE2 JIT is supported")
        else ()
            message(STATUS "PCRE2 JIT is NOT supported")
        endif ()
    else ()
        list(APPEND CMAKE_REQUIRED_INCLUDES "${PCRE_INCLUDE}")
        if (PCRE_LIBRARY_PATH)
            set(CMAKE_REQUIRED_LIBRARIES "${CMAKE_REQUIRED_LIBRARIES};-L${PCRE_LIBRARY_PATH};${PCRE_LIBRARY}")
        else ()
            set(CMAKE_REQUIRED_LIBRARIES "${CMAKE_REQUIRED_LIBRARIES};-lpcre")
        endif ()

        # Check for PCRE JIT fast path
        set(_PCRE_FAST_TEST "
#include \"pcre.h\"
int main (void)
{
	int rc;
	int ovector[30];
	pcre *re;
	pcre_extra *extra;
	pcre_jit_stack *jit_stack;

	re = pcre_compile(\"abc\", 0, NULL, NULL, NULL);
	extra = pcre_study(re, PCRE_STUDY_JIT_COMPILE, NULL);
	jit_stack = pcre_jit_stack_alloc(32*1024, 512*1024);
	pcre_assign_jit_stack(extra, NULL, jit_stack);
	rc = pcre_jit_exec(re, extra, \"abc\", 3, 0, 0, ovector, 30, jit_stack);

	return rc;
}
")
        check_c_source_compiles("${_PCRE_FAST_TEST}" HAVE_PCRE_JIT_FAST)
        if (HAVE_PCRE_JIT_FAST)
            message(STATUS "pcre_jit_exec is supported")
        else ()
            message(STATUS "pcre_jit_exec is NOT supported")
        endif ()
    endif ()

    # Critical checks
    if (NOT HAVE_GETADDRINFO)
        message(FATAL_ERROR "Your system does not support getaddrinfo call, please consider upgrading it to run rspamd")
    endif ()

    # Check for signal information
    if (HAVE_SIGINFO_H)
        check_symbol_exists(SA_SIGINFO "signal.h;siginfo.h" HAVE_SA_SIGINFO)
    else ()
        check_symbol_exists(SA_SIGINFO "signal.h" HAVE_SA_SIGINFO)
    endif ()

    # Clock and timer features
    if (NOT CMAKE_SYSTEM_NAME STREQUAL "SunOS")
        if (HAVE_CLOCK_GETTIME)
            check_symbol_exists(CLOCK_PROCESS_CPUTIME_ID time.h HAVE_CLOCK_PROCESS_CPUTIME_ID)
            check_symbol_exists(CLOCK_VIRTUAL time.h HAVE_CLOCK_VIRTUAL)
        else ()
            check_include_files(sys/timeb.h HAVE_SYS_TIMEB_H)
        endif ()
    endif ()

    # Linux-specific features
    if (CMAKE_SYSTEM_NAME STREQUAL "Linux")
        # In linux, we need to mount /run/shm to test which could be unavailable
        # on a build system. On the other hand, we know that linux has stupid
        # but compatible shmem support, so we assume this macro as true
        set(HAVE_SANE_SHMEM 1)

        check_c_source_compiles("#define _GNU_SOURCE
                              #include <sys/socket.h>
                              int main (int argc, char **argv) {
                                return ((int*)(&recvmmsg))[argc];
                              }" HAVE_RECVMMSG)

        check_c_source_compiles("#define _GNU_SOURCE
                              #include <fcntl.h>
                              int main (int argc, char **argv) {
                                return ((int*)(&readahead))[argc];
                              }" HAVE_READAHEAD)
    endif ()

    # Propagate variables to parent scope
    set(HAVE_PCRE_JIT_FAST ${HAVE_PCRE_JIT_FAST} PARENT_SCOPE)
    set(HAVE_SANE_SHMEM ${HAVE_SANE_SHMEM} PARENT_SCOPE)
    set(HAVE_GETPAGESIZE ${HAVE_GETPAGESIZE} PARENT_SCOPE)
    set(HAVE_NANOSLEEP ${HAVE_NANOSLEEP} PARENT_SCOPE)
    set(HAVE_FLOCK ${HAVE_FLOCK} PARENT_SCOPE)
    set(HAVE_TANH ${HAVE_TANH} PARENT_SCOPE)
    set(HAVE_MKSTEMP ${HAVE_MKSTEMP} PARENT_SCOPE)
    set(HAVE_CLOCK_GETTIME ${HAVE_CLOCK_GETTIME} PARENT_SCOPE)
    set(HAVE_PATH_MAX ${HAVE_PATH_MAX} PARENT_SCOPE)
    set(HAVE_MAXPATHLEN ${HAVE_MAXPATHLEN} PARENT_SCOPE)
    set(HAVE_MMAP_ANON ${HAVE_MMAP_ANON} PARENT_SCOPE)
    set(HAVE_IPV6_V6ONLY ${HAVE_IPV6_V6ONLY} PARENT_SCOPE)
    set(HAVE_POSIX_FALLOCATE ${HAVE_POSIX_FALLOCATE} PARENT_SCOPE)
    set(HAVE_FALLOCATE ${HAVE_FALLOCATE} PARENT_SCOPE)
    set(HAVE_SC_NPROCESSORS_ONLN ${HAVE_SC_NPROCESSORS_ONLN} PARENT_SCOPE)
    set(PARAM_H_HAS_BITSET ${PARAM_H_HAS_BITSET} PARENT_SCOPE)
    set(HAVE_GETADDRINFO ${HAVE_GETADDRINFO} PARENT_SCOPE)
    set(HAVE_SCHED_YIELD ${HAVE_SCHED_YIELD} PARENT_SCOPE)
    set(HAVE_NFTW ${HAVE_NFTW} PARENT_SCOPE)
    set(HAVE_MEMRCHR ${HAVE_MEMRCHR} PARENT_SCOPE)
    set(HAVE_PCRE_JIT ${HAVE_PCRE_JIT} PARENT_SCOPE)
    set(HAVE_SOCK_SEQPACKET ${HAVE_SOCK_SEQPACKET} PARENT_SCOPE)
    set(HAVE_ONOFOLLOW ${HAVE_ONOFOLLOW} PARENT_SCOPE)
    set(HAVE_OCLOEXEC ${HAVE_OCLOEXEC} PARENT_SCOPE)
    set(HAVE_SSL_TLSEXT_HOSTNAME ${HAVE_SSL_TLSEXT_HOSTNAME} PARENT_SCOPE)
    set(HAVE_FIPS_MODE ${HAVE_FIPS_MODE} PARENT_SCOPE)
    set(HAVE_DIRFD ${HAVE_DIRFD} PARENT_SCOPE)
    set(HAVE_FPATHCONF ${HAVE_FPATHCONF} PARENT_SCOPE)
    set(HAVE_SIGALTSTACK ${HAVE_SIGALTSTACK} PARENT_SCOPE)
    set(HAVE_OPENMEMSTREAM ${HAVE_OPENMEMSTREAM} PARENT_SCOPE)
    set(HAVE_FMEMOPEN ${HAVE_FMEMOPEN} PARENT_SCOPE)
    set(HAVE_CLOCK_GETCPUCLOCKID ${HAVE_CLOCK_GETCPUCLOCKID} PARENT_SCOPE)
    set(HAVE_RUSAGE_SELF ${HAVE_RUSAGE_SELF} PARENT_SCOPE)
    set(HAVE_FFSLL ${HAVE_FFSLL} PARENT_SCOPE)
    set(HAVE_SA_SIGINFO ${HAVE_SA_SIGINFO} PARENT_SCOPE)
    set(HAVE_CLOCK_PROCESS_CPUTIME_ID ${HAVE_CLOCK_PROCESS_CPUTIME_ID} PARENT_SCOPE)
    set(HAVE_CLOCK_VIRTUAL ${HAVE_CLOCK_VIRTUAL} PARENT_SCOPE)

    # Linux-specific features propagation
    if (CMAKE_SYSTEM_NAME STREQUAL "Linux")
        set(HAVE_RECVMMSG ${HAVE_RECVMMSG} PARENT_SCOPE)
        set(HAVE_READAHEAD ${HAVE_READAHEAD} PARENT_SCOPE)
    endif ()
endfunction()

# Execute the function
CheckSystemFeatures()
