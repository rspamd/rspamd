# Function to check for atomic builtins, CPU features, and other specialized symbols
function(CheckSymbols)
    # Check for atomic builtins
    check_c_source_runs("
    #include <stdbool.h>
    int main(int argc, char **argv) {
            int a = 0, b = 0;
            if (__atomic_compare_exchange_n(&a, &b, 1, false, __ATOMIC_RELEASE, __ATOMIC_RELAXED)) {
                    return 0;
            }
            return -1;
    }
    " HAVE_ATOMIC_BUILTINS)

    if (NOT HAVE_ATOMIC_BUILTINS)
        message(STATUS "atomic builtins are -NOT- supported")
    else ()
        message(STATUS "atomic builtins are supported")
    endif ()

    # Check for libatomic
    check_library_exists(atomic __atomic_fetch_add_4 "" HAVE_LIBATOMIC)
    if (HAVE_LIBATOMIC)
        list(APPEND CMAKE_REQUIRED_LIBRARIES "atomic")
        list(APPEND RSPAMD_REQUIRED_LIBRARIES "atomic")
        set(RSPAMD_REQUIRED_LIBRARIES "${RSPAMD_REQUIRED_LIBRARIES}" PARENT_SCOPE)
    endif ()

    # Check for CPU feature intrinsics
    check_c_source_runs("
    #include <stdio.h>
    int main() {
      __builtin_cpu_init();
      printf(\"%d\", __builtin_cpu_supports(\"avx\"));
      return 0;
    }" HAVE_BUILTIN_CPU_SUPPORTS)

    if (HAVE_BUILTIN_CPU_SUPPORTS)
        message(STATUS "CPU feature detection via __builtin_cpu_supports is supported")
    else ()
        message(STATUS "CPU feature detection via __builtin_cpu_supports is NOT supported")
    endif ()

    # Check for RDTSC
    check_c_source_runs("
    #include <x86intrin.h>
    int main(int argc, char **argv) {
            __builtin_ia32_lfence();
            if (__builtin_ia32_rdtsc()) {
                    return 0;
            }
            return -1;
    }
    " HAVE_RDTSC)

    if (NOT HAVE_RDTSC)
        message(STATUS "rdtsc intrinsic is -NOT- supported")
    else ()
        message(STATUS "rdtsc intrinsic is supported")
    endif ()

    # Check for POSIX shared memory support
    if (NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
        # For non-Linux systems, test shmem capability
        check_c_source_runs("
        #include <sys/mman.h>
        #include <fcntl.h>
        #include <unistd.h>
        #define TEST_NAME \"/test-shmem-work\"
        int
        main(int argc, char **argv)
        {
          int fd;

          fd = shm_open(TEST_NAME, O_RDWR | O_CREAT | O_EXCL, 00600);
          if (fd == -1) {
            return -1;
          }
          if (ftruncate(fd, 100) == -1) {
            shm_unlink(TEST_NAME);
            close(fd);
            return -1;
          }

          if (ftruncate(fd, 200) == -1) {
            shm_unlink(TEST_NAME);
            close(fd);
            return -1;
          }
          if (ftruncate(fd, 300) == -1) {
            shm_unlink(TEST_NAME);
            close(fd);
            return -1;
          }

          close(fd);
          shm_unlink(TEST_NAME);
          return 0;
        }
        " HAVE_SANE_SHMEM)

        if (NOT HAVE_SANE_SHMEM)
            message(STATUS "shmem support is NOT compatible with POSIX")
        else ()
            message(STATUS "shmem support is compatible with POSIX")
        endif ()
    endif ()

    # Check for pthread shared mutexes and robust mutexes
    file(WRITE ${CMAKE_BINARY_DIR}/pthread_setpshared.c "
    #include <pthread.h>
    #include <stdlib.h>
    int main(void)
    {
        pthread_mutexattr_t mattr;
        if (pthread_mutexattr_init(&mattr) != 0) return 0;
        if (pthread_mutexattr_setpshared(&mattr, PTHREAD_PROCESS_SHARED) != 0) return 0;
        if (pthread_mutexattr_setrobust(&mattr, PTHREAD_MUTEX_ROBUST) != 0) return 0;
        return 1;
    }
    ")

    try_run(_CAN_RUN _CAN_COMPILE
            "${CMAKE_BINARY_DIR}" "${CMAKE_BINARY_DIR}/pthread_setpshared.c"
            CMAKE_FLAGS CMAKE_C_FLAGS="-pthread")

    if (_CAN_RUN EQUAL 1)
        set(HAVE_PTHREAD_PROCESS_SHARED 1 CACHE INTERNAL "")
    endif ()

    if (HAVE_PTHREAD_PROCESS_SHARED)
        message(STATUS "pthread_mutexattr_setpshared is supported")
    else ()
        message(STATUS "pthread_mutexattr_setpshared is -NOT- supported")
    endif ()

    # Propagate variables to parent scope
    set(HAVE_ATOMIC_BUILTINS ${HAVE_ATOMIC_BUILTINS} PARENT_SCOPE)
    set(HAVE_LIBATOMIC ${HAVE_LIBATOMIC} PARENT_SCOPE)
    set(HAVE_BUILTIN_CPU_SUPPORTS ${HAVE_BUILTIN_CPU_SUPPORTS} PARENT_SCOPE)
    set(HAVE_RDTSC ${HAVE_RDTSC} PARENT_SCOPE)
    set(HAVE_SANE_SHMEM ${HAVE_SANE_SHMEM} PARENT_SCOPE)
    set(HAVE_PTHREAD_PROCESS_SHARED ${HAVE_PTHREAD_PROCESS_SHARED} PARENT_SCOPE)
endfunction()

CheckSymbols()