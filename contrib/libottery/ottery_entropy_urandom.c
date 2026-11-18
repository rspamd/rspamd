/* Libottery by Nick Mathewson.

   This software has been dedicated to the public domain under the CC0
   public domain dedication.

   To the extent possible under law, the person who associated CC0 with
   libottery has waived all copyright and related or neighboring rights
   to libottery.

   You should have received a copy of the CC0 legalcode along with this
   work in doc/cc0.txt.  If not, see
      <http://creativecommons.org/publicdomain/zero/1.0/>.
 */

#ifndef _WIN32

#include <errno.h>
#if defined(HAVE_GETRANDOM)
#include <sys/random.h>
#elif defined(__linux__)
#include <sys/syscall.h>
#endif
#if defined(HAVE_GETENTROPY)
#include <unistd.h>
#elif defined(HAVE_GETENTROPY_SYS_RANDOM)
#include <sys/random.h>
#endif

/**
 * Read from a file into an n-byte buffer until the buffer is full or until
 * we reach an error.  Returns the number of bytes read.  If the return
 * value is less than n, an error occurred.
 */
static int
ottery_read_n_bytes_from_file_(int fd, uint8_t *out, size_t n)
{
  ssize_t r;
  uint8_t *outp = out;
  while (n) {
    r = read(fd, outp, n);
    if (r < 0 && errno == EINTR)
      continue;
    if (r <= 0 || (size_t)r > n)
      return outp - out;
    outp += r;
    n -= r;
  }
  return outp - out;
}

/**
 * Get random bytes from the kernel without a file descriptor or a device
 * node, so seeding works in a chroot, without /dev, or with the descriptor
 * table full. getrandom() also blocks until the kernel CRNG is seeded,
 * which reading /dev/urandom does not.
 *
 * @return 0 on success, -1 if the interface is missing or failed; the caller
 *    then falls back to the device.
 */
static int
ottery_get_entropy_syscall_(uint8_t *out, size_t outlen)
{
#if defined(HAVE_GETRANDOM) || (defined(__linux__) && defined(SYS_getrandom))
  uint8_t *p = out;
  while (outlen) {
    ssize_t r;
#ifdef HAVE_GETRANDOM
    r = getrandom(p, outlen, 0);
#else
    r = syscall(SYS_getrandom, p, outlen, 0);
#endif
    if (r < 0 && errno == EINTR)
      continue;
    if (r <= 0 || (size_t)r > outlen)
      return -1; /* e.g. ENOSYS on an old kernel or under seccomp */
    p += r;
    outlen -= (size_t)r;
  }
  return 0;
#elif defined(HAVE_GETENTROPY) || defined(HAVE_GETENTROPY_SYS_RANDOM)
  uint8_t *p = out;
  while (outlen) {
    /* getentropy() is limited to 256 bytes per call */
    size_t m = outlen > 256 ? 256 : outlen;
    if (getentropy(p, m) != 0)
      return -1;
    p += m;
    outlen -= m;
  }
  return 0;
#else
  (void)out;
  (void)outlen;
  return -1;
#endif
}


/** Generate random bytes using the unix-style /dev/urandom RNG, or another
 * such device as configured in the configuration. */
static int
ottery_get_entropy_urandom(const struct ottery_entropy_config *cfg,
                           struct ottery_entropy_state *state,
                            uint8_t *out, size_t outlen)
{
  /* On most unixes these days, you can get strong random numbers from
   * /dev/urandom.
   *
   * That's assuming that /dev/urandom is seeded.  For most applications,
   * that won't be a problem. But for stuff that starts close to system
   * startup, before the operating system has added any entropy to the pool,
   * it can be pretty bad.
   *
   * You could use /dev/random instead, if you want, but that has another
   * problem.  It will block if the OS PRNG has received less entropy than
   * it has emitted.  If we assume that the OS PRNG isn't cryptographically
   * weak, blocking in that case is simple overkill.
   *
   * It would be best if there were an alternative that blocked if the PRNG
   * had _never_ been seeded.  But most operating systems don't have that.
   */
  int fd;
  ssize_t n;
  int result = 0;
  const char *urandom_fname;
  struct stat st;
  int own_fd = 0;
  int check_device = !cfg || !cfg->allow_nondev_urandom;
#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif
  /* Prefer the kernel interface unless a device or an fd was configured */
  if (!(cfg && (cfg->urandom_fd_is_set || cfg->urandom_fname)) &&
      ottery_get_entropy_syscall_(out, outlen) == 0)
    return 0;

  if (cfg && cfg->urandom_fd_is_set && cfg->urandom_fd >= 0) {
    fd = cfg->urandom_fd;
  } else {
    if (cfg && cfg->urandom_fname)
      urandom_fname = cfg->urandom_fname;
    else
      urandom_fname = "/dev/urandom";

    fd = open(urandom_fname, O_RDONLY|O_CLOEXEC);
    own_fd = 1;
    if (fd < 0)
      return OTTERY_ERR_INIT_STRONG_RNG;
  }
  if (fstat(fd, &st) < 0) {
    result = OTTERY_ERR_INIT_STRONG_RNG;
    goto end;
  }
  if (check_device) {
    if (!S_ISCHR(st.st_mode)) {
      result = OTTERY_ERR_INIT_STRONG_RNG;
      goto end;
    }

    if (state) {
      if (0 == state->urandom_fd_inode) {
        state->urandom_fd_inode = (uint64_t) st.st_ino;
      } else if ((uint64_t)st.st_ino != state->urandom_fd_inode) {
        /* Do not close an fd that the caller owns */
        result = OTTERY_ERR_ACCESS_STRONG_RNG;
        goto end;
      }
    }
  }

  n = ottery_read_n_bytes_from_file_(fd, out, outlen);
  if (n < 0 || (size_t)n != outlen)
    result = OTTERY_ERR_ACCESS_STRONG_RNG;

 end:
  if (own_fd)
    close(fd);
  return result;
}

#define ENTROPY_SOURCE_URANDOM \
  { ottery_get_entropy_urandom, SRC(RANDOMDEV)|DOM(OS)|FL(STRONG) }

#endif
