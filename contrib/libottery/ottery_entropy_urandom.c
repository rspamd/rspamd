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
    if (r <= 0 || (size_t)r > n)
      return outp - out;
    outp += r;
    n -= r;
  }
  return outp - out;
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
    if (0 == (st.st_mode & S_IFCHR)) {
      result = OTTERY_ERR_INIT_STRONG_RNG;
      goto end;
    }

    if (state) {
      if (0 == state->urandom_fd_inode) {
        state->urandom_fd_inode = (uint64_t) st.st_ino;
      } else if ((uint64_t)st.st_ino != state->urandom_fd_inode) {
        close(fd);
        return OTTERY_ERR_ACCESS_STRONG_RNG;
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
