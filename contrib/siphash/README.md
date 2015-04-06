siphash
=======

The mirror of William Ahern siphash implementation

siphash.h - SipHash-2-4 in a single header file
--------------------------------------------------------------------------

Derived by William Ahern[1] from the reference implementation[2] published[3]
by Jean-Philippe Aumasson and Daniel J. Berstein. Licensed in kind.

1. http://25thandclement.com/~william/projects/siphash.h.html
2. https://www.131002.net/siphash/siphash24.c
3. https://www.131002.net/siphash/

HISTORY:
--------------------------------------------------------------------------
* 2012-11-04 - Born.

USAGE:
--------------------------------------------------------------------------
SipHash-2-4 takes as input two 64-bit words as the key, some number of
message bytes, and outputs a 64-bit word as the message digest. This
implementation employs two data structures: a struct sipkey for
representing the key, and a struct siphash for representing the hash
state.

For converting a 16-byte unsigned char array to a key, use either the
macro sip_keyof or the routine sip_tokey. The former instantiates a
compound literal key, while the latter requires a key object as a
parameter.

~~~c
	unsigned char secret[16];
	arc4random_buf(secret, sizeof secret);
	struct sipkey *key = sip_keyof(secret);
~~~

For hashing a message, use either the convenience macro siphash24 or the
routines sip24_init, sip24_update, and sip24_final.

~~~c
	struct siphash state;
	void *msg;
	size_t len;
	uint64_t hash;

	sip24_init(&state, key);
	sip24_update(&state, msg, len);
	hash = sip24_final(&state);
~~~

or

~~~c
	hash = siphash24(msg, len, key);
~~~

To convert the 64-bit hash value to a canonical 8-byte little-endian
binary representation, use either the macro sip_binof or the routine
sip_tobin. The former instantiates and returns a compound literal array,
while the latter requires an array object as a parameter.

NOTES:
--------------------------------------------------------------------------
* Neither `sip_keyof`, `sip_binof`, nor `siphash24` will work with compilers
  lacking compound literal support. Instead, you must use the lower-level
  interfaces which take as parameters the temporary state objects.
* Uppercase macros may evaluate parameters more than once. Lowercase
  macros should not exhibit any such side effects.
