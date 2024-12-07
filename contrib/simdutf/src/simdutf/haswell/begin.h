#define SIMDUTF_IMPLEMENTATION haswell

#if SIMDUTF_CAN_ALWAYS_RUN_HASWELL
// nothing needed.
#else
SIMDUTF_TARGET_HASWELL
#endif

#if SIMDUTF_GCC11ORMORE // workaround for
                        // https://gcc.gnu.org/bugzilla/show_bug.cgi?id=105593
// clang-format off
SIMDUTF_DISABLE_GCC_WARNING(-Wmaybe-uninitialized)
// clang-format on
#endif // end of workaround
