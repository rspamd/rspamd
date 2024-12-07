#define SIMDUTF_IMPLEMENTATION icelake

#if SIMDUTF_CAN_ALWAYS_RUN_ICELAKE
// nothing needed.
#else
SIMDUTF_TARGET_ICELAKE
#endif

#if SIMDUTF_GCC11ORMORE // workaround for
                        // https://gcc.gnu.org/bugzilla/show_bug.cgi?id=105593
// clang-format off
SIMDUTF_DISABLE_GCC_WARNING(-Wmaybe-uninitialized)
// clang-format on
#endif // end of workaround
