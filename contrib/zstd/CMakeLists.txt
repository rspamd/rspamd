SET(ZSTDSRC
		cover.c
		divsufsort.c
		entropy_common.c
		error_private.c
		fse_compress.c
		fse_decompress.c
		huf_compress.c
		huf_decompress.c
		pool.c
		threading.c
		zdict.c
		zstd_common.c
		zstd_compress.c
		zstd_decompress.c
		zstd_double_fast.c
		zstd_fast.c
		zstd_lazy.c
		zstd_ldm.c
		zstdmt_compress.c
		zstd_opt.c)

ADD_LIBRARY(rspamd-zstd STATIC ${ZSTDSRC})
ADD_DEFINITIONS(-DZSTD_STATIC_LINKING_ONLY)
