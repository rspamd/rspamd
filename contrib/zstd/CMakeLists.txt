SET(ZSTDSRC
		debug.c
		divsufsort.c
		entropy_common.c
		error_private.c
		fse_compress.c
		fse_decompress.c
		hist.c
		huf_compress.c
		huf_decompress.c
		pool.c
		threading.c
		zstd_common.c
		zstd_compress.c
		zstd_compress_literals.c
		zstd_compress_sequences.c
		zstd_compress_superblock.c
		zstd_ddict.c
		zstd_decompress.c
		zstd_decompress_block.c
		zstd_double_fast.c
		zstd_fast.c
		zstd_lazy.c
		zstd_ldm.c
		zstd_opt.c)

ADD_LIBRARY(rspamd-zstd STATIC ${ZSTDSRC})
ADD_DEFINITIONS(-DZSTD_STATIC_LINKING_ONLY)
