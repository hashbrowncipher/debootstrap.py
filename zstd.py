import ctypes

class ZstdCContext(ctypes.c_void_p):
    pass

zstd = ctypes.CDLL("libzstd.so.1")
_create_cctx = zstd.ZSTD_createCCtx
_create_cctx.restype = ctypes.c_void_p
_free_cctx = zstd.ZSTD_freeCCtx
_free_cctx.argtypes = [ctypes.c_void_p]

_compress_block = zstd.ZSTD_compressBlock
_compress_block.argtypes = [
    ctypes.c_void_p, # ctx
    ctypes.c_void_p, # dst
    ctypes.c_size_t, # dstCapacity
    ctypes.c_void_p, # src
    ctypes.c_size_t, # srcCapacity
]
_compress_block.restype = ctypes.c_size_t

_compress_begin = zstd.ZSTD_compressBegin
_compress_begin.argtypes = [ZstdCContext, ctypes.c_int]
_compress_block.restype = ctypes.c_size_t

_get_block_size = zstd.ZSTD_getBlockSize
_get_block_size.argtypes = [ZstdCContext]
_get_block_size.restype = ctypes.c_size_t

class ZstdCompressor:
    def __init__(self):
        self._ctx = _create_cctx()
        _compress_begin(self._ctx, 6)

    def compress_block(self, src):
        dst = (ctypes.c_char * (len(src)))()
        size = _compress_block(
            self._ctx,
            dst, len(dst),
            src, len(src),
        )
        if size == 0:
            return src

        return dst[:size]

    def block_size(self):
        return _get_block_size(self._ctx)

    def __del__(self):
        _free_cctx(self._ctx)
