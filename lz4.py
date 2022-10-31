import ctypes

LZ4_stream_t = ctypes.c_uint8 * 16416

lz4 = ctypes.CDLL("liblz4.so.1")
_reset_stream = lz4.LZ4_resetStream
_reset_stream.argtypes = [ctypes.c_void_p]

def _get_fn(name, argtypes, restype):
    ret = getattr(lz4, name)
    ret.argtypes = argtypes
    ret.restype = restype
    return ret

_compress_fast_continue = _get_fn(
    "LZ4_compress_fast_continue", 
    [LZ4_stream_t, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_size_t, ctypes.c_int],
    ctypes.c_size_t,
)
_create_stream_decode = _get_fn("LZ4_createStreamDecode", [], ctypes.c_void_p)
_free_stream_decode = _get_fn("LZ4_freeStreamDecode", [ctypes.c_void_p], ctypes.c_int)
_decompress_safe_continue = _get_fn("LZ4_decompress_safe_continue", [
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_int,
    ctypes.c_int,
], ctypes.c_int)

class LZ4Compressor():
    def __init__(self):
        self._stream = LZ4_stream_t()

    def compress_block(self, src):
        assert len(src) < 131072 # FIXME
          
        output_size = len(src) + (len(src) // 255) + 16
        dst = (ctypes.c_char * output_size)()
        ret = _compress_fast_continue(self._stream, src, dst, len(src), len(dst), 1)
        return dst[:ret]

class LZ4Decompressor():
    def __init__(self):
        self._stream = _create_stream_decode()

    def __del__(self):
        if self._stream:
            _free_stream_decode(self._stream)
        self._stream = None

    def decompress_block(self, src):
        output_size = 131072
        dst = (ctypes.c_char * output_size)()
        ret = _decompress_safe_continue(self._stream, src, dst, len(src), output_size)
        if ret == -1:
            raise RuntimeError("LZ4 decompression error")
        return dst[:ret]
