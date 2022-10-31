import ctypes
import io
import os
import itertools
import stat
from binascii import hexlify
from time import process_time
from dataclasses import dataclass
from enum import Enum
from os.path import join

from os import SEEK_END

from lz4 import LZ4Compressor, LZ4Decompressor
from zstd import ZstdCompressor

UIDS_TABLE = {1000: 0}
GIDS_TABLE = {1000: 0}


class FileType(int, Enum):
    FIFO = 0
    CHRDEV = 1
    DIRECTORY = 2
    BLKDEV = 3
    REGULAR = 4
    SYMLINK = 5
    SOCKET = 6

    @classmethod
    def from_mode(cls, mode):
        mode = mode >> 12
        return cls(FILE_TYPES[mode])


FILE_TYPES = {
    1: FileType.FIFO,
    2: FileType.CHRDEV,
    4: FileType.DIRECTORY,
    6: FileType.BLKDEV,
    8: FileType.REGULAR,
    10: FileType.SYMLINK,
    12: FileType.SOCKET,
}

i16 = ctypes.c_int16.__ctype_be__
u16 = ctypes.c_uint16.__ctype_be__
u32 = ctypes.c_uint32.__ctype_be__
u64 = ctypes.c_uint64.__ctype_be__
u8 = ctypes.c_ubyte
u1 = ctypes.c_bool
struct = ctypes.BigEndianStructure


# FIT: fixed inode table
class FITEntry(struct):
    _fields_ = [
        ("size", u64),
        ("mtime", u64),
        ("ad_len", u16),
        ("uid", u16),
        ("gid", u16),
        ("mode", u16),
    ]

    @classmethod
    def from_host_inode(cls, ino):
        mode = ino.type << 12 + ino.mode
        return cls(
            uid=ino.uid,
            gid=ino.gid,
            size=ino.size,
            mtime=ino.mtime,
            mode=mode,
            ad_len=0,
        )


# fixed dentry table entry
# fixed (directory entry) table entry
class FDTEntry(struct):
    _fields_ = [
        ("dir_inode", u64),
        ("inode", u64),
        ("length", u16),
    ]

    @classmethod
    def from_entry(cls, item):
        ret = cls(
            dir_inode=item.dir_inode,
            inode=item.inode,
            length=len(item.name),
        )
        ret.name = item.name
        return ret

    @property
    def pk(self):
        # Just the dir_inode and the name
        return bytes(self)[0:8] + self.name

    def __len__(self):
        return ctypes.sizeof(self) + len(self.name)

    def __repr__(self):
        return "{}(dir_inode={}, name={}, inode={})".format(
            self.__class__.__name__, self.dir_inode, self.name, self.inode
        )


# I would have called them "index nodes"
# but that would make them inodes, which would be even more confusing
class TreeNode(struct):
    _fields_ = [
        ("span", u64),
        # FIXME: consider making this a u16 and just having all blocks be an even number
        # of bytes smaller than 131072?
        ("size", u32),
    ]

    @classmethod
    def create(cls, span, size, pk):
        ret = cls(span, size)
        ret.pk = pk
        return ret

    def __repr__(self):
        return "{}(span={}, size={}, pk={})".format(
            self.__class__.__name__, self.span, self.size, self.pk
        )


@dataclass(frozen=True, order=True)
class HostINode:
    # This order determines sort order
    uid: int
    gid: int
    mtime: int
    type: FileType
    mode: int
    size: int

    @staticmethod
    def _transform_mode(mode):
        mode = mode & 0o7777
        return mode ^ 0o644

    @classmethod
    def from_stat(cls, st):
        return cls(
            type=FileType.from_mode(st.st_mode),
            mode=cls._transform_mode(st.st_mode),
            uid=UIDS_TABLE[st.st_uid],
            gid=GIDS_TABLE[st.st_gid],
            mtime=st.st_mtime_ns,
            size=st.st_size,
        )


def _handle_inode(st, dirs_cache, inodes, path):
    inode_key = (st.st_dev, st.st_ino)
    if stat.S_ISDIR(st.st_mode):
        dirs_cache[path] = inode_key

    inode_value = HostINode.from_stat(st)
    inodes[inode_key] = inode_value
    return inode_key


def read_host_fs():
    os.chdir("foo")
    dirs_cache = dict()
    dentries = dict()
    inodes = dict()
    st = os.stat(".", follow_symlinks=False)
    _handle_inode(st, dirs_cache, inodes, ".")

    for dirname, dirnames, filenames, dfd in os.fwalk(".", topdown=True):
        dir_inode = dirs_cache[dirname]

        for basename in itertools.chain(filenames, dirnames):
            path = join(dirname, basename)
            st = os.stat(basename, dir_fd=dfd, follow_symlinks=False)
            dentry_key = (dir_inode, os.fsencode(basename))
            dentry_value = _handle_inode(st, dirs_cache, inodes, path)
            dentries[dentry_key] = dentry_value

    os.chdir("..")
    print("Done scanning")
    return inodes, dentries


@dataclass(eq=True, frozen=True, order=True)
class Dentry:
    dir_inode: int
    name: bytes
    inode: int


def produce_output_mapping(inodes, dentries) -> tuple[list[HostINode], list]:
    """Assigns inode numbers to all of the files seen on the filesystem.

    Returns:
      archive_inodes: a list of

    The inode numbers are implicit in the
    Produces a list
    """
    inodes_mapping = [(value, key) for key, value in inodes.items()]
    inodes_mapping.sort()

    # Maps on-host inodes to the inodes we've assigned (host-to-archive)
    h2a_mapping = dict()
    for (_, host_inode_no), mapped in zip(inodes_mapping, itertools.count()):
        h2a_mapping[host_inode_no] = mapped

    archive_dentries = list()
    for (dir_inode, filename), host_inode in dentries.items():
        archive_dentries.append(
            Dentry(
                dir_inode=h2a_mapping[dir_inode],
                name=filename,
                inode=h2a_mapping[host_inode],
            )
        )

    archive_dentries.sort()
    archive_inodes = [inode for (inode, _) in inodes_mapping]

    return archive_inodes, archive_dentries


def write_fit(out, inodes):
    for inode in inodes:
        buf = FITEntry.from_host_inode(inode)
        out.write(buf)


class NoOpCompressor:
    def compress_block(self, src):
        return src

    def decompress_block(self, src):
        return src


def _compress_dentry_block(block):
    ret = NoOpCompressor().compress_block(block)
    return ret


def _uncompress_dentry_block(fh, size):
    buf = fh.read(size)
    return NoOpCompressor().decompress_block(buf)


def _test_dentry_compression():
    for i in (0, 1, 2, 16):
        in_bytes = b"\x00" * i
        compressed = _compress_dentry_block(in_bytes)
        fh = io.BytesIO(compressed)
        fh.seek(0, SEEK_END)
        fh.write(b"\x00" * 20)
        fh.seek(0)
        back = _uncompress_dentry_block(fh, len(compressed))
        assert in_bytes == back


_test_dentry_compression()


def write_fdt_block(dentries):
    """Writes one block of the FDT from the supplied `dentries`

    Returns: (the completed block, a DentryIndex describing the block)
    """
    bytes_avail = 131072
    names = list()
    uncompressed = io.BytesIO()
    count = 0
    first = None
    # 56 * 18 bytes = 1008 bytes of FDT
    while dentries and count < 128:
        dentry = dentries.pop()
        last = FDTEntry.from_entry(dentry)
        if count == 0:
            first = last

        bytes_avail -= len(last)
        if bytes_avail <= 0:
            dentries.append(dentry)

        print(last)
        uncompressed.write(last)
        names.append(last.name)
        count += 1

    if count == 0:
        return None

    common_prefix = _shared_prefix(first.pk, last.pk)
    print("Prefix: ", common_prefix)
    # TODO: do something with this information

    ret = bytes([ctypes.c_uint8(count).value])
    ret += transform_block(uncompressed.getvalue(), ctypes.sizeof(FDTEntry))
    ret += b"".join(names)
    return (
        _compress_dentry_block(ret),
        first.pk,
        last.pk,
    )


def _compute_break(last, first):
    """Find a 'break' point that distinguishes two strings.

    Instead of storing full PKs, we can chop off any portion of the PK that doesn't
    distinguish from the previous block.
    """
    while not last.startswith(first):
        # very inefficient
        first, removed = first[:-1], first[-1]
    return first + bytes([removed])


def test_compute_break():
    assert _compute_break(b"test.abcd", b"test.abcde") == b"test.abcde"
    assert _compute_break(b"test.abcd", b"test.abce") == b"test.abce"
    assert _compute_break(b"test.10681", b"test.1069abcde") == b"test.1069"


def _shared_prefix(xs, ys):
    i = 0
    for (x, y) in zip(xs, ys):
        if x != y:
            break

        i += 1

    return xs[:i]


def test_shared_prefix():
    assert _shared_prefix("foobar", "foobaz") == "fooba"
    assert _shared_prefix("foobar", "") == ""
    assert _shared_prefix("foobar", "foo") == "foo"


test_compute_break()
test_shared_prefix()


def create_fdt_index_chunk(chunks_it, lengths_it):
    entries = []
    for i, fe in zip(range(128), chunks_it):
        entries.append(_compute_break(*fe))

    if not entries:
        return None

    lengths = (u64 * len(entries))()
    total_length = 0
    for i in range(len(entries)):
        chunk_length = next(lengths_it)
        total_length += chunk_length
        lengths[i] = chunk_length
        print("FDTIndex(pk={}, size={})".format(entries[i], chunk_length))

    total_length += next(lengths_it)
    break_chunk = None
    try:
        break_chunk = next(chunks_it)
    except StopIteration:
        pass

    break_at = _compute_break(*break_chunk) if break_chunk else None

    buf = bytes(lengths)
    buf = transform_block(buf, 8)
    fh = io.BytesIO(buf)
    fh.seek(0, SEEK_END)
    for entry in entries:
        fh.write(entry)

    return _compress_dentry_block(fh.getvalue()), total_length, break_at


def write_fdt(out, dentries):
    dentries.reverse()

    lengths = []
    firsts = []
    lasts = []
    while block_info := write_fdt_block(dentries):
        buf, first, last = block_info
        lengths.append(len(buf))
        firsts.append(first)
        lasts.append(last)
        out.write(buf)

    chunks_it = zip(lasts, firsts[1:])
    lengths_it = iter(lengths)
    nodes = []
    while chunk := create_fdt_index_chunk(chunks_it, lengths_it):
        buf, span, break_at = chunk
        nodes.append(TreeNode.create(span, len(buf), break_at))
        out.write(buf)

    # TODO: recursively build treenodes until they all fit in a single node
    # Store the tree height in the superblock
    for node in nodes:
        print(node)


def delta_encode(buf):
    last = buf[0]
    for i in range(1, len(buf)):
        current = buf[i]
        buf[i] = (current - last) % 256
        last = current


def undelta_encode(buf):
    for i in range(1, len(buf)):
        buf[i] = (buf[i] + buf[i - 1]) % 256


def transpose(in_buf, rows, columns):
    # Transpose from row-order to column-order
    # 0 1 2 3, 4 5 6 7, 8 9 A B becomes
    # 0 4 8, 1 5 9, 2 6 A, 3 7 B

    buf = bytearray(len(in_buf))
    for i in range(rows):
        for j in range(columns):
            buf[j * rows + i] = in_buf[i * columns + j]

    return buf


def transform_block(in_buf, stride):
    rows = len(in_buf) // stride
    buf = bytearray(in_buf)

    buf = transpose(buf, rows, stride)
    delta_encode(buf)
    return bytes(buf)


def untransform_block(in_buf, stride):
    rows = len(in_buf) // stride
    buf = bytearray(in_buf)

    # Delta-unencode
    undelta_encode(buf)
    buf = transpose(buf, stride, rows)
    return bytes(buf)


def transform_bytes(in_b, out_b, stride, rows):
    compressor = LZ4Compressor()
    out_buf = io.BytesIO()
    c_bytes = 0
    u_bytes = 0
    elapsed = 0
    while True:
        for i in range(128):
            if not (in_buf := in_b.read(stride * rows)):
                break

            block = transform_block(in_buf, stride)
            back = untransform_block(block, stride)
            assert in_buf == back
            out_buf.write(block)

        u_bytes += len(out_buf.getvalue())
        start = process_time()
        compressed = compressor.compress_block(out_buf.getvalue())
        elapsed += process_time() - start
        c_bytes += len(compressed)
        out_b.write(ctypes.c_uint16(len(compressed)))
        out_b.write(compressed)
        out_buf = io.BytesIO()
        if not in_buf:
            break
    print(
        f"U: {u_bytes}B, C: {c_bytes}B, Ratio: {u_bytes / c_bytes}, Speed: {elapsed}s"
    )


def main():
    args = read_host_fs()
    inodes, dentries = produce_output_mapping(*args)

    inodes_rows = io.BytesIO()
    write_fit(inodes_rows, inodes)
    inodes_rows.seek(0)

    dentries_fh = io.BytesIO()
    stride = ctypes.sizeof(FITEntry)
    with open("archive", "wb") as fh:
        transform_bytes(inodes_rows, fh, stride, 16)
        write_fdt(fh, dentries)


raise SystemExit(main())
