#!/usr/bin/env python3
"""Cross platform, rootless, and fast debootstrap.

Designed to work anywhere you can run Python and Docker/Podman (e.g. a Mac laptop).

* Tested only with Ubuntu Focal and Jammy
* Right now LZMA decoding takes up most of the time. Parallelize it? Python's LZMA
  library does release the GIL.

"""
import ctypes
import lzma
import os
import random
import requests
import re
import sys
from contextlib import contextmanager
from enum import Enum
from pathlib import Path
from dataclasses import dataclass
from fnmatch import fnmatch
from hashlib import sha256
from io import BytesIO
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import as_completed
from os import path
from subprocess import Popen
from subprocess import check_call
from subprocess import check_output
from subprocess import PIPE
from tarfile import TarInfo
from tempfile import NamedTemporaryFile
from zstandard import ZstdDecompressor
import shutil
import tarfile

def tarinfo_repr(self):
    info = dict()
    for a in self.__slots__:
        try:
            info[a] = getattr(self, a)
        except AttributeError:
            pass
    return "TarInfo(**{0:})".format(info)

TarInfo.__repr__ = tarinfo_repr

ARCHIVE_URL = "http://archive.ubuntu.com/ubuntu/"
SUITE = "focal"
ARCHIVE_SUFFIX = f"dists/{SUITE}/main/binary-amd64/Packages.xz"
NUL = b"\0"
BLOCKSIZE = tarfile.BLOCKSIZE

if False:
    orig_getcomptype = tarfile._StreamProxy.getcomptype
    def getcomptype(self):
        print(self.buf[:4])
        if self.buf.startswith(b"\xFD\x2F\xB5\x28"):
            return "zstd"
        return orig_getcomptype(self)

@classmethod
def zstdopen(cls, name, mode="r", fileobj=None, **kwargs):
    dctx = ZstdDecompressor()
    fileobj = dctx.stream_reader(fileobj)
    try:
        t = cls.taropen(name, mode, fileobj, **kwargs)
    except:
        fileobj.close()
        raise
    t._extfileobj = False
    return t

tarfile.TarFile.zstdopen = zstdopen
tarfile.TarFile.OPEN_METH["zstd"] = "zstdopen"


SECOND_STAGE="""\
#!/bin/bash
set -e

cat << EOF > /usr/bin/policy-rc.d
#!/bin/sh
exit 101
EOF
chmod 755 /usr/bin/policy-rc.d

echo "Making control file" >&2
cd /var/lib/dpkg/info
for f in *.control; do
  cat $f
  echo
done > /var/lib/dpkg/status
rm -r *.control

# SOURCE_DATE_EPOCH makes /etc/shadow reproducible
export DEBIAN_FRONTEND=noninteractive SOURCE_DATE_EPOCH=0

set -x
for script in *.preinst; do
  package_fullname="${script//.preinst}"
  package_name="${package_fullname//:*}"
  DPKG_MAINTSCRIPT_NAME=preinst \
  DPKG_MAINTSCRIPT_PACKAGE=$package_name \
  ./"$script" install
done

cd /
# libc6's postinst requires `which`, which is configured via update-alternatives(1)
dpkg --configure --force-depends debianutils
dpkg --configure -a

rm /etc/passwd- /etc/group- /etc/shadow- \
  /var/cache/debconf/*-old /var/lib/dpkg/*-old \
  /init
# This cache is not reproducible
rm /var/cache/ldconfig/aux-cache
# Some log files (e.g. btmp) need to exist with the right modes, so we truncate them
# instead of deleting them.
find /var/log -type f -exec truncate -s0 {} \;
"""

SECOND_STAGE += f"echo deb http://archive.ubuntu.com/ubuntu/ {SUITE} main > /etc/apt/sources.list\n"

FIELDS = (
    "Package",
    "Filename",
    "Version",
    "Priority",
    "SHA256",
    "Depends",
    "Pre-Depends",
)
FIELDS_MATCHER = re.compile("^({}): (.*)$".format("|".join(FIELDS)))

def is_excluded(name):
    if name.startswith("usr/share/doc/"):
        return True
    
    if name.startswith("usr/share/man/"):
        return True

    return fnmatch(name, "usr/share/locale/*/LC_MESSAGES/*.mo")


def packages_dict(packages):
    ret = {}
    package = {}
    for line in packages:
        if line == "\n" and package:
            ret[package["Package"]] = package
            package = dict()
 
        match = FIELDS_MATCHER.match(line)
        if match:
            key, value = match.group(1), match.group(2)
            package[key] = value

    if package:
        ret[package["Package"]] = package

    return ret


def get_dependencies(info):
    deps = []
    deps += info.get("Depends", "").split(",")
    deps += info.get("Pre-Depends", "").split(",")
    ret = []
    for dep in deps:
        if dep == "":
            continue

        ret.append(dep.strip().split()[0])

    return ret


def get_needed_packages():
    with requests.get(ARCHIVE_URL + ARCHIVE_SUFFIX, stream=True) as r:
        r.raise_for_status()
       
        with lzma.open(r.raw, "rt") as plain_f:
            packages_info = packages_dict(plain_f)

    required = set()
    unprocessed = set([k for k, v in packages_info.items() if v["Priority"] == "required"])
    unprocessed.add("apt")
    unprocessed.add("gpgv")

    while unprocessed:
        name = unprocessed.pop()

        try:
            info = packages_info[name]
        except KeyError:
            continue

        required.add(name)
        for dep in get_dependencies(info):
            if dep in required:
                continue

            if dep in unprocessed:
                continue

            print("Adding dependency {} from {}".format(dep, name), file=sys.stderr)
            unprocessed.add(dep)

    ret = [packages_info[name] for name in required]
    random.shuffle(ret)
    return ret

def copy_file_sha256(src, dst):
    hasher = sha256()
    while True:
        buf = src.read(1024 * 1024)
        hasher.update(buf)
        if not buf:
            break
        dst.write(buf)
    dst.flush()
    return hasher.hexdigest()


def download_file(url, out_fh):
    with requests.get(url, stream=True) as resp:
        resp.raise_for_status()
        return copy_file_sha256(resp.raw, out_fh)


KNOWN_EXTENSIONS = {".xz", ".gz", ".bz2"}
WANTED_LINES = set(["Package", "Architecture", "Multi-Arch"])


def _get_dpkg_name(control):
    if control.get("Multi-Arch", None) == "same":
        return "{}:{}".format(control["Package"], control["Architecture"])

    return control["Package"]


def parse_control_data(data):
    lines = data.splitlines(True)
    parsed = dict()
    insert_at = 1
    for idx, line in enumerate(lines):
        parts = line.split(": ")
        if len(parts) < 2:
            continue
        if parts[0] in WANTED_LINES:
            parsed[parts[0]] = parts[1].rstrip()

        if parts[0] == "Priority":
            insert_at = idx
           
    # the table at lib/dpkg/parse.c seems to determine the "correct" order
    # of fields, but we just drop this last.
    lines.append("Status: install ok unpacked\n")

    name = _get_dpkg_name(parsed)
    return (
        "var/lib/dpkg/info/{}.".format(name),
        "".join(lines).encode()
    )


def _dpkg_info_files(prefix, control_data, tf):
    control_info = TarInfo(prefix + "control")
    control_info.size = len(control_data)
    yield control_info, control_data

    for member, file_contents in tf:
        if not member.isreg():
            continue

        name = member.name.lstrip("./")
        if name == "control":
            continue
        member.name = prefix + name
        yield member, file_contents

def extract_whole_tar(contents):
    tf = tarfile.open(fileobj=BytesIO(contents))
    ret = dict()
    for ti in tf:
        inner_fh = tf.extractfile(ti)
        file_data = None if inner_fh is None else inner_fh.read()
        ret[ti.name] = (ti, file_data)
    return ret

def handle_control_tar(contents):
    data = extract_whole_tar(contents)
    control_data = data["./control"][1].decode()
    prefix, new_control_data = parse_control_data(control_data)
    return prefix, _dpkg_info_files(prefix, new_control_data, data.values())

def transform_name(name):
    if name == "":
        # I have no idea why dpkg does this
        return "/.\n"

    return "/" + name + "\n"

def unpack_ar(fh):
    assert fh.read(8) == b"!<arch>\n"
    prefix = None
    files = []
    while True:
        pos = fh.tell()
        header = fh.read(60)
        if not header:
            break

        name = header[0:16]

        size = int(header[48:58], 10)
        assert header[58:60] == b"\x60\x0A"
        file_contents = fh.read(size)
        fh.read(size % 2)

        if name.startswith(b"data.tar"):
            tf = tarfile.open(fileobj=BytesIO(file_contents))
            for member in tf:
                contents = tf.extractfile(member).read() if member.isreg() else None
                member.name = member.name.lstrip("./")
                files.append(transform_name(member.name))
                yield member, contents

        if name.startswith(b"control.tar"):
            prefix, dpkg_files = handle_control_tar(file_contents)
            yield from dpkg_files

    if prefix is None:
        raise RuntimeError("Missing control file?")

    # This becomes the dpkg .list info file
    files_manifest = "".join(files).encode()
    info = TarInfo(prefix + "list")
    info.size = len(files_manifest)
    yield info, files_manifest


class Filesystem:
    def __init__(self):
        self._files = dict()

    def mkdir(self, name):
        ti = TarInfo(name)
        ti.type = tarfile.DIRTYPE
        ti.mode = 0o755
        self.add(ti)

    def symlink(self, name, target):
        ti = TarInfo(name)
        ti.type = tarfile.SYMTYPE
        ti.linkname = target
        self.add(ti)

    def file(self, name, contents, mode=None):
        ti = TarInfo(name)

        if isinstance(contents, str):
            contents = contents.encode()

        ti.size = len(contents)
        if mode is not None:
            ti.mode = mode
        self.add(ti, BytesIO(contents))

    def mknod(self, name, major, minor):
        ti = TarInfo(name)
        ti.type = tarfile.CHRTYPE
        ti.devmajor = major
        ti.devminor = minor
        self.add(ti)

    def resolve(self, name):
        try:
            entry = self._files[name]
        except KeyError:
            return name

        info, fh = entry
        if not info.issym():
            return name

        dirname = path.dirname(name)
        target = path.normpath(path.join(dirname, info.linkname))
        return self.resolve(target)

    def _build_path(self, name):
        ret = ""
        components = name.split("/")[::-1]
        while components:
            c = components.pop()
            ret = self.resolve(path.join(ret, c))

        return ret

    def add(self, ti, fileobj=None):
        ti.name = self._build_path(ti.name)
        ti.uname = ""
        ti.gname = ""

        if ti.name in self._files:
            existing, _ = self._files[ti.name]
            existing.mtime = max(existing.mtime, ti.mtime)

            if extract_useful(ti) != extract_useful(existing):
                raise RuntimeError(ti.name)

            return

        if ti.name == "":
            return

        self._files[ti.name] = (ti, fileobj)

def extract_useful(ti):
    return (ti.name, ti.mode, ti.uid, ti.gid, ti.size, ti.type, ti.uname, ti.gname, ti.pax_headers)

def download_files(packages):
    executor = ThreadPoolExecutor(8)

    futures = dict()
    for info in packages:
        url = ARCHIVE_URL + info["Filename"]
        destination = Path("debs/" + path.basename(info["Filename"]))
        if destination.exists():
            print(f"Destination {destination} already exists. Skipping.")
            yield destination
            continue

        temp_fh = NamedTemporaryFile(dir=destination.parent)
        fut = executor.submit(download_file, url, temp_fh)
        futures[fut] = (info, temp_fh, destination)

    for future in as_completed(futures):
        info, temp_fh, destination = futures[future]
        name = info["Package"]
        try:
            digest = future.result()
        except Exception as exc:
            print('%r generated an exception: %s' % (name, exc), file=sys.stderr)
            continue

        if digest != info["SHA256"]:
            raise RuntimeError("Corrupted download of {}".format(name))

        os.link(temp_fh.name, destination)
        print(f"Downloaded {destination}")
        yield destination


def get_debs_from_directory(paths):
    for deb in paths:
        yield deb.open("rb")


def get_unpacked_files(fhs):
    for fh in fhs:
        yield from unpack_ar(fh)
        fh.close()

def main():
    print("Evaluating packages to download")
    packages = get_needed_packages()

    print("Creating filesystem")
    deb_paths = download_files(packages)
    fs = create_filesystem(deb_paths)

    print("Writing image to docker import")
    docker_import_p = Popen(["docker", "import", "-"], stdin=PIPE, stdout=PIPE)
    with docker_import_p.stdin as fh:
        write_image(fs, fh)
    image_id = docker_import_p.stdout.read().rstrip()
    ret = docker_import_p.wait()
    if ret != 0:
        raise RuntimeError("Couldn't docker import")

    print("Running container for second stage installation")
    container_id = check_output(["docker", "create", image_id, "/init"]).rstrip()
    check_call(["docker", "start", "-a", container_id])
    docker_export_p = Popen(["docker", "export", container_id], stdout=PIPE)

    print("Running docker export and performing output filtering")
    with NamedTemporaryFile(dir=".") as out_fh:
        output_filter(fs, docker_export_p.stdout, out_fh)
        if docker_export_p.wait() != 0:
            raise RuntimeError("Couldn't docker export")
        out_fh.flush()
        os.link(out_fh.name, "root.tar.new")
        os.rename("root.tar.new", "root.tar")



def create_vestigial_files():
    # Not called.
    # Debootstrap creates these files, but I haven't found them to be necessary.
    # ...or something else also creates them
    fs.mkdir("var/lib/dpkg")

    fs.mkdir("etc")

    fs.mknod("dev/null", 1, 3)
    fs.mknod("dev/zero", 1, 5)
    fs.mknod("dev/full", 1, 7)
    fs.mknod("dev/random", 1, 8)
    fs.mknod("dev/urandom", 1, 9)
    fs.mknod("dev/tty", 1, 0)
    fs.mknod("dev/console", 5, 1)
    fs.mknod("dev/ptmx", 5, 2)

    fs.mkdir("dev/pts")
    fs.mkdir("dev/shm")

    fs.symlink("dev/fd", "/proc/self/fd")
    fs.symlink("dev/stdin", "/proc/self/fd/0")
    fs.symlink("dev/stdout", "/proc/self/fd/1")
    fs.symlink("dev/stderr", "/proc/self/fd/2")


def create_filesystem(deb_names):
    fs = Filesystem()
    fs.file("init", SECOND_STAGE, mode=0o755)

    # These files will get created by dpkg as well..mostly.
    # There's a risk that zero packages will install these files.
    # Which is why we create them manually
    for name in ("bin", "sbin", "lib", "lib32", "lib64", "libx32"):
        real = f"usr/{name}"
        fs.mkdir(real)
        fs.symlink(name, real)

    debs = get_debs_from_directory(deb_names)
    for member, contents in get_unpacked_files(debs):
        fs.add(member, BytesIO(contents))

    return fs


def write_image(fs, out_fh):
    files = fs._files
    for name in sorted(files):
        info, fh = files[name]
        if not info.isdir() and is_excluded(name):
            continue

        out_fh.write(info.tobuf())
        if info.size == 0:
            continue

        tarfile.copyfileobj(fh, out_fh, info.size)
        blocks, remainder = divmod(info.size, BLOCKSIZE)
        if remainder > 0:
            out_fh.write(NUL * (BLOCKSIZE - remainder))


class NullFile:
    @staticmethod
    def write(buf):
        pass

def roundup_block(size):
    blocks = (size + 511) >> 9
    return blocks << 9


OutputAction = Enum("OutputAction", 'NOTHING TRUNCATE ALL')


def mutate_file(fs, ti):
    if ti.name == ".dockerenv":
        return OutputAction.NOTHING

    original_entry = fs._files.get(ti.name)
    if original_entry:
        original_mtime = original_entry[0].mtime
        if original_mtime != ti.mtime:
            ti.mtime = original_mtime
    else:
        ti.mtime = 0

    return OutputAction.ALL


def output_filter(fs, in_fh, out_fh):
    while True:
        buf = in_fh.read(BLOCKSIZE)
        try:
            ti = TarInfo.frombuf(buf, tarfile.ENCODING, "surrogateescape")
        except tarfile.EOFHeaderError:
            break

        len_to_read = roundup_block(ti.size)
        output_action = mutate_file(fs, ti)

        if output_action is not OutputAction.NOTHING:
            out_fh.write(ti.tobuf())

        destination = out_fh if output_action is OutputAction.ALL else NullFile
        tarfile.copyfileobj(in_fh, destination, len_to_read)
            
    out_fh.write(NUL * (BLOCKSIZE * 2))


if __name__ == '__main__':
    raise SystemExit(main())
