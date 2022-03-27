#!/usr/bin/env python3
"""
* Tested only with Ubuntu Focal and Jammy
* Right now LZMA decoding takes up most of the time. Parallelize it? Python's LZMA
  library does release the GIL.
"""
import fnmatch
from http.client import HTTPConnection
import lzma
import os
import random
import re
import sys
import tarfile
import threading
import time
from contextlib import closing
from contextlib import ExitStack
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from hashlib import sha256
from io import BytesIO
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import as_completed
from os import path
from subprocess import Popen
from subprocess import check_call
from subprocess import check_output
from subprocess import PIPE
from subprocess import DEVNULL
from tarfile import TarInfo
from tempfile import NamedTemporaryFile
from urllib.parse import urlparse
try:
    from zstandard import ZstdDecompressor
except ModuleNotFoundError:
    pass

KEYRING = "keyrings/ubuntu.gpg"
ARCHIVE_URL = "http://archive.ubuntu.com/ubuntu/"
PARSED_ARCHIVE_URL = urlparse(ARCHIVE_URL)
NUL = b"\0"
BLOCKSIZE = tarfile.BLOCKSIZE
CACHE_PATH = Path("debs")
GNUPG_PREFIX = b"[GNUPG:] "


class GPGVNotFoundError(Exception):
    pass

def stderr(*args, **kwargs):
    kwargs["file"] = sys.stderr
    return print(*args, **kwargs)

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


SECOND_STAGE = """\
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
  DPKG_MAINTSCRIPT_NAME=preinst \\
  DPKG_MAINTSCRIPT_PACKAGE=$package_name \\
  ./"$script" install
done

cd /
# libc6's postinst requires `which`, which is configured via update-alternatives(1)
dpkg --configure --force-depends debianutils
dpkg --configure -a

rm /etc/passwd- /etc/group- /etc/shadow- \\
  /var/cache/debconf/*-old /var/lib/dpkg/*-old \\
  /init
# This cache is not reproducible
rm /var/cache/ldconfig/aux-cache
# Some log files (e.g. btmp) need to exist with the right modes, so we truncate them
# instead of deleting them.
find /var/log -type f -exec truncate -s0 {} \\;
"""
ADD_SOURCES_LIST = f"echo deb {ARCHIVE_URL} {{suite}} main >> /etc/apt/sources.list\n"

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
LOCALE_MATCHER = re.compile(fnmatch.translate("usr/share/locale/*/LC_MESSAGES/*.mo"))

def is_excluded(name):
    if name.startswith("usr/share/doc/"):
        return True

    if name.startswith("usr/share/man/"):
        return True

    return bool(LOCALE_MATCHER.match(name))


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


def get_needed_packages(packages_info):
    required = set()
    unprocessed = set(
        [k for k, v in packages_info.items() if v["Priority"] == "required"]
    )
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

            stderr("Adding dependency {} from {}".format(dep, name), file=sys.stderr)
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


threadlocals = threading.local()

def download_file(url, out_fh):
    try:
        conn = threadlocals.conn
    except AttributeError:
        conn = HTTPConnection(PARSED_ARCHIVE_URL.netloc)
        threadlocals.conn = conn

    conn.request("GET", url)
    r = conn.getresponse()
    if r.status != 200:
        raise RuntimeError(r.status)
    return copy_file_sha256(r, out_fh)


WANTED_LINES = set(["Package", "Architecture", "Multi-Arch"])

def _get_dpkg_name(control):
    if control.get("Multi-Arch", None) == "same":
        return "{}:{}".format(control["Package"], control["Architecture"])

    return control["Package"]


def parse_control_data(data):
    lines = data.splitlines(True)
    parsed = dict()
    for idx, line in enumerate(lines):
        parts = line.split(": ", 1)
        if len(parts) != 2:
            continue

        k, v = parts
        if k in WANTED_LINES:
            parsed[k] = v.rstrip()

    # the table at lib/dpkg/parse.c seems to determine the "correct" order
    # of fields, but we just drop this last.
    # We assume that the next run of dpkg will fix it (it does)
    lines.append("Status: install ok unpacked\n")

    name = _get_dpkg_name(parsed)
    return ("var/lib/dpkg/info/{}.".format(name), "".join(lines).encode())


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
    return (
        ti.name,
        ti.mode,
        ti.uid,
        ti.gid,
        ti.size,
        ti.type,
        ti.uname,
        ti.gname,
        ti.pax_headers,
    )


def download_files(packages):
    CACHE_PATH.mkdir(exist_ok=True)
    executor = ThreadPoolExecutor(8)

    futures = dict()
    for info in packages:
        url = PARSED_ARCHIVE_URL.path + info["Filename"]
        destination = CACHE_PATH / Path(info["Filename"]).name
        if destination.exists():
            stderr(f"Destination {destination} already exists. Skipping.")
            yield destination
            continue

        temp_fh = NamedTemporaryFile(dir=destination.parent)
        fut = executor.submit(download_file, url, temp_fh)
        futures[fut] = (info, temp_fh, destination)

    for future in as_completed(futures):
        info, temp_fh, destination = futures[future]
        name = info["Package"]
        digest = future.result()
        if digest != info["SHA256"]:
            raise RuntimeError("Corrupted download of {}".format(name))

        os.link(temp_fh.name, destination)
        stderr(f"Downloaded {destination}")
        yield destination


def get_debs_from_directory(paths):
    for deb in paths:
        yield deb.open("rb")


def get_unpacked_files(fhs):
    for fh in fhs:
        yield from unpack_ar(fh)
        fh.close()




def create_filesystem(deb_names, add_sources_list: str):
    fs = Filesystem()

    second_stage = SECOND_STAGE
    for suite in add_sources_list:
        second_stage += ADD_SOURCES_LIST.format(suite=suite)

    fs.file("init", second_stage, mode=0o755)

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

def pretty_time(value):
    if value < 0.001:
        return "{:.2f} µs".format(value * 1_000_000)
    if value < 1:
        return "{:.2f} ms".format(value * 1_000)
    return "{:.2f} s".format(value)


class Timer:
    value = 0.0

    def __enter__(self):
        self.value -= time.perf_counter()
        return self

    def __exit__(self, *args):
        self.value += time.perf_counter()

    @property
    def fvalue(self):
        return pretty_time(self.value)


def second_stage(image_id):
    stderr("Running container for second stage installation")
    container_id = check_output(["docker", "create", image_id, "/init"]).rstrip()

    (r, w) = os.pipe()
    docker_start_p = Popen(["docker", "start", "-a", container_id], stdout=w, stderr=w)
    os.close(w)
    docker_output = []
    while True:
        buf = os.read(r, 1024 * 1024)
        if not buf:
            break

        docker_output.append(buf)
    os.close(r)

    retcode = docker_start_p.wait()
    if retcode != 0:
        for buf in docker_output:
            sys.stderr.buffer.write(buf)
        raise RuntimeError("Container failed")

    return container_id


class SHA256File:
    def __init__(self, fh):
        self._fh = fh
        self._hasher = sha256()
        self._hash_timer = Timer()
        self._write_timer = Timer()

    def write(self, buf):
        with self._hash_timer:
            self._hasher.update(buf)
        with self._write_timer:
            return self._fh.write(buf)

    def flush(self):
        self._fh.flush()

    def hexdigest(self):
        return self._hasher.hexdigest()

    @property
    def hash_time(self):
        return self._hash_timer.value

    @property
    def write_time(self):
        return self._write_timer.value


def write_file(out_fh, info, fh):
    if not info.isdir() and is_excluded(info.name):
        return

    out_fh.write(info.tobuf())
    tarfile.copyfileobj(fh, out_fh, info.size)
    blocks, remainder = divmod(info.size, BLOCKSIZE)
    if remainder == 0:
        return
    
    out_fh.write(NUL * (BLOCKSIZE - remainder))


def write_image(fs, out_fh):
    files = fs._files
    for name in sorted(files):
        write_file(out_fh, *files[name])



class NullFile:
    @staticmethod
    def write(buf):
        pass


def roundup_block(size):
    blocks = (size + 511) >> 9
    return blocks << 9


def mutate_file(fs, ti):
    if ti.name == ".dockerenv":
        return False

    original_entry = fs._files.get(ti.name)
    if original_entry:
        original_mtime = original_entry[0].mtime
        if original_mtime != ti.mtime:
            ti.mtime = original_mtime
    else:
        ti.mtime = 0

    return True


def output_filter(fs, in_fh, out_fh):
    while True:
        buf = in_fh.read(BLOCKSIZE)
        try:
            ti = TarInfo.frombuf(buf, tarfile.ENCODING, "surrogateescape")
        except tarfile.EOFHeaderError:
            break

        len_to_read = roundup_block(ti.size)
        destination = out_fh if mutate_file(fs, ti) else NullFile
        destination.write(ti.tobuf())
        tarfile.copyfileobj(in_fh, destination, len_to_read)

    out_fh.write(NUL * (BLOCKSIZE * 2))
    out_fh.flush()


def getresponse(conn, path):
    conn.request("GET", path)
    r = conn.getresponse()
    if r.status != 200:
        raise RuntimeError(r.status)

    return r.read()

@dataclass()
class OSFile:
    fd: int
    closed: bool = False

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def fileno(self):
        return self.fd

    def close(self):
        if self.closed:
            return

        os.close(self.fd)
        self.closed = True

    def write(self, data):
        os.write(self.fileno(), data)

    @property
    def dev_name(self):
        return f"/dev/fd/{self.fd}"

    @classmethod
    def make_pipe(cls):
        r, w = os.pipe()
        return cls(r), cls(w)


def _gpg_verify(keyring, signature, contents):
    sig_r, sig_w = OSFile.make_pipe()
    cont_r, cont_w = OSFile.make_pipe()
    with ExitStack() as s:
        for fd in (sig_r, sig_w, cont_r, cont_w):
            s.enter_context(fd)

        try:
            p = Popen([
                "gpgv", "-q",
                "--status-fd", "1",
                "--keyring", keyring,
                sig_r.dev_name,
                cont_r.dev_name,
            ], pass_fds=(sig_r.fileno(), cont_r.fileno()), stdout=PIPE, stderr=DEVNULL)
        except FileNotFoundError as e:
            raise GPGVNotFoundError from e

        sig_r.close()
        cont_r.close()

        sig_w.write(signature)
        sig_w.close()

        cont_w.write(contents)
        cont_w.close()

    ret = dict()
    def good_to_return():
        return b"GOODSIG" in ret and b"VALIDSIG" in ret

    with p:
        for line in p.stdout:
            if not line.startswith(GNUPG_PREFIX):
                continue

            # Trim prefix and newline
            op = line[len(GNUPG_PREFIX):-1]
            if op == b"NEWSIG":
                if good_to_return():
                    return ret
                ret.clear()
                continue

            opcode, rest = op.split(maxsplit=1)
            ret[opcode] = rest

        if good_to_return():
            return ret


def gpg_verify(keyring, signature, contents):
    sig_info = _gpg_verify(keyring, signature, contents)
    if sig_info is None:
        raise RuntimeError("gpg validation failed")

    stderr("From GPG:")
    for key, value in sig_info.items():
        stderr(f"{key.decode()}: {value.decode()}")


def get_sha256sums(release_file):
    release_file = BytesIO(release_file)
    checksums = dict()

    for line in release_file:
        if line == b"SHA256:\n":
            break

    for line in release_file:
        if not line.startswith(b" "):
            break

        checksum, _, filename = line.split()
        checksums[filename.decode()] = checksum.decode()

    return checksums

def _get_packages(suite):
    dist_path = PARSED_ARCHIVE_URL.path + f"dists/{suite}/"
    with closing(HTTPConnection(PARSED_ARCHIVE_URL.netloc)) as c:
        release = getresponse(c, dist_path + "Release")
        release_gpg = getresponse(c, dist_path + "Release.gpg")
        packages_xz = getresponse(c, dist_path + "main/binary-amd64/Packages.xz")

    gpg_verify(KEYRING, release_gpg, release)
    sha256sums = get_sha256sums(release)

    def repo_verify(path, contents):
        expected_checksum = sha256sums[path]
        actual_checksum = sha256(contents).hexdigest()
        if expected_checksum != actual_checksum:
            raise RuntimeError(expected_checksum, actual_checksum)

        return contents

    return repo_verify("main/binary-amd64/Packages.xz", packages_xz)


def get_packages(suite):
    contents = _get_packages(suite)
    with lzma.open(BytesIO(contents), "rt") as plain_f:
        return packages_dict(plain_f)


def main():
    suites = sys.argv[1:]

    packages = dict()
    for suite in suites:
        packages.update(get_packages(suite))

    stderr("Evaluating packages to download")
    packages = get_needed_packages(packages)

    stderr("Creating filesystem")
    deb_paths = download_files(packages)
    fs = create_filesystem(deb_paths, add_sources_list=suites)

    stderr("Writing image to docker import")
    docker_import_p = Popen(["docker", "import", "-"], stdin=PIPE, stdout=PIPE)
    with docker_import_p.stdin as fh:
        hasher = SHA256File(fh)
        with Timer() as timer:
            write_image(fs, hasher)
    timer.value -= hasher.hash_time + hasher.write_time
    stderr(f"Hashing took {pretty_time(hasher.hash_time)} seconds")
    stderr(f"Writing took {pretty_time(hasher.write_time)} seconds")
    stderr(f"Other tasks took {timer.fvalue}")

    stderr("SHA256 sent to docker: " + hasher.hexdigest())
    image_id = docker_import_p.stdout.read().rstrip()
    ret = docker_import_p.wait()
    if ret != 0:
        raise RuntimeError("Couldn't docker import")

    with Timer() as timer:
        container_id = second_stage(image_id)
    stderr(f"Second stage took {timer.fvalue}")

    docker_export_p = Popen(["docker", "export", container_id], stdout=PIPE)

    stderr("Running docker export and performing output filtering")
    with NamedTemporaryFile(dir=".") as out_fh:
        hasher = SHA256File(out_fh)
        output_filter(fs, docker_export_p.stdout, hasher)
        if docker_export_p.wait() != 0:
            raise RuntimeError("Couldn't docker export")
        os.link(out_fh.name, "root.tar.new")
        os.rename("root.tar.new", "root.tar")
    print("sha256:" + hasher.hexdigest())


if __name__ == "__main__":
    raise SystemExit(main())
