#!/usr/bin/env python3
"""
* Right now LZMA decoding takes up most of the time. Parallelize it? Python's LZMA
  library does release the GIL.
"""
import json
import gzip
import lzma
import os
import random
import re
import sys
import tarfile
import threading
import time
from argparse import ArgumentParser
from concurrent.futures import as_completed
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from contextlib import ExitStack
from dataclasses import dataclass
from hashlib import sha256
from http.client import HTTPConnection
from http.client import RemoteDisconnected
from http.cookiejar import http2time
from io import BytesIO
from os import path
from pathlib import Path
from subprocess import check_output
from subprocess import DEVNULL
from subprocess import PIPE
from subprocess import Popen
from tarfile import TarInfo
from tempfile import NamedTemporaryFile
from urllib.parse import urlparse
from wsgiref.handlers import format_date_time

from lib.assemble import create_filesystem

NUL = b"\0"
BLOCKSIZE = tarfile.BLOCKSIZE
CACHE_PATH = Path("debs")
GNUPG_PREFIX = b"[GNUPG:] "
PACKAGES_PREFERENCE = {".xz": lzma.open, ".gz": gzip.open, "": lambda f, mode: f}
THIRD_STAGE = r"""
# Make suitable for VM use
passwd -d root
ln -s /lib/systemd/systemd /sbin/init
ln -s /lib/systemd/system/systemd-networkd.service \
    /etc/systemd/system/multi-user.target.wants/systemd-networkd.service

cat << EOF > /etc/systemd/network/ens.network
[Match]
Name=!lo*

[Network]
DHCP=yes

[DHCPv4]
UseHostname=no
EOF
"""



class GPGVNotFoundError(Exception):
    pass


def stderr(*args, **kwargs):
    kwargs["file"] = sys.stderr
    return print(*args, **kwargs)


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

    # VM dependencies
    unprocessed.add("systemd")
    unprocessed.add("linux-image-virtual")
    unprocessed.add("udev")

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

def download_file(netloc, url, out_fh):
    r = fetch_http(netloc, url)
    if r.status != 200:
        raise RuntimeError(r.status)

    return copy_file_sha256(r, out_fh)

def download_files(parsed_archive_url, packages):
    executor = ThreadPoolExecutor(8)

    futures = dict()
    for info in packages:
        url = parsed_archive_url.path + info["Filename"]
        destination = CACHE_PATH / Path(parsed_archive_url.netloc + "/" + url)
        if destination.exists():
            stderr(f"Destination {destination} already exists. Skipping.")
            yield destination
            continue

        destination.parent.mkdir(exist_ok=True, parents=True)
        temp_fh = NamedTemporaryFile(dir=destination.parent)
        fut = executor.submit(download_file, parsed_archive_url.netloc, url, temp_fh)
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
    container_id = check_output(["docker", "create", "--net=none", image_id, "/init"]).rstrip()

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

    def close(self):
        self._fh.close()

    @property
    def hash_time(self):
        return self._hash_timer.value

    @property
    def write_time(self):
        return self._write_timer.value



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

    if ti.name == "etc/resolv.conf":
        # Docker leaves this in even though we specify --net=none
        # I hate Docker
        return False

    original_entry = fs._files.get(ti.name)
    if original_entry:
        original_mtime = original_entry[0].mtime
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

    ti = TarInfo("etc/resolv.conf")
    ti.type = tarfile.SYMTYPE
    ti.linkname = "/run/systemd/resolve/stub-resolv.conf"
    out_fh.write(ti.tobuf())

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
            p = Popen(
                [
                    "gpgv",
                    "-q",
                    "--status-fd",
                    "1",
                    "--keyring",
                    f"keyrings/{keyring}.gpg",
                    sig_r.dev_name,
                    cont_r.dev_name,
                ],
                pass_fds=(sig_r.fileno(), cont_r.fileno()),
                stdout=PIPE,
                stderr=DEVNULL,
            )
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
            op = line[len(GNUPG_PREFIX) : -1]
            if op == b"NEWSIG":
                if good_to_return():
                    return ret
                ret.clear()
                continue

            opcode, rest = op.split(maxsplit=1)
            ret[opcode] = rest

        if good_to_return():
            return ret


def gpg_verify(keyring, name, signature, contents):
    sig_info = _gpg_verify(keyring, signature, contents)
    if sig_info is None:
        raise RuntimeError("gpg validation failed")

    stderr(f"From GPG for '{name}':")
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


def fetch_http(netloc, path, follow_redirects=1, **kwargs):
    try:
        conns = threadlocals.conns
    except AttributeError:
        conns = dict()
        threadlocals.conns = conns

    while True:
        try:
            conn = conns[netloc]
        except KeyError:
            conn = HTTPConnection(netloc)
            conns[netloc] = conn

        conn.request("GET", path, **kwargs)

        try:
            r = conn.getresponse()
        except RemoteDisconnected:
            pass
        else:
            break

    if r.status == 302 and follow_redirects > 0:
        r.read()
        parsed = urlparse(r.headers["Location"])
        return fetch_http(parsed.netloc, parsed.path, follow_redirects - 1, **kwargs)

    return r


def download_cached(netloc, path):
    destination = CACHE_PATH / (netloc + path)
    try:
        stat = destination.stat()
    except FileNotFoundError:
        stat = None

    headers = dict()
    if stat:
        headers["If-Modified-Since"] = format_date_time(stat.st_mtime)

    r = fetch_http(netloc, path, headers=headers)
    stderr(f"HTTP {r.status} for {netloc}{path}")
    if r.status == 304:
        r.read()
        return destination.read_bytes()

    if r.status != 200:
        raise RuntimeError(r.status)

    ret = r.read()
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(ret)
    mtime = int(http2time(r.headers["Date"]))
    os.utime(destination, (mtime, mtime))
    return ret


def get_release_fetcher(keyring, netloc, dist_path):
    name = dist_path + "Release"
    cache_path = CACHE_PATH / netloc / dist_path

    release = download_cached(netloc, name)
    release_gpg = download_cached(netloc, dist_path + "Release.gpg")
    gpg_verify(keyring, name, release_gpg, release)

    sha256sums = get_sha256sums(release)

    def repo_fetch(path):
        expected_checksum = sha256sums[path]
        contents = download_cached(netloc, dist_path + path)
        actual_checksum = sha256(contents).hexdigest()

        if expected_checksum != actual_checksum:
            raise RuntimeError(expected_checksum, actual_checksum)

        return contents

    return repo_fetch



def _get_packages(architecture, keyring, parsed_archive_url, suite):
    url = (parsed_archive_url.netloc, parsed_archive_url.path + f"dists/{suite}/")

    repo_fetch = get_release_fetcher(keyring, *url)
    for pref in PACKAGES_PREFERENCE:
        try:
            return pref, repo_fetch(f"main/binary-{architecture}/Packages{pref}")
        except KeyError:
            pass



def get_packages(*args):
    pref, contents = _get_packages(*args)
    opener = PACKAGES_PREFERENCE[pref]

    with opener(BytesIO(contents), "rt") as plain_f:
        return packages_dict(plain_f)


def get_all_packages_info(architecture, keyring, parsed_archive_url, suites):
    futs = []
    with ThreadPoolExecutor() as executor:
        for suite in suites:
            futs.append(executor.submit(get_packages, architecture, keyring, parsed_archive_url, suite))

    ret = dict()
    for fut in futs:
        ret.update(fut.result())

    return ret


def build_os(*, architecture, keyring, archive_url, suites):
    parsed_archive_url = urlparse(archive_url)
    packages_info = get_all_packages_info(architecture, keyring, parsed_archive_url, suites)

    stderr("Evaluating packages to download")
    packages = get_needed_packages(packages_info)

    stderr("Creating filesystem")
    deb_paths = download_files(parsed_archive_url, packages)
    sources_entries = [dict(archive_url=archive_url, suite=suite) for suite in suites]
    fs = create_filesystem(deb_paths, add_sources_list=sources_entries, third_stage=THIRD_STAGE)

    stderr("Writing image to docker import")
    docker_import_p = Popen(["docker", "import", "-"], stdin=PIPE, stdout=PIPE)
    with docker_import_p.stdin as fh:
        hasher = SHA256File(fh)
        with Timer() as timer:
            fs.write(hasher)
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


def main():
    ostype = sys.argv[1]
    if "." in ostype or "/" in ostype:
        raise RuntimeError(ostype)

    with open(f"definitions/{ostype}.json") as f:
        kwargs = json.load(f)

    kwargs.setdefault("architecture", "amd64")
    return build_os(**kwargs)


if __name__ == "__main__":
    raise SystemExit(main())
