Cross platform, rootless, and fast debootstrap

Designed to
 * work anywhere you can run Python and Docker/Podman (e.g. a Mac laptop)
 * produce completely reproducible (byte-for-byte) output

Tested to produce images for:
 * Debian (bullseye and sid)
 * Ubuntu (focal, jammy, noble)
 * Kali (rolling and last-snapshot)

# Dependencies 

* A Docker-compatible commandline client at `docker`.
* a `gpgv` binary, for signature verification.
* PyYAML
* `pip install zstandard`, but only if you want to use debs that contain
.zst compressed members.

# Cross-compilation

By installing qemu-user-static, you can build images for multiple architectures
on your local architecture.
