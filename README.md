Cross platform, rootless, and fast debootstrap

Designed to work anywhere you can run Python and Docker/Podman (e.g. a Mac laptop).

Designed to produce completely reproducible (byte-for-byte) output.

# Dependencies 

A Docker-compatible commandline client at `docker`.

`pip install zstandard`, but only if you want to use debs that contain
.zst compressed members.
