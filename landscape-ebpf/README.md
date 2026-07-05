# Landscape-ebpf
The set of eBPF programs used in landscape.

## Attribution

NATv4 was independently designed from the beginning. Some implementation-level functions are reused from the
[einat-ebpf](https://github.com/EHfive/einat-ebpf) project (GPL-2.0-or-later).

These reused parts include NAT packet-processing logic (header modification and checksum updates), IP fragment tracking, and some shared helpers, types and constants.

All reused code is properly attributed via SPDX headers in the corresponding source files.

## LICENSE
GPL-2.0-or-later