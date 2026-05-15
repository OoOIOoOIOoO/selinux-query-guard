# selinux-query-guard

`selinux-query-guard` is a KernelPatch KPM module that hooks SELinux query-related paths and normalizes sensitive probe results when the module is loaded.

There are no runtime switches for verbose logging, simulation, or AV override. Loading the module installs the hooks immediately and enables result modification by default.

## Environment

Required build environment:

- KernelPatch source tree with this module placed under `kpms/selinux-query-guard`.
- AArch64 cross GCC toolchain that provides `aarch64-none-elf-gcc` or `aarch64-linux-android-gcc`.
- `TARGET_COMPILE` pointing to the toolchain prefix when the compiler is not in `PATH`, for example `/opt/toolchains/bin/aarch64-none-elf-`.
- `KP_DIR` pointing to the KernelPatch repository root. When building from this directory, the default `../..` is correct.

## Build

From this directory:

```sh
make
```

Or from another location:

```sh
make -C /path/to/KernelPatch/kpms/selinux-query-guard KP_DIR=/path/to/KernelPatch TARGET_COMPILE=/path/to/aarch64-none-elf-
```

Output:

```text
selinux_query_guard.kpm
```
