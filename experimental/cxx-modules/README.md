# C++ standard-library module metadata templates

These experimental `.pc.in` files describe the source module interface units
for `std` and `std.compat`. They are intended for standard-library maintainers
and distributors to configure and install alongside the matching toolchain;
pkgconf does not install them because their paths and versions belong to that
toolchain, not to pkgconf.

Replace every `@...@` token at packaging or toolchain build time. In
particular, `@MODULEDIR@` must be the installed directory containing the
source interfaces, and `@VERSION@` must identify the standard-library/toolset
version. The configured file should be installed in the toolchain's
pkg-config search path under the name shown below.

| Template | Suggested package name | Source files |
| --- | --- | --- |
| `libstdc++-modules.pc.in` | `libstdc++-modules` | `std.cc`, `std.compat.cc` |
| `libc++-modules.pc.in` | `libc++-modules` | `std.cppm`, `std.compat.cppm` |
| `msvc-stl-modules.pc.in` | `msvc-stl-modules` | `std.ixx`, `std.compat.ixx` |

The flags are deliberately limited to requirements intrinsic to the library
implementation. A build system remains responsible for selecting the matching
compiler, scanning dependencies, ordering `std` before `std.compat`, and
choosing locations and formats for compiler-generated module artifacts.

Example queries after configuring and installing a template:

```sh
pkgconf --cxx-modules libc++-modules
pkgconf --cxx-module-source=std libc++-modules
pkgconf --cxx-module-cflags=std.compat libc++-modules
```

These templates track an experimental metadata format and may change without
the compatibility guarantees of the established pkg-config fields.
