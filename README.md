# wirefile

Read and write pcap and pcapng capture files, the formats Wireshark opens. Streaming reader with bounded memory, no stdio required.

## Build and install

```sh
cmake -S . -B build -DBUILD_SHARED_LIBS=ON
cmake --build build
cmake --install build --prefix /usr/local
```

Use it from CMake:

```cmake
find_package(wirefile REQUIRED)
target_link_libraries(app PRIVATE wirefile::wirefile)
```

Or with pkg-config:

```sh
cc app.c $(pkg-config --cflags --libs wirefile)
```

## Single-file form

`scripts/amalgamate.sh` writes `dist/wirefile.h`. Copy it into your project and, in exactly
one `.c` file:

```c
#define PCW_IMPLEMENTATION
#include "wirefile.h"
```

Define `PCW_STATIC` as well to keep every function private to that file.

## Usage

See [`examples/basic.c`](examples/basic.c). The header `include/wirefile/wirefile.h` is the
API reference.

Conventions:

- every function that can fail returns `PCW_OK` or an error code; `pcw_strerror` describes it
- what `pcw_x_create` returns is released only by `pcw_x_destroy`, which accepts `NULL`
- functions never take ownership of their arguments; returned pointers belong to the library
- pass your own allocator to `pcw_buf_create`, or `NULL` for `malloc`/`free`

## Versioning

Semantic Versioning. Compatible releases bump the minor version; incompatible ones bump the
major version and the soname. See [CHANGELOG.md](CHANGELOG.md).

## License

MIT, see [LICENSE](LICENSE).
