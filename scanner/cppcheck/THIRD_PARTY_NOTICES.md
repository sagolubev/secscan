# Cppcheck 2.21.1

Cppcheck is licensed under GNU GPL version 3 or later.
Source commit: 904cfdcf774c44b17db789c8a212e2f1c69fc833.
Source: https://github.com/danmar/cppcheck/tree/904cfdcf774c44b17db789c8a212e2f1c69fc833
Archive SHA-256: 90ae3b938521d49b2c583e3b04e75a805517a486a99143f77982067688b7b305.

The prepared image includes the matching complete source archive at
/usr/src/cppcheck.tar.gz, the build recipe at /usr/src/Dockerfile, and the
upstream license at /usr/share/licenses/cppcheck/COPYING. The source archive
contains additional upstream third-party notices and licenses.

The build uses GCC 15.2.0, pinned by the recipe. Its statically linked runtime
libraries carry the GCC Runtime Library Exception. Its verbatim text from
GCC releases/gcc-15.2.0/COPYING.RUNTIME is included in the image (SHA-256
9d6b43ce4d8de0c878bf16b54d8e7a10d9bd42b75178153e3af6a815bdc90f74).
The image also retains the compiler platform's glibc copyright and LGPL text.
The project does not distribute upstream Semgrep or Bearer images or rules.
