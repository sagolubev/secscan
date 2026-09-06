FROM docker.io/library/gcc:15.2.0@sha256:3ae15afe768b06d0c0fe088d822ba5f8045c26630bdacc8d8e7713cf5d8e7289 AS build
ENV SOURCE_DATE_EPOCH=1781913600
WORKDIR /src
COPY source.tar.gz /src/source.tar.gz
COPY Dockerfile THIRD_PARTY_NOTICES.md GCC-COPYING.RUNTIME /src/
RUN echo '90ae3b938521d49b2c583e3b04e75a805517a486a99143f77982067688b7b305  source.tar.gz' | sha256sum -c - && tar xzf source.tar.gz --strip-components=1 && make -j2 FILESDIR=/usr/share/cppcheck CXXFLAGS='-O2 -ffile-prefix-map=/src=.' LDFLAGS='-static -pthread' RDYNAMIC= && mkdir -p /rootfs/usr/bin /rootfs/usr/share/cppcheck /rootfs/usr/share/licenses/cppcheck /rootfs/usr/src && cp cppcheck /rootfs/usr/bin/ && cp -r cfg platforms /rootfs/usr/share/cppcheck/ && cp COPYING /rootfs/usr/share/licenses/cppcheck/ && cp source.tar.gz /rootfs/usr/src/cppcheck.tar.gz && cp Dockerfile THIRD_PARTY_NOTICES.md /rootfs/usr/src/ && cp /usr/share/doc/libc6/copyright /rootfs/usr/share/licenses/cppcheck/GLIBC-COPYRIGHT && cp GCC-COPYING.RUNTIME /rootfs/usr/share/licenses/cppcheck/ && cp /usr/share/common-licenses/GPL-3 /usr/share/common-licenses/LGPL-2.1 /rootfs/usr/share/licenses/cppcheck/ && find /rootfs -exec touch -h -d @1781913600 '{}' +
FROM scratch
COPY --from=build /rootfs/ /
USER 65532:65532
ENTRYPOINT ["/usr/bin/cppcheck"]
