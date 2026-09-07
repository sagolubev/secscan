# syntax=docker/dockerfile:1@sha256:ecfaec9ed6d810b56388c508f4121597bfbba70d41a6dfeee4d8cad5f295fc32

ARG TARGETARCH

FROM alpine:3.22@sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce

ARG TARGETARCH

COPY rootfs-${TARGETARCH}/ /

LABEL org.opencontainers.image.source="https://github.com/sigiuscom/secscan" \
      org.opencontainers.image.version="1.29.0" \
      io.secscan.rules.digest="6389f1f651ceaa52527e17a7ed0675f2c0b2c1933ede4f3e80ac167b886851e8" \
      io.secscan.rules.count="8"

ENV HOME=/tmp
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/opengrep"]
