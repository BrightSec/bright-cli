# Linux toolchain for the PKCS#11 tests; keep the package list in sync with .github/workflows/pkcs11.yml.
FROM node:24-trixie

RUN apt-get update -yq \
  && apt-get install -yq --no-install-recommends \
    softhsm2 \
    opensc \
    pkcs11-provider \
    libengine-pkcs11-openssl \
    openssl \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app
