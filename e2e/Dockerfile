# syntax=docker/dockerfile:1.7

FROM golang:1.25.5-trixie@sha256:1763926ff08117bdf4c76182c02fecbcfc3086771169b2a03574273dde17fcee

ARG CHUTNEY_COMMIT=6cc158868d722e652975cb4efd5b278d95ff2fbb
ARG LYREBIRD_SHA256=ee13ec155cf9b131a3e1b87bd6d697a10c42d04f2eaaeab6b1590c9971d41421

RUN apt-get update \
    && apt-get install --yes --no-install-recommends \
        python3 \
        python3-cryptography \
        python3-networkx \
        python3-paramiko \
        python3-rpyc \
        python3-tomli-w \
        python3-typeguard \
        iproute2 \
        nftables \
        tor \
    && rm -rf /var/lib/apt/lists/*

ADD --checksum=sha256:08d49de27f542b8f73e2014e064d8320562b5d20019c03d4725c5a5249d97985 \
    https://archive.torproject.org/tor-package-archive/torbrowser/15.0.23/tor-expert-bundle-linux-x86_64-15.0.23.tar.gz \
    /tmp/tor-expert-bundle.tar.gz

RUN mkdir -p /opt/tor \
    && tar -xzf /tmp/tor-expert-bundle.tar.gz -C /opt/tor \
    && rm /tmp/tor-expert-bundle.tar.gz \
    && echo "$LYREBIRD_SHA256  /opt/tor/tor/pluggable_transports/lyrebird" | sha256sum --check --strict \
    && chmod -R a+rX /opt/tor \
    && ln -s /opt/tor/tor/pluggable_transports/lyrebird /usr/bin/obfs4proxy

RUN git init /opt/chutney \
    && git -C /opt/chutney remote add origin https://gitlab.torproject.org/tpo/core/chutney.git \
    && git -C /opt/chutney fetch --depth 1 origin "${CHUTNEY_COMMIT}" \
    && git -C /opt/chutney checkout --detach FETCH_HEAD \
    && rm -rf /opt/chutney/.git

WORKDIR /workspace
COPY go.mod go.sum ./
RUN go mod download
COPY . .

RUN go build -o /usr/local/bin/pt-fixture ./e2e/pt-fixture \
    && ln -s /usr/local/bin/pt-fixture /usr/local/bin/pt-crash \
    && ln -s /usr/local/bin/pt-fixture /usr/local/bin/pt-no-proxy \
    && ln -s /usr/local/bin/pt-fixture /usr/local/bin/pt-escape

RUN useradd --create-home --uid 1000 tor-test \
    && mkdir -p /home/tor-test/.cache/go-build \
    && chown -R tor-test:tor-test /home/tor-test

ENV CHUTNEY_DATA_DIR=/tmp/chutney \
    CHUTNEY_DISABLE_IPV6=1 \
    CHUTNEY_DNS_CONF=/dev/null \
    CHUTNEY_PATH=/opt/chutney \
    CHUTNEY_START_TIME=300 \
    CHUTNEY_TOR=/opt/tor/tor/tor \
    CHUTNEY_TOR_GENCERT=/usr/bin/tor-gencert \
    CHUTNEY_TOR_SANDBOX=0 \
    GOCACHE=/home/tor-test/.cache/go-build \
    TOR_BINARY=/opt/tor/tor/tor \
    TOR_OBFS4_BINARY=/opt/tor/tor/pluggable_transports/lyrebird \
    TOR_PT_FIXTURE_CRASH=/usr/local/bin/pt-crash \
    TOR_PT_FIXTURE_NO_PROXY=/usr/local/bin/pt-no-proxy \
    TOR_PT_FIXTURE_ESCAPE=/usr/local/bin/pt-escape

USER tor-test:tor-test
ENTRYPOINT ["./e2e/container-run.sh"]
