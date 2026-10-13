ARG DEBIAN_BASE=debian:bookworm-slim
FROM ${DEBIAN_BASE}

ARG TOR_PACKAGE_VERSION=0.4.9.11-0+deb12u1
ARG STEM_PACKAGE_VERSION=1.8.1-2.1

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install --yes --no-install-recommends \
        ca-certificates \
        curl \
        python3 \
        python3-stem=${STEM_PACKAGE_VERSION} \
        iproute2 \
        iptables \
        tcpdump \
        tor=${TOR_PACKAGE_VERSION} \
        tor-geoipdb=${TOR_PACKAGE_VERSION} \
    && rm -rf /var/lib/apt/lists/* \
    && dpkg-query -W -f='${Package}=${Version}\n' tor tor-geoipdb python3-stem iproute2 iptables \
        > /etc/p2-tor-packages.txt

CMD ["sleep", "infinity"]
