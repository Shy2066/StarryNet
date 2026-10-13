ARG DEBIAN_BASE=debian:bookworm-slim
ARG DEBIAN_MIRROR=ftp.de.debian.org
FROM ${DEBIAN_BASE}

ARG DEBIAN_MIRROR
ARG TOR_PACKAGE_VERSION=0.4.9.11-0+deb12u1
ARG STEM_PACKAGE_VERSION=1.8.1-2.1

ENV DEBIAN_FRONTEND=noninteractive

RUN sed -i "s|deb.debian.org|${DEBIAN_MIRROR}|g; s|security.debian.org|${DEBIAN_MIRROR}|g" \
        /etc/apt/sources.list.d/debian.sources \
    && apt-get -o Acquire::Retries=4 -o Acquire::http::Timeout=60 update \
    && apt-get install --yes --no-install-recommends \
        ca-certificates \
        curl \
        firefox-esr \
        python3 \
        python3-stem=${STEM_PACKAGE_VERSION} \
        iproute2 \
        iptables \
        tcpdump \
        tor=${TOR_PACKAGE_VERSION} \
        tor-geoipdb=${TOR_PACKAGE_VERSION} \
    && rm -rf /var/lib/apt/lists/* \
    && dpkg-query -W -f='${Package}=${Version}\n' tor tor-geoipdb python3-stem iproute2 iptables firefox-esr \
        > /etc/p2-tor-packages.txt

CMD ["sleep", "infinity"]
