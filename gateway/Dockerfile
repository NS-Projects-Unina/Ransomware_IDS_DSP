
FROM debian:trixie-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       suricata \
       nftables \
       iproute2 \
       iputils-ping \
       tcpdump \
       python3 \
       ca-certificates \
    && rm -rf /var/lib/apt/lists/*

CMD ["tail", "-f", "/dev/null"]
