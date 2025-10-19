FROM debian:bookworm-20250721-slim@sha256:2424c1850714a4d94666ec928e24d86de958646737b1d113f5b2207be44d37d8

ADD --chmod=0755 --checksum=sha256:c125df9762b0c7233459087bb840c0e5dbfc4d9690ee227f1ed8994f4d51d2e0 \
    https://raw.githubusercontent.com/reproducible-containers/repro-sources-list.sh/v0.1.4/repro-sources-list.sh \
    /usr/local/bin/repro-sources-list.sh

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked --mount=type=cache,target=/var/lib/apt,sharing=locked \
    /usr/local/bin/repro-sources-list.sh && \
    apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install --no-install-recommends --yes \
        iproute2 python3 && \
    rm -f /usr/local/bin/repro-sources-list.sh

RUN useradd --no-create-home --home-dir / user

RUN echo 'flag{This is a fake flag, on the server you will find a real flag here}' > /flag && \
    chmod 004 /flag

COPY --chmod=0500 qdiscworld.sh /qdiscworld.sh
COPY --chmod=0005 server.py /server.py

RUN chmod 500 /usr/bin/su && \
    find / -ignore_readdir_race -type f \( -perm -4000 -o -perm -2000 \) -not -wholename /readflag -delete

USER user
RUN ! find / -writable -or -user "$(id -un)" -or -group $(id -Gn | sed -e 's/ / -or -group /g') 2> /dev/null | \
      grep -Ev -m 1 '^(/dev/|/run/|/proc/|/sys/|/tmp|/var/tmp|/var/lock)'
USER root

ENV PYTHONDONTWRITEBYTECODE=1
ENTRYPOINT ["/qdiscworld.sh"]
