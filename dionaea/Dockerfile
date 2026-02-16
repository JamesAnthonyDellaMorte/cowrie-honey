FROM dinotools/dionaea:latest

RUN apt-get update && apt-get install -y --no-install-recommends \
    inotify-tools file \
    && rm -rf /var/lib/apt/lists/*

COPY dionaea-to-dl.sh /usr/local/bin/dionaea-to-dl.sh
RUN chmod +x /usr/local/bin/dionaea-to-dl.sh

ENTRYPOINT []
