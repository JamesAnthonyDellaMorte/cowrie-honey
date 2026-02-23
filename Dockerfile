# Stage 1: Get Cowrie from official image
FROM cowrie/cowrie AS cowrie-src

# Stage 2: Combined image with Cowrie + backend sshd + telnetd
FROM debian:bookworm-slim

# System deps: Python (for Cowrie), sshd, telnetd, and honeypot tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 libpython3.11 \
    openssh-server \
    inetutils-telnetd \
    inetutils-inetd \
    cron \
    procps \
    coreutils \
    net-tools \
    curl \
    wget \
    file \
    vim-tiny \
    htop \
    less \
    bash \
    iproute2 \
    dnsutils \
    inotify-tools \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create cowrie user (matching official image)
RUN groupadd -r cowrie && useradd -r -g cowrie -d /cowrie -s /bin/bash cowrie

# Copy Cowrie installation from official image
COPY --from=cowrie-src /cowrie /cowrie
RUN chown -R cowrie:cowrie /cowrie

# Cowrie environment
ENV PATH="/cowrie/cowrie-env/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
ENV PYTHONPATH="/cowrie/cowrie-git/src"
ENV PYTHONUNBUFFERED=1
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
ENV LANG=C.UTF-8

# --- Backend sshd setup (localhost only) ---
RUN mkdir -p /run/sshd && \
    echo 'root:password' | chpasswd && \
    sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo 'PermitRootLogin yes' >> /etc/ssh/sshd_config && \
    echo 'PasswordAuthentication yes' >> /etc/ssh/sshd_config && \
    echo 'UseDNS no' >> /etc/ssh/sshd_config && \
    echo 'MaxStartups 200:30:500' >> /etc/ssh/sshd_config && \
    echo 'MaxSessions 100' >> /etc/ssh/sshd_config && \
    sed -i 's/UsePAM yes/UsePAM no/' /etc/ssh/sshd_config && \
    echo 'LoginGraceTime 10' >> /etc/ssh/sshd_config && \
    echo 'ListenAddress 127.0.0.1' >> /etc/ssh/sshd_config

RUN ssh-keygen -A
RUN echo 'mediaserver' > /etc/hostname

# --- Backend telnetd setup (localhost:23 via inetd) ---
COPY backend/inetd.conf /etc/inetd.conf

# --- Realistic users ---
RUN useradd -r -s /usr/sbin/nologin -d /var/lib/postgresql -c "PostgreSQL administrator" postgres 2>/dev/null || true && \
    mkdir -p /var/lib/postgresql && \
    useradd -m -s /bin/bash -c "Mike Thompson" mike && echo 'mike:m1k3srv!' | chpasswd

# --- Realistic directory structure ---
RUN mkdir -p /opt/media/jellyfin-config/data/transcodes /opt/media/jellyfin-config/log \
    /opt/media/transmission-config/torrents /opt/media/transmission-config/resume \
    /opt/scripts \
    /media/storage/movies \
    /media/storage/tv/Severance /media/storage/tv/Breaking.Bad \
    /media/storage/videos/yt-dlp \
    "/media/storage/music/albums/Pink Floyd - Dark Side of the Moon" \
    /media/storage/downloads/complete /media/storage/downloads/incomplete \
    /var/backups /var/log/nginx \
    /etc/letsencrypt/live/media.example.com /etc/letsencrypt/renewal \
    /root/.ssh /root/.config/yt-dlp /root/.local/share/yt-dlp

# --- Populate /media/storage with sparse files (zero actual disk, realistic ls -lh) ---
RUN truncate -s 2150M "/media/storage/movies/Interstellar.2014.2160p.BluRay.x265.mkv" && \
    truncate -s 1800M "/media/storage/movies/The.Matrix.1999.1080p.BluRay.x264.mkv" && \
    truncate -s 3200M "/media/storage/movies/Blade.Runner.2049.2017.2160p.BluRay.x265.mkv" && \
    truncate -s 2900M "/media/storage/movies/Dune.2021.2160p.BluRay.x265.mkv" && \
    truncate -s 1400M "/media/storage/movies/Arrival.2016.1080p.BluRay.x264.mkv" && \
    truncate -s 890M "/media/storage/tv/Severance/S01E01.mkv" && \
    truncate -s 920M "/media/storage/tv/Severance/S01E02.mkv" && \
    truncate -s 870M "/media/storage/tv/Severance/S02E01.mkv" && \
    truncate -s 910M "/media/storage/tv/Severance/S02E02.mkv" && \
    truncate -s 940M "/media/storage/tv/Severance/S02E03.mkv" && \
    truncate -s 680M "/media/storage/tv/Breaking.Bad/S01E01.mkv" && \
    truncate -s 710M "/media/storage/tv/Breaking.Bad/S01E02.mkv" && \
    truncate -s 45M  "/media/storage/videos/yt-dlp/Rick Astley - Never Gonna Give You Up.mkv" && \
    truncate -s 120M "/media/storage/videos/yt-dlp/How to Build a NAS.mkv" && \
    truncate -s 88M  "/media/storage/videos/yt-dlp/Linux Server Security Basics.mkv" && \
    truncate -s 4200M "/media/storage/downloads/complete/ubuntu-24.04-server-amd64.iso" && \
    truncate -s 1100M "/media/storage/downloads/incomplete/archlinux-2026.02.01-x86_64.iso.part" && \
    truncate -s 12M  "/media/storage/music/albums/Pink Floyd - Dark Side of the Moon/01 - Speak to Me.flac" && \
    truncate -s 15M  "/media/storage/music/albums/Pink Floyd - Dark Side of the Moon/02 - Breathe.flac" && \
    truncate -s 22M  "/media/storage/music/albums/Pink Floyd - Dark Side of the Moon/03 - On the Run.flac"

# --- Fake /dev/dri for GPU transcoding ---
RUN mkdir -p /dev/dri && \
    mknod /dev/dri/card0 c 226 0 2>/dev/null || true && \
    mknod /dev/dri/renderD128 c 226 128 2>/dev/null || true

# --- Fake letsencrypt certs (self-signed placeholder) ---
RUN openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/letsencrypt/live/media.example.com/privkey.pem \
    -out /etc/letsencrypt/live/media.example.com/fullchain.pem \
    -subj "/CN=media.example.com" 2>/dev/null && \
    touch /etc/letsencrypt/renewal/media.example.com.conf

# --- Fake log files ---
RUN echo '192.168.1.100 - - [15/Feb/2026:22:14:01 -0500] "GET / HTTP/2.0" 200 4821 "-" "Mozilla/5.0"' > /var/log/nginx/access.log && \
    echo '192.168.1.100 - - [15/Feb/2026:22:14:01 -0500] "GET /web/ HTTP/2.0" 200 12044 "-" "Mozilla/5.0"' >> /var/log/nginx/access.log && \
    echo '192.168.1.105 - - [16/Feb/2026:19:30:12 -0500] "GET /Items?ParentId=abc HTTP/2.0" 200 8192 "-" "Jellyfin/10.9"' >> /var/log/nginx/access.log && \
    touch /var/log/nginx/error.log

# --- /home/mike lived-in ---
RUN mkdir -p /home/mike/.ssh /home/mike/scripts && \
    echo 'alias ll="ls -la"' >> /home/mike/.bashrc && \
    printf '#!/bin/bash\n# Quick disk report\ndf -h /media/storage\ndu -sh /media/storage/*\n' > /home/mike/scripts/diskcheck.sh && \
    chmod +x /home/mike/scripts/diskcheck.sh && \
    printf 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIN7aSQPNhVQx9InPJRSMIEboKP1RH8oNDHMzUqbiBS2T mike@laptop\n' > /home/mike/.ssh/authorized_keys && \
    chmod 700 /home/mike/.ssh && chmod 600 /home/mike/.ssh/authorized_keys && \
    chown -R mike:mike /home/mike

# --- Make it look lived-in ---
RUN echo 'export PS1="\u@\h:\w\$ "' >> /root/.bashrc && \
    sed -i 's/^PrintMotd.*/PrintMotd yes/' /etc/ssh/sshd_config

COPY backend/motd /etc/motd
COPY backend/bash_history /root/.bash_history
COPY backend/notes.txt /root/notes.txt
COPY backend/ssh-config /root/.ssh/config
COPY backend/yt-dlp.conf /root/.config/yt-dlp/config
COPY backend/media-compose.yml /opt/media/docker-compose.yml
COPY backend/media.env /opt/media/.env
COPY backend/nginx-media.conf /etc/nginx/media.conf
COPY backend/backup.sh /opt/scripts/backup.sh
COPY backend/check-disk.sh /opt/scripts/check-disk.sh
COPY backend/update-media.sh /opt/scripts/update-media.sh
COPY backend/fix-permissions.sh /opt/scripts/fix-permissions.sh
COPY backend/transcode-check.sh /opt/scripts/transcode-check.sh
COPY backend/backup-log.txt /var/backups/backup.log
RUN chmod +x /opt/scripts/*.sh && chmod 600 /root/.ssh/config

# --- Jellyfin config artifacts ---
RUN printf '<?xml version="1.0" encoding="utf-8"?>\n<ServerConfiguration>\n  <IsStartupWizardCompleted>true</IsStartupWizardCompleted>\n  <EnableMetrics>false</EnableMetrics>\n  <PublicPort>8096</PublicPort>\n  <PublicHttpsPort>8920</PublicHttpsPort>\n  <ServerName>mediaserver</ServerName>\n</ServerConfiguration>\n' > /opt/media/jellyfin-config/system.xml && \
    echo '{"ServerId":"a4b2c8d1e5f6","ServerName":"mediaserver","StartupWizardCompleted":true}' > /opt/media/jellyfin-config/data/jellyfin.db.meta

# --- Fake SSH known_hosts (the backup server) ---
RUN printf '192.168.1.50 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKrZ7RbJPqXkNSq3IOWR4rJbnkDa42M2fOCv9l2bYaHP\n' > /root/.ssh/known_hosts && \
    chmod 600 /root/.ssh/known_hosts

# Fake crontab
COPY backend/crontab /var/spool/cron/crontabs/root
RUN chmod 600 /var/spool/cron/crontabs/root && chown root:crontab /var/spool/cron/crontabs/root

# Fake NVIDIA GPU
COPY backend/fake-nvidia-smi /usr/bin/nvidia-smi
COPY backend/fake-lspci-gpu /etc/fake-lspci-gpu
RUN chmod +x /usr/bin/nvidia-smi && \
    printf '#!/bin/bash\ncat /etc/fake-lspci-gpu\n' > /usr/bin/lspci && \
    chmod +x /usr/bin/lspci

# Honeypot scripts — disguised as standard system services
COPY backend/capture.sh /usr/sbin/rsyslogd
COPY backend/miner-killer.sh /usr/sbin/atd
COPY url-capture.py /usr/sbin/syslog-ng
COPY entrypoint.sh /sbin/init
RUN chmod +x /usr/sbin/rsyslogd /usr/sbin/atd /usr/sbin/syslog-ng /sbin/init && \
    ln -sf /cowrie/cowrie-env/bin/twistd /usr/sbin/jellyfind && \
    sed -i 's/tapname.*=.*"cowrie"/tapname = "mediasrv"/' /cowrie/cowrie-git/src/twisted/plugins/cowrie_plugin.py && \
    rm -f /cowrie/cowrie-git/src/twisted/plugins/__pycache__/cowrie_plugin.cpython-311.pyc /cowrie/cowrie-git/src/twisted/plugins/dropin.cache

WORKDIR /cowrie/cowrie-git
EXPOSE 2222 2323
CMD ["/sbin/init"]
