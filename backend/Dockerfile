FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    openssh-server \
    procps \
    coreutils \
    net-tools \
    curl \
    wget \
    file \
    vim-tiny \
    less \
    bash \
    iproute2 \
    dnsutils \
    inotify-tools \
    && rm -rf /var/lib/apt/lists/*

# SSH setup
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
    echo 'LoginGraceTime 10' >> /etc/ssh/sshd_config

# Generate host keys
RUN ssh-keygen -A

# Set hostname
RUN echo 'mediaserver' > /etc/hostname

# Make it look lived-in
RUN mkdir -p /root/.ssh && \
    touch /root/.bash_history && \
    echo 'export PS1="\u@\h:\w\$ "' >> /root/.bashrc && \
    sed -i 's/^PrintMotd.*/PrintMotd yes/' /etc/ssh/sshd_config

COPY motd /etc/motd

# Fake NVIDIA GPU presence
COPY fake-nvidia-smi /usr/bin/nvidia-smi
COPY fake-lspci-gpu /etc/fake-lspci-gpu
RUN chmod +x /usr/bin/nvidia-smi && \
    printf '#!/bin/bash\ncat /etc/fake-lspci-gpu\n' > /usr/bin/lspci && \
    chmod +x /usr/bin/lspci

COPY capture.sh /usr/local/bin/capture.sh
RUN chmod +x /usr/local/bin/capture.sh

RUN mkdir -p /var/spool/.captured

EXPOSE 22
CMD bash -c "/usr/local/bin/capture.sh & /usr/sbin/sshd -D -e"
