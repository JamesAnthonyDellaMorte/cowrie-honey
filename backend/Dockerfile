FROM --platform=linux/arm64 debian:bookworm-slim

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
    echo 'PasswordAuthentication yes' >> /etc/ssh/sshd_config

# Generate host keys
RUN ssh-keygen -A

# Set hostname
RUN echo 'mediaserver' > /etc/hostname

# Make it look lived-in
RUN mkdir -p /root/.ssh && \
    touch /root/.bash_history && \
    echo 'export PS1="\u@\h:\w\$ "' >> /root/.bashrc

COPY capture.sh /usr/local/bin/capture.sh
RUN chmod +x /usr/local/bin/capture.sh

RUN mkdir -p /var/spool/.captured

EXPOSE 22
CMD bash -c "/usr/local/bin/capture.sh & /usr/sbin/sshd -D -e"
