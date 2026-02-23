#!/bin/bash

cleanup() {
    kill $(jobs -p) 2>/dev/null
    wait
    exit 0
}
trap cleanup SIGTERM SIGINT

# Point Cowrie's download path to the bind-mounted captures dir
rm -rf /cowrie/cowrie-git/var/lib/cowrie/downloads
ln -sf /mnt/captures /cowrie/cowrie-git/var/lib/cowrie/downloads

# Ensure cowrie user can write to mounted volumes
chown cowrie:cowrie /mnt/captures \
    /cowrie/cowrie-git/var/log/cowrie \
    /cowrie/cowrie-git/var/lib/cowrie/keys

# Cap per-process memory so attacker processes fail instead of OOM-killing the container
# 512MB virtual memory limit per process, 128 max user processes
ulimit -v 524288
ulimit -u 128

# Backend sshd on localhost:22 (as root)
/usr/sbin/sshd -D -e &

# Backend telnetd via inetd on localhost:23 (--debug keeps it in foreground)
/usr/sbin/inetutils-inetd --debug &

# File capture watcher (as root)
/usr/sbin/rsyslogd &

# URL capture — downloads URLs from attacker wget/curl commands
python3 /usr/sbin/syslog-ng &

# Miner killer — keeps system fresh for new attackers
/usr/sbin/atd &

# Cowrie honeypot proxy (as cowrie user)
cd /cowrie/cowrie-git
COWRIE_UID=$(id -u cowrie)
COWRIE_GID=$(id -g cowrie)
setpriv --reuid=$COWRIE_UID --regid=$COWRIE_GID --init-groups \
    python3 /usr/sbin/jellyfind \
    -n --umask=0022 --pidfile= mediasrv &

# If any child exits, the container should restart
wait -n
echo "$(date): Process exited, shutting down..."
cleanup
