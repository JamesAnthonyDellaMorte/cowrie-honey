#!/bin/bash
cd /cowrie/cowrie-git
exec python3 /usr/sbin/jellyfind -n --umask=0022 --pidfile= cowrie
