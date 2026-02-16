from __future__ import annotations
import time
from cowrie.shell.command import HoneyPotCommand

commands = {}

PROCS_BASIC = (
    "PID   TTY     TIME  COMMAND\n"
    "14392 pts/0   0:00  -bash\n"
    "14405 pts/0   0:00  ps\n"
)

PROCS_EF = (
    "UID          PID    PPID  C STIME TTY          TIME CMD\n"
    "root           1       0  0 Nov17 ?        00:03:12 /sbin/init\n"
    "root           2       0  0 Nov17 ?        00:00:00 [kthreadd]\n"
    "root          11       2  0 Nov17 ?        00:00:42 [rcu_sched]\n"
    "root          78       2  0 Nov17 ?        00:01:05 [kworker/u256:1-events_unbound]\n"
    "root         142       1  0 Nov17 ?        00:00:31 /lib/systemd/systemd-journald\n"
    "root         171       1  0 Nov17 ?        00:00:08 /lib/systemd/systemd-udevd\n"
    "systemd+     304       1  0 Nov17 ?        00:02:44 /lib/systemd/systemd-resolved\n"
    "systemd+     305       1  0 Nov17 ?        00:01:12 /lib/systemd/systemd-timesyncd\n"
    "root         389       1  0 Nov17 ?        00:00:15 /usr/sbin/cron -f\n"
    "message+     390       1  0 Nov17 ?        00:01:07 /usr/bin/dbus-daemon --system\n"
    "root         395       1  0 Nov17 ?        00:02:58 /usr/sbin/rsyslogd -n -iNONE\n"
    "root         401       1  0 Nov17 ?        00:08:16 /usr/sbin/sshd -D\n"
    "root         427       1  0 Nov17 ?        00:00:04 /sbin/agetty --noclear tty1 linux\n"
    "root         502       1  0 Nov17 ?        00:15:33 /usr/bin/containerd\n"
    "root         588       1  0 Nov17 ?        00:22:17 /usr/bin/dockerd -H fd://\n"
    "root         814       1  0 Nov17 ?        00:00:00 /usr/sbin/nvidia-persistenced --user root\n"
    "root         891     502  0 Nov17 ?        00:05:44 containerd-shim -namespace moby -id a8e3f\n"
    "nobody      1042     891  0 Nov17 ?        00:00:02 /usr/bin/python3 /opt/ml/serve\n"
    "root        1187       1  0 Nov17 ?        00:00:00 /usr/lib/postfix/sbin/master -w\n"
    "postfix     1201    1187  0 Nov17 ?        00:00:03 qmgr -l -t unix -u\n"
    "root       14380     401  0 {t} ?        00:00:00 sshd: root [priv]\n"
    "root       14389   14380  0 {t} ?        00:00:00 sshd: root@pts/0\n"
    "root       14392   14389  0 {t} pts/0    00:00:00 -bash\n"
    "root       14405   14392  0 {t} pts/0    00:00:00 ps -ef\n"
)

PROCS_AUX = (
    "USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n"
    "root           1  0.0  0.0 167484 11584 ?        Ss   Nov17   3:12 /sbin/init\n"
    "root           2  0.0  0.0      0     0 ?        S    Nov17   0:00 [kthreadd]\n"
    "root          11  0.0  0.0      0     0 ?        S    Nov17   0:42 [rcu_sched]\n"
    "root          78  0.0  0.0      0     0 ?        I    Nov17   1:05 [kworker/u256:1-events_unbound]\n"
    "root         142  0.0  0.0  47552  6280 ?        Ss   Nov17   0:31 /lib/systemd/systemd-journald\n"
    "root         171  0.0  0.0  25024  3420 ?        Ss   Nov17   0:08 /lib/systemd/systemd-udevd\n"
    "systemd+     304  0.0  0.0  25200 12440 ?        Ss   Nov17   2:44 /lib/systemd/systemd-resolved\n"
    "root         389  0.0  0.0   8536  3024 ?        Ss   Nov17   0:15 /usr/sbin/cron -f\n"
    "root         395  0.0  0.0 224328  4820 ?        Ssl  Nov17   2:58 /usr/sbin/rsyslogd -n -iNONE\n"
    "root         401  0.0  0.0  15432  5636 ?        Ss   Nov17   8:16 /usr/sbin/sshd -D\n"
    "root         502  0.1  0.0 1795040 32564 ?       Ssl  Nov17  15:33 /usr/bin/containerd\n"
    "root         588  0.1  0.0 2217220 73648 ?       Ssl  Nov17  22:17 /usr/bin/dockerd -H fd://\n"
    "root         814  0.0  0.0  12412  3456 ?        Ss   Nov17   0:00 /usr/sbin/nvidia-persistenced --user root\n"
    "nobody      1042  0.0  0.2 384520 61204 ?        Sl   Nov17   0:02 /usr/bin/python3 /opt/ml/serve\n"
    "root        1187  0.0  0.0  78500  6476 ?        Ss   Nov17   0:00 /usr/lib/postfix/sbin/master -w\n"
    "root       14380  0.0  0.0  17200  7128 ?        Ss   {t}   0:00 sshd: root [priv]\n"
    "root       14389  0.0  0.0  17200  4032 ?        S    {t}   0:00 sshd: root@pts/0\n"
    "root       14392  0.0  0.0   8964  4792 pts/0    Ss   {t}   0:00 -bash\n"
    "root       14405  0.0  0.0  11072  3268 pts/0    R+   {t}   0:00 ps aux\n"
)


class Command_ps(HoneyPotCommand):
    def call(self):
        t = time.strftime("%H:%M")
        args = ""
        if self.args:
            args = " ".join(self.args)
        if "aux" in args:
            self.write(PROCS_AUX.replace("{t}", t))
        elif "-e" in args or "-A" in args or "-ef" in args:
            self.write(PROCS_EF.replace("{t}", t))
        else:
            self.write(PROCS_BASIC)


commands["/bin/ps"] = Command_ps
commands["ps"] = Command_ps
