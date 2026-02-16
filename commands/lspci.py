from __future__ import annotations
import time
import datetime
from cowrie.shell.command import HoneyPotCommand

UPTIME_OFFSET = 87 * 24 * 3600

commands = {}

# --- lspci ---

LSPCI_OUTPUT = """\
00:00.0 Host bridge: Intel Corporation 8th Gen Core Processor Host Bridge/DRAM Registers (rev 08)
00:02.0 VGA compatible controller: Intel Corporation UHD Graphics 620 (rev 00)
00:14.0 USB controller: Intel Corporation 100 Series/C230 Series Chipset Family USB 3.0 xHCI Controller/Hub (rev 31)
00:16.0 Communication controller: Intel Corporation 100 Series/C230 Series Chipset Family MEI Controller #1 (rev 31)
00:17.0 SATA controller: Intel Corporation Q170/Q150/B150/H170/H110/Z170/CM236 Chipset SATA Controller [AHCI Mode] (rev 31)
00:1c.0 PCI bridge: Intel Corporation 100 Series/C230 Series Chipset Family PCI Express Root Port #1 (rev f1)
00:1f.0 ISA bridge: Intel Corporation 100 Series/C230 Series Chipset Family LPC Controller/eSPI Controller (rev 31)
00:1f.2 Memory controller: Intel Corporation 100 Series/C230 Series Chipset Family Power Management Controller (rev 31)
00:1f.4 SMBus: Intel Corporation 100 Series/C230 Series Chipset Family SMBus (rev 31)
00:1f.6 Ethernet controller: Intel Corporation Ethernet Connection (2) I219-V (rev 31)
01:00.0 3D controller: NVIDIA Corporation Tesla T4 (rev a1)
"""


class Command_lspci(HoneyPotCommand):
    def call(self):
        self.write(LSPCI_OUTPUT)


commands["/usr/bin/lspci"] = Command_lspci
commands["lspci"] = Command_lspci


# --- ps ---

PS_BASIC = (
    "PID   TTY     TIME  COMMAND\n"
    "14392 pts/0   0:00  -bash\n"
    "14405 pts/0   0:00  ps\n"
)

PS_EF = (
    "UID          PID    PPID  C STIME TTY          TIME CMD\n"
    "root           1       0  0 {b} ?        00:03:12 /sbin/init\n"
    "root           2       0  0 {b} ?        00:00:00 [kthreadd]\n"
    "root          11       2  0 {b} ?        00:00:42 [rcu_sched]\n"
    "root          78       2  0 {b} ?        00:01:05 [kworker/u256:1-events_unbound]\n"
    "root         142       1  0 {b} ?        00:00:31 /lib/systemd/systemd-journald\n"
    "root         171       1  0 {b} ?        00:00:08 /lib/systemd/systemd-udevd\n"
    "systemd+     304       1  0 {b} ?        00:02:44 /lib/systemd/systemd-resolved\n"
    "systemd+     305       1  0 {b} ?        00:01:12 /lib/systemd/systemd-timesyncd\n"
    "root         389       1  0 {b} ?        00:00:15 /usr/sbin/cron -f\n"
    "message+     390       1  0 {b} ?        00:01:07 /usr/bin/dbus-daemon --system\n"
    "root         395       1  0 {b} ?        00:02:58 /usr/sbin/rsyslogd -n -iNONE\n"
    "root         401       1  0 {b} ?        00:08:16 /usr/sbin/sshd -D\n"
    "root         427       1  0 {b} ?        00:00:04 /sbin/agetty --noclear tty1 linux\n"
    "root         502       1  0 {b} ?        00:15:33 /usr/bin/containerd\n"
    "root         588       1  0 {b} ?        00:22:17 /usr/bin/dockerd -H fd://\n"
    "root         814       1  0 {b} ?        00:00:00 /usr/sbin/nvidia-persistenced --user root\n"
    "root         891     502  0 {b} ?        00:05:44 containerd-shim -namespace moby -id a8e3f\n"
    "nobody      1042     891  0 {b} ?        00:00:02 /usr/bin/python3 /opt/ml/serve\n"
    "root        1187       1  0 {b} ?        00:00:00 /usr/lib/postfix/sbin/master -w\n"
    "postfix     1201    1187  0 {b} ?        00:00:03 qmgr -l -t unix -u\n"
    "root       14380     401  0 {t} ?        00:00:00 sshd: root [priv]\n"
    "root       14389   14380  0 {t} ?        00:00:00 sshd: root@pts/0\n"
    "root       14392   14389  0 {t} pts/0    00:00:00 -bash\n"
    "root       14405   14392  0 {t} pts/0    00:00:00 ps -ef\n"
)

PS_AUX = (
    "USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n"
    "root           1  0.0  0.0 167484 11584 ?        Ss   {b}   3:12 /sbin/init\n"
    "root           2  0.0  0.0      0     0 ?        S    {b}   0:00 [kthreadd]\n"
    "root          11  0.0  0.0      0     0 ?        S    {b}   0:42 [rcu_sched]\n"
    "root          78  0.0  0.0      0     0 ?        I    {b}   1:05 [kworker/u256:1-events_unbound]\n"
    "root         142  0.0  0.0  47552  6280 ?        Ss   {b}   0:31 /lib/systemd/systemd-journald\n"
    "root         171  0.0  0.0  25024  3420 ?        Ss   {b}   0:08 /lib/systemd/systemd-udevd\n"
    "systemd+     304  0.0  0.0  25200 12440 ?        Ss   {b}   2:44 /lib/systemd/systemd-resolved\n"
    "root         389  0.0  0.0   8536  3024 ?        Ss   {b}   0:15 /usr/sbin/cron -f\n"
    "root         395  0.0  0.0 224328  4820 ?        Ssl  {b}   2:58 /usr/sbin/rsyslogd -n -iNONE\n"
    "root         401  0.0  0.0  15432  5636 ?        Ss   {b}   8:16 /usr/sbin/sshd -D\n"
    "root         502  0.1  0.0 1795040 32564 ?       Ssl  {b}  15:33 /usr/bin/containerd\n"
    "root         588  0.1  0.0 2217220 73648 ?       Ssl  {b}  22:17 /usr/bin/dockerd -H fd://\n"
    "root         814  0.0  0.0  12412  3456 ?        Ss   {b}   0:00 /usr/sbin/nvidia-persistenced --user root\n"
    "nobody      1042  0.0  0.2 384520 61204 ?        Sl   {b}   0:02 /usr/bin/python3 /opt/ml/serve\n"
    "root        1187  0.0  0.0  78500  6476 ?        Ss   {b}   0:00 /usr/lib/postfix/sbin/master -w\n"
    "root       14380  0.0  0.0  17200  7128 ?        Ss   {t}   0:00 sshd: root [priv]\n"
    "root       14389  0.0  0.0  17200  4032 ?        S    {t}   0:00 sshd: root@pts/0\n"
    "root       14392  0.0  0.0   8964  4792 pts/0    Ss   {t}   0:00 -bash\n"
    "root       14405  0.0  0.0  11072  3268 pts/0    R+   {t}   0:00 ps aux\n"
)


class Command_ps(HoneyPotCommand):
    def call(self):
        now = datetime.datetime.now()
        boot = now - datetime.timedelta(seconds=UPTIME_OFFSET)
        b = boot.strftime("%b%d")
        t = now.strftime("%H:%M")
        args = ""
        if self.args:
            args = " ".join(self.args)
        if "aux" in args:
            self.write(PS_AUX.replace("{t}", t).replace("{b}", b))
        elif "-e" in args or "-A" in args:
            self.write(PS_EF.replace("{t}", t).replace("{b}", b))
        else:
            self.write(PS_BASIC)


commands["/bin/ps"] = Command_ps
commands["ps"] = Command_ps


# --- chattr ---

CHATTR_USAGE = "Usage: chattr [-pRVf] [-+=aAcCdDeFijPsStTu] [-v version] files...\n"


class Command_chattr(HoneyPotCommand):
    def call(self):
        if not self.args:
            self.write(CHATTR_USAGE)


commands["/usr/bin/chattr"] = Command_chattr
commands["chattr"] = Command_chattr
