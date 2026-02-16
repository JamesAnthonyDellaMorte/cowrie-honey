from __future__ import annotations

import random
import time

from twisted.internet import reactor

from cowrie.core import utils
from cowrie.shell.command import HoneyPotCommand

commands = {}

UPTIME_OFFSET = 87 * 24 * 3600 + 7 * 3600 + 14 * 60  # 87 days, 7:14

TOP_HEADER = """\
top - {time} up {uptime},  1 user,  load average: {l1}, {l2}, {l3}
Tasks: 142 total,   1 running, 140 sleeping,   0 stopped,   1 zombie
%Cpu(s):  {us} us,  {sy} sy,  0.0 ni, {id} id,  0.1 wa,  0.0 hi,  0.1 si,  0.0 st
MiB Mem : 257694.2 total, {memfree} free,   {memused} used,  55510.6 buff/cache
MiB Swap:   8192.0 total,   8192.0 free,      0.0 used. {memavail} avail Mem
"""

TOP_PROCS = """\
    PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND
      1 root      20   0  167484  11584   8320 S   0.0   0.0   3:12.41 systemd
      2 root      20   0       0      0      0 S   0.0   0.0   0:00.38 kthreadd
     11 root      20   0       0      0      0 S   0.0   0.0   0:42.17 rcu_sched
     78 root      20   0       0      0      0 I   0.0   0.0   1:05.83 kworker/u256:1-
    142 root      20   0   47552   6280   5644 S   0.0   0.0   0:31.02 systemd-journal
    171 root      20   0   25024   3420   2984 S   0.0   0.0   0:08.54 systemd-udevd
    304 systemd+  20   0   25200  12440   8316 S   0.0   0.0   2:44.19 systemd-resolve
    305 systemd+  20   0   90224   6048   5268 S   0.0   0.0   1:12.07 systemd-timesyn
    389 root      20   0    8536   3024   2768 S   0.0   0.0   0:15.93 cron
    390 message+  20   0    8608   4536   3920 S   0.0   0.0   1:07.22 dbus-daemon
    395 root      20   0  224328   4820   4148 S   0.0   0.0   2:58.61 rsyslogd
    401 root      20   0   15432   5636   4948 S   0.0   0.0   8:16.04 sshd
    427 root      20   0    5960   1840   1716 S   0.0   0.0   0:04.11 agetty
    502 root      20   0 1795040  32564  24816 S   0.1   0.0  15:33.28 containerd
    588 root      20   0 2217220  73648  42312 S   0.1   0.0  22:17.55 dockerd
    814 root      20   0   12412   3456   3120 S   0.0   0.0   0:00.74 nvidia-persiste
    891 root      20   0  711208  10284   7460 S   0.0   0.0   5:44.32 containerd-shim
   1042 nobody    20   0  384520  61204  18736 S   0.0   0.0   0:02.18 python3
   1187 root      20   0   78500   6476   5740 S   0.0   0.0   0:00.49 master
   1201 postfix   20   0   78784   5816   5116 S   0.0   0.0   0:03.87 qmgr
  14380 root      20   0   17200   7128   6080 S   0.0   0.0   0:00.03 sshd
  14389 root      20   0   17200   4032   3024 S   0.0   0.0   0:00.01 sshd
  14392 root      20   0    8964   4792   3648 S   0.0   0.0   0:00.05 bash
  14405 root      20   0   11072   3268   2804 R   0.0   0.0   0:00.00 top
"""


class Command_top(HoneyPotCommand):
    scheduled = None
    batch = False
    iterations = 0
    max_iterations = 0
    running = False

    def start(self):
        args = self.args[:]
        self.batch = False
        self.max_iterations = 0

        i = 0
        while i < len(args):
            a = args[i]
            if a == "-b":
                self.batch = True
            elif a == "-n" and i + 1 < len(args):
                i += 1
                try:
                    self.max_iterations = int(args[i])
                except ValueError:
                    pass
            elif a.startswith("-bn"):
                self.batch = True
                try:
                    self.max_iterations = int(a[3:])
                except ValueError:
                    pass
            elif a.startswith("-n"):
                try:
                    self.max_iterations = int(a[2:])
                except ValueError:
                    pass
            i += 1

        self.iterations = 0
        self.running = True
        self._render()

    def _clear_screen(self):
        self.protocol.terminal.cursorHome()
        self.protocol.terminal.eraseDisplay()

    def _render(self):
        if not self.running:
            return

        if not self.batch:
            self._clear_screen()

        self.write(self._build_output())
        self.iterations += 1

        if self.max_iterations > 0 and self.iterations >= self.max_iterations:
            self.running = False
            self.exit()
            return

        self.scheduled = reactor.callLater(3, self._render)

    def _build_output(self):
        real_uptime = self.protocol.uptime()
        faked = real_uptime + UPTIME_OFFSET
        uptime_str = utils.uptime(faked)

        us = round(0.8 + random.random() * 0.8, 1)
        sy = round(0.3 + random.random() * 0.3, 1)
        idle = round(100.0 - us - sy - 0.2, 1)
        l1 = f"{0.05 + random.random() * 0.15:.2f}"
        l2 = f"{0.03 + random.random() * 0.10:.2f}"
        l3 = f"{0.01 + random.random() * 0.05:.2f}"

        memfree = f"{198200 + random.randint(-500, 500):.1f}"
        memused = f"{3842 + random.randint(-100, 100):.1f}"
        memavail = f"{251000 + random.randint(-500, 500):.1f}"

        header = TOP_HEADER.format(
            time=time.strftime("%H:%M:%S"),
            uptime=uptime_str,
            us=us, sy=sy, id=idle,
            l1=l1, l2=l2, l3=l3,
            memfree=memfree, memused=memused, memavail=memavail,
        )

        return header + TOP_PROCS

    def handle_CTRL_C(self):
        self.running = False
        if self.scheduled and self.scheduled.active():
            self.scheduled.cancel()
        self.write("^C\n")
        self.exit()

    def lineReceived(self, line):
        if line.strip() == "q":
            self.running = False
            if self.scheduled and self.scheduled.active():
                self.scheduled.cancel()
            self.exit()


commands["/usr/bin/top"] = Command_top
commands["top"] = Command_top
