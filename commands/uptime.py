from __future__ import annotations

import time

from cowrie.core import utils
from cowrie.shell.command import HoneyPotCommand

commands = {}

# Fake offset: ~87 days in seconds (makes it look like server has been up since mid-November)
UPTIME_OFFSET = 87 * 24 * 3600


class Command_uptime(HoneyPotCommand):
    def call(self) -> None:
        real_uptime = self.protocol.uptime()
        faked = real_uptime + UPTIME_OFFSET
        self.write(
            "{}  up {},  1 user,  load average: 0.08, 0.03, 0.01\n".format(
                time.strftime("%H:%M:%S"), utils.uptime(faked)
            )
        )


commands["/usr/bin/uptime"] = Command_uptime
commands["uptime"] = Command_uptime
