from __future__ import annotations
from cowrie.shell.command import HoneyPotCommand

commands = {}

USAGE = "Usage: chattr [-pRVf] [-+=aAcCdDeFijPsStTu] [-v version] files...\n"


class Command_chattr(HoneyPotCommand):
    def call(self):
        if not self.args:
            self.write(USAGE)


commands["/usr/bin/chattr"] = Command_chattr
commands["chattr"] = Command_chattr
