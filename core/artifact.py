# Copyright (c) 2016 Michel Oosterhof <michel@oosterhof.net>

"""
This module contains code to handling saving of honeypot artifacts
These will typically be files uploaded to the honeypot and files
downloaded inside the honeypot, or input being piped in.

Code behaves like a normal Python file handle.

Example:

    with Artifact(name) as f:
        f.write("abc")

or:

    g = Artifact("testme2")
    g.write("def")
    g.close()

"""

from __future__ import annotations

import hashlib
import os
import re
import tempfile
from typing import Any, TYPE_CHECKING

from twisted.python import log

from cowrie.core.config import CowrieConfig

if TYPE_CHECKING:
    from types import TracebackType


class Artifact:
    artifactDir: str = CowrieConfig.get("honeypot", "download_path", fallback=".")

    def __init__(self, label: str) -> None:
        self.label: str = label

        self.fp = tempfile.NamedTemporaryFile(  # pylint: disable=R1732
            dir=self.artifactDir, delete=False
        )
        self.tempFilename = self.fp.name
        self.closed: bool = False

        self.shasum: str = ""
        self.shasumFilename: str = ""

    def __enter__(self) -> Any:
        return self.fp

    def __exit__(
        self,
        etype: type[BaseException] | None,
        einst: BaseException | None,
        etrace: TracebackType | None,
    ) -> bool:
        self.close()
        return True

    def write(self, data: bytes) -> None:
        self.fp.write(data)

    def fileno(self) -> Any:
        return self.fp.fileno()

    def close(self, keepEmpty: bool = False) -> tuple[str, str] | None:
        size: int = self.fp.tell()
        if size == 0 and not keepEmpty:
            try:
                os.remove(self.fp.name)
            except FileNotFoundError:
                pass
            return None

        self.fp.seek(0)
        data = self.fp.read()
        self.fp.close()
        self.closed = True

        self.shasum = hashlib.sha256(data).hexdigest()
        self.shasumFilename = os.path.join(self.artifactDir, self.shasum)

        # Build a friendly filename: "asd456dsa - virus.sh"
        basename = os.path.basename(self.label) if self.label else ""
        basename = re.sub(r'[^a-zA-Z0-9._\-]', '_', basename)
        if basename and basename != self.shasum:
            friendlyName = f"{self.shasum[:9]} - {basename}"
        else:
            friendlyName = self.shasum
        friendlyPath = os.path.join(self.artifactDir, friendlyName)

        # Check for duplicates by SHA256 - look for any file starting with this hash prefix
        duplicate = False
        if os.path.exists(self.shasumFilename):
            duplicate = True
        else:
            for existing in os.listdir(self.artifactDir):
                if existing.startswith(self.shasum[:9] + " - "):
                    duplicate = True
                    break

        if duplicate:
            log.msg("Not storing duplicate content " + self.shasum)
            os.remove(self.fp.name)
        else:
            os.rename(self.fp.name, friendlyPath)
            umask = os.umask(0)
            os.umask(umask)
            os.chmod(friendlyPath, 0o666 & ~umask)

        self.shasumFilename = friendlyPath
        return self.shasum, self.shasumFilename
