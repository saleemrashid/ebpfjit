import base64
import hashlib
import subprocess
from typing import Self

from netaddr import IPNetwork

import ip

TIMEOUT = 5


def tap_name(prefix: IPNetwork) -> str:
    suffix = (
        base64.b32encode(hashlib.sha256(str(prefix).encode()).digest()).decode().lower()
    )
    return f"tap0{suffix}"[:15]


class Runner(object):
    def __init__(self, executable: str):
        self.prefix, self.addr = ip.random_point_to_point()
        self.tap_name = tap_name(self.prefix)
        self.process = subprocess.Popen(
            [executable, self.tap_name], stdout=subprocess.DEVNULL
        )

        ip.wait_for_interface(self.tap_name, TIMEOUT)
        ip.bring_up(self.tap_name, self.prefix)
        assert ip.route_interface(self.addr) == self.tap_name

    @property
    def url(self) -> str:
        return f"http://{self.addr.ipv4()}"

    def __enter__(self) -> Self:
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.process.terminate()
        try:
            self.process.wait(TIMEOUT)
        except TimeoutError:
            self.process.kill()
            raise
