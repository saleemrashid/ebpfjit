import json
import random
import subprocess
import time
from typing import Iterator

from netaddr import IPAddress, IPNetwork, IPSet

LOCAL_ADDRESSES = IPSet(
    (
        IPNetwork("10.0.0.0/8"),
        IPNetwork("172.16.0.0/12"),
        IPNetwork("192.168.0.0/16"),
    )
)


def host_interfaces() -> Iterator[IPNetwork]:
    output = subprocess.check_output(["ip", "-json", "-4", "address", "show"])
    for interface in json.loads(output):
        for addr in interface["addr_info"]:
            subnet = IPNetwork(addr["local"])
            subnet.prefixlen = addr["prefixlen"]
            yield subnet


def available_ips() -> IPSet:
    available = LOCAL_ADDRESSES.copy()
    for subnet in host_interfaces():
        available.remove(subnet)
    return available


def random_subnet(prefixlen: int) -> IPAddress:
    available = available_ips()
    available.compact()

    # Fairly choose a random CIDR that's large enough
    cidrs = [cidr for cidr in available.iter_cidrs() if cidr.prefixlen <= prefixlen]
    weights = [len(cidr) for cidr in cidrs]
    (cidr,) = random.choices(cidrs, weights)

    chosen = IPNetwork(random.choice(cidr))
    chosen.prefixlen = prefixlen
    return chosen


def random_point_to_point() -> tuple[IPNetwork, IPAddress]:
    subnet = random_subnet(30)
    local_host, remote_host = subnet.iter_hosts()

    prefix = IPNetwork(local_host)
    prefix.prefixlen = subnet.prefixlen

    return prefix, remote_host


def wait_for_interface(name: str, timeout: float) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        ret = subprocess.call(
            ["ip", "address", "show", name],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if ret == 0:
            break
        time.sleep(0.1)
    else:
        raise TimeoutError


def bring_up(name: str, prefix: IPNetwork) -> None:
    subprocess.check_call(["ip", "address", "replace", str(prefix), "dev", name])
    subprocess.check_call(["ip", "link", "set", name, "up"])


def route_interface(addr: IPAddress) -> str:
    output = subprocess.check_output(["ip", "-json", "-4", "route", "get", str(addr)])
    return json.loads(output)[0]["dev"]
