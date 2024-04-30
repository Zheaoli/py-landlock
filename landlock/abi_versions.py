from dataclasses import dataclass

from landlock import syscall
from landlock.access_sets.access_fs import AccessFSSet
from landlock.access_sets.access_net import AccessNetSet


@dataclass
class ABIVersion:
    version: int
    support_access_fs: AccessFSSet
    support_access_network: AccessNetSet


_INDEX = [
    ABIVersion(0, AccessFSSet(0), AccessNetSet(0)),
    ABIVersion(1, AccessFSSet((1 << 13) - 1), AccessNetSet(0)),
    ABIVersion(2, AccessFSSet((1 << 14) - 1), AccessNetSet(0)),
    ABIVersion(3, AccessFSSet((1 << 15) - 1), AccessNetSet(0)),
    ABIVersion(4, AccessFSSet((1 << 15) - 1), AccessNetSet((1 << 2)) - 1),
]


def get_abi_info() -> ABIVersion:
    version = syscall.get_abi_version()
    return _INDEX[version] if version <= len(_INDEX) else _INDEX[-1]
