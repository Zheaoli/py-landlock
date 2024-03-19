from dataclasses import dataclass

from landlock import syscall


@dataclass
class ABIVersion:
    version: int
    support_access_fs: int
    support_access_network: int


__INDEX = [
    ABIVersion(0, 0, 0),
    ABIVersion(1, (1 << 13) - 1, 0),
    ABIVersion(2, (1 << 14) - 1, 0),
    ABIVersion(3, (1 << 15) - 1, 0),
    ABIVersion(4, (1 << 15) - 1, (1 << 2) - 1),
]


def get_abi_info() -> ABIVersion:
    version = syscall.get_abi_version()
    return __INDEX[version]
