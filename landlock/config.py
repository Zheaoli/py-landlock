from typing import Optional, Self

from landlock import syscall
from landlock.access_sets.access_fs import AccessFSSet
from landlock.access_sets.access_net import AccessNetSet
from landlock.abi_versions import _INDEX, ABIVersion

from dataclasses import dataclass

ACCESS_FILE = AccessFSSet(
    syscall.AccessFs.AccessFSExecute
    | syscall.AccessFs.AccessFSWriteFile
    | syscall.AccessFs.AccessFSReadFile
)
ACCESS_FS_READ = AccessFSSet(
    syscall.AccessFs.AccessFSExecute
    | syscall.AccessFs.AccessFSReadFile
    | syscall.AccessFs.AccessFSReadDir
)
ACCESS_FS_WRITE = AccessFSSet(
    syscall.AccessFs.AccessFSWriteFile
    | syscall.AccessFs.AccessFSRemoveDir
    | syscall.AccessFs.AccessFSRemoveFile
    | syscall.AccessFs.AccessFSMakeChar
    | syscall.AccessFs.AccessFSMakeDir
    | syscall.AccessFs.AccessFSMakeReg
    | syscall.AccessFs.AccessFSMakeSock
    | syscall.AccessFs.AccessFSMakeFifo
    | syscall.AccessFs.AccessFSMakeBlock
    | syscall.AccessFs.AccessFSMakeSym
    | syscall.AccessFs.AccessFSTruncate
)

ACCESS_FS_READ_WRITE = ACCESS_FS_READ.union(ACCESS_FS_WRITE)


@dataclass
class Config:
    handled_access_fs: Optional["AccessFSSet"]
    handled_access_network: Optional["AccessNetSet"]
    best_effort: bool

    def compatible_with_abi(self, abi: ABIVersion) -> bool:
        if self.handled_access_fs is not None:
            if not self.handled_access_fs.is_subset(abi.support_access_fs):
                return False
        if self.handled_access_network is not None:
            if not self.handled_access_network.is_subset(abi.support_access_network):
                return False
        return True

    def __str__(self) -> str:
        abi = ABIVersion(-1, AccessFSSet(0), AccessNetSet(0))
        for i in range(len(_INDEX)):
            if self.compatible_with_abi(_INDEX[i]):
                abi = _INDEX[i]
        fs_set_description = str(self.handled_access_fs)
        if (
                abi.support_access_fs == self.handled_access_fs
                and not self.handled_access_fs.is_empty()
        ):
            fs_set_description = "all"
        net_set_description = str(self.handled_access_network)
        if (
                abi.support_access_network == self.handled_access_network
                and not self.handled_access_network.is_empty()
        ):
            net_set_description = "all"
        best_effort = "" if not self.best_effort else " (best effort)"
        version = "V???" if abi.version < 0 else f"V{abi.version}"
        return (
            f"{'{'} Landlock {version}; FS: {fs_set_description}; "
            f"Net:{net_set_description}; BestEffort:{best_effort} {'}'}"
        )

    def restrict_to(self, abi: ABIVersion) -> Self:
        return Config(
            handled_access_fs=self.handled_access_fs.intersection(abi.support_access_fs),
            handled_access_network=self.handled_access_network.intersection(
                abi.support_access_network
            ),
            best_effort=self.best_effort,
        )
