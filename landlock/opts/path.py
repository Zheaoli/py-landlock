from typing import Self
from dataclasses import dataclass

from landlock import syscall
from landlock.access_sets.access_fs import AccessFSSet
from landlock.opts.abstract import AbstractRule
from landlock.config import Config


@dataclass
class FsRule(AbstractRule):
    access_fs: AccessFSSet
    paths: list[str]
    enforce_subset: bool
    ignore_missing: bool

    def _with_right(self, access_fs: AccessFSSet) -> Self:
        self.access_fs = self.access_fs.union(access_fs)
        return self

    def _intersect_rights(self, access_fs: AccessFSSet) -> Self:
        self.access_fs = self.access_fs.intersection(access_fs)
        return self

    def with_refer(self) -> Self:
        return self._with_right(AccessFSSet(syscall.AccessFs.AccessFSRefer))

    def ignore_missing(self) -> Self:
        self.ignore_missing = True
        return self

    def __str__(self):
        return f"REQUIRED {self.access_fs} for paths {self.paths}"

    def _compatible_with_config(self, config: Config) -> bool:
        temp = self.access_fs
        if not self.enforce_subset:
            temp = temp.intersection(AccessFSSet(syscall.AccessFs.AccessFSRefer))
        return temp.is_subset(config.handled_access_fs)

    def _downgrade(self, config: Config) -> tuple[Self, bool]:
        if self.has_refer(self.access_fs) and not self.has_refer(config.handled_access_fs):
            return FsRule(AccessFSSet(0), [], False, False), False
        return self._intersect_rights(config.handled_access_fs), True

    def _add_to_rule_set(self, rule_set_fd: int, config: Config):
        pass
