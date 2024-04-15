import os
from contextlib import contextmanager
from typing import Self, Iterable
from dataclasses import dataclass

from landlock import syscall
from landlock.access_sets.access_fs import AccessFSSet
from landlock.opts.abstract import AbstractRule
from landlock.config import Config, ACCESS_FS_READ, ACCESS_FS_READ_WRITE, ACCESS_FILE


@contextmanager
def os_open(path: str, flags: int) -> Iterable[int]:
    fd = os.open(path, flags)
    try:
        yield fd
    finally:
        os.close(fd)


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

    @staticmethod
    def has_refer(fs: AccessFSSet) -> bool:
        return fs & AccessFSSet(syscall.AccessFs.AccessFSRefer) != 0

    def __str__(self):
        return f"REQUIRED {self.access_fs} for paths {self.paths}"

    def _compatible_with_config(self, config: Config) -> bool:
        temp = self.access_fs
        if not self.enforce_subset:
            temp = temp.intersection(AccessFSSet(syscall.AccessFs.AccessFSRefer))
        return temp.is_subset(config.handled_access_fs)

    def _downgrade(self, config: Config) -> tuple[Self, bool]:
        if self.has_refer(self.access_fs) and not self.has_refer(
                config.handled_access_fs
        ):
            return FsRule(AccessFSSet(0), [], False, False), False
        return self._intersect_rights(config.handled_access_fs), True

    def _add_to_rule_set(self, rule_set_fd: int, config: Config):
        effective_access_fs = self.access_fs
        if not self.enforce_subset:
            effective_access_fs = effective_access_fs.intersection(
                AccessFSSet(syscall.AccessFs.AccessFSRefer)
            )
        for path in self.paths:
            syscall.add(rule_set_fd, path, effective_access_fs, self.ignore_missing)

    @staticmethod
    def __add_path(rule_set_fd: int, path: str, access_fs: AccessFSSet):
        with os_open(path, os.O_PATH | os.O_CLOEXEC) as fd:
            path_beaneath=P


def path_access(access_fs: AccessFSSet, paths: list[str]) -> FsRule:
    return FsRule(access_fs, paths, True, False)


def read_only_dirs(paths: list[str]) -> FsRule:
    return FsRule(ACCESS_FS_READ, paths, True, False)


def read_write_dirs(paths: list[str]) -> FsRule:
    return FsRule(ACCESS_FS_READ_WRITE, paths, True, False)


def read_only_files(paths: list[str]) -> FsRule:
    return FsRule(ACCESS_FILE & ACCESS_FS_READ_WRITE, paths, True, False)


def read_write_files(paths: list[str]) -> FsRule:
    return FsRule(ACCESS_FILE & ACCESS_FS_READ_WRITE, paths, True, False)
