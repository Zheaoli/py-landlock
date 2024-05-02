import ctypes
from enum import IntEnum
from functools import partial

from landlock.syscall.exceptions import LandLockSyscallException

RULESET_ATTR_SIZE = 16

CREATE_RULESET_VERSION = 1


class AccessFs(IntEnum):
    AccessFSExecute = 1 << 0
    AccessFSWriteFile = 1 << 1
    AccessFSReadFile = 1 << 2
    AccessFSReadDir = 1 << 3
    AccessFSRemoveDir = 1 << 4
    AccessFSRemoveFile = 1 << 5
    AccessFSMakeChar = 1 << 6
    AccessFSMakeDir = 1 << 7
    AccessFSMakeReg = 1 << 8
    AccessFSMakeSock = 1 << 9
    AccessFSMakeFifo = 1 << 10
    AccessFSMakeBlock = 1 << 11
    AccessFSMakeSym = 1 << 12
    AccessFSRefer = 1 << 13
    AccessFSTruncate = 1 << 14


class AccessNetwork(IntEnum):
    AccessNetBindTCP = 1 << 0
    AccessNetConnectTCP = 1 << 1


class RulesetAttr(ctypes.Structure):
    _fields_ = [
        ("handled_access_fs", ctypes.c_uint64),
        ("handled_access_network", ctypes.c_uint64),
    ]


class PathBeneathAttr(ctypes.Structure):
    _fields_ = [
        ("allowed_access", ctypes.c_uint64),
        ("parent_fd", ctypes.c_int),
    ]


class NetServiceAttr(ctypes.Structure):
    _fields_ = [
        ("allowed_access", ctypes.c_uint64),
        ("port", ctypes.c_uint16),
    ]


__RULE_TYPE_PATH_BENEATH = 1
__RULE_TYPE_NET_SERVICE = 2

__SYS_LANDLOCK_CREATE_RULESET = 444
__SYS_LANDLOCK_ADD_RULE = 445
__SYS_LANDLOCK_RESTRICT_SELF = 446

__CREATE_RULESET_BINDING = ctypes.CDLL(None).syscall
__CREATE_RULESET_BINDING.restype = ctypes.c_int
__CREATE_RULESET_BINDING.argtypes = [
    ctypes.c_uint,
    ctypes.POINTER(RulesetAttr),
    ctypes.c_uint,
    ctypes.c_uint,
]
__CREATE_RULESET_SYSCALL = partial(
    __CREATE_RULESET_BINDING, __SYS_LANDLOCK_CREATE_RULESET
)

__ADD_RULE_BINDING = ctypes.CDLL(None).syscall
__ADD_RULE_BINDING.restype = ctypes.c_int
__ADD_RULE_BINDING.argtypes = [
    ctypes.c_uint,
    ctypes.c_int,
    ctypes.c_uint,
    ctypes.c_void_p,
    ctypes.c_uint,
]
__ADD_RULE_SYSCALL = partial(__ADD_RULE_BINDING, __SYS_LANDLOCK_ADD_RULE)

__RESTRICT_SELF_BINDING = ctypes.CDLL(None).syscall
__RESTRICT_SELF_BINDING.restype = ctypes.c_int
__RESTRICT_SELF_BINDING.argtypes = [ctypes.c_uint, ctypes.c_int, ctypes.c_uint]
__RESTRICT_SELF_SYSCALL = partial(__RESTRICT_SELF_BINDING, __SYS_LANDLOCK_RESTRICT_SELF)

__PRCTL_BINDING = ctypes.CDLL(None).syscall
__PRCTL_BINDING.restype = ctypes.c_int
__PRCTL_BINDING.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int]
__PRCTL_SYSCALL = partial(__PRCTL_BINDING, 157)


def create_ruleset(attr: RulesetAttr, flags: int) -> int:
    result = __CREATE_RULESET_SYSCALL(ctypes.byref(attr), RULESET_ATTR_SIZE, flags)
    if result < 0:
        raise LandLockSyscallException(ctypes.get_errno())
    return result


def get_abi_version() -> int:
    result = __CREATE_RULESET_SYSCALL(None, 0, CREATE_RULESET_VERSION)
    if result < 0:
        raise LandLockSyscallException(ctypes.get_errno())
    return result


def create_path_beneath_rule(ruleset_fd: int, attr: PathBeneathAttr, flags: int):
    result = __ADD_RULE_SYSCALL(
        ruleset_fd, __RULE_TYPE_PATH_BENEATH, ctypes.byref(attr), flags
    )
    if result < 0:
        raise LandLockSyscallException(ctypes.get_errno())


def create_net_service_rule(ruleset_fd: int, attr: NetServiceAttr, flags: int):
    result = __ADD_RULE_SYSCALL(
        ruleset_fd, __RULE_TYPE_NET_SERVICE, ctypes.byref(attr), flags
    )
    if result < 0:
        raise LandLockSyscallException(ctypes.get_errno())


def add_rule(ruleset_fd: int, rule_type: int, attr: PathBeneathAttr | NetServiceAttr, flags: int):
    result = __ADD_RULE_SYSCALL(ruleset_fd, rule_type, ctypes.pointer(attr), flags)
    if result < 0:
        raise LandLockSyscallException(ctypes.get_errno())


def restrict_self(ruleset_fd: int, flags: int):
    result = __RESTRICT_SELF_SYSCALL(ruleset_fd, flags)
    if result < 0:
        raise LandLockSyscallException(ctypes.get_errno())


def all_threads_prctl(option: int, arg1: int, arg2: int, arg3: int, arg4: int):
    result = __PRCTL_SYSCALL(option, arg1, arg2, arg3, arg4)
    if result < 0:
        raise LandLockSyscallException(ctypes.get_errno())


def add_path_beneath_rule(ruleset_fd: int, attr: PathBeneathAttr, flags: int):
    add_rule(ruleset_fd, __RULE_TYPE_PATH_BENEATH, attr, flags)


def add_net_service_rule(ruleset_fd: int, attr: NetServiceAttr, flags: int):
    add_rule(ruleset_fd, __RULE_TYPE_NET_SERVICE, attr, flags)
