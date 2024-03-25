from landlock import syscall
from landlock.access_fs import AccessFSSet
from landlock.access_net import AccessNetSet

_ACCESS_FILE = AccessFSSet(
    syscall.AccessFs.AccessFSExecute
    | syscall.AccessFs.AccessFSWriteFile
    | syscall.AccessFs.AccessFSReadFile
)
_ACCESS_FS_READ = AccessFSSet(
    syscall.AccessFs.AccessFSExecute
    | syscall.AccessFs.AccessFSReadFile
    | syscall.AccessFs.AccessFSReadDir
)
_ACCESS_FS_WRITE = AccessFSSet(
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

_ACCESS_FS_READ_WRITE = _ACCESS_FS_READ.union(_ACCESS_FS_WRITE)


