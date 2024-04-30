from landlock.opts.base import BaseRule


class LandLockSyscallException(Exception):
    def __init__(self, error_code: int):
        self.error_code = error_code
        super().__init__(f"Landlock syscall failed with error code {error_code}")


class LandLockUnsupportedException(Exception):
    def __init__(self):
        super().__init__("Landlock is not supported on this system")


class LandLockUncompilableRuleException(Exception):
    def __init__(self, rule: BaseRule):
        super().__init__(f"Rule {rule} is not compatible with the current Landlock configuration")


class LandLockABIVersionMissingException(Exception):
    def __init__(self, want: int):
        super().__init__(f"missing kernel Landlock support. want: {want}")
