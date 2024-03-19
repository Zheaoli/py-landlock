class LandLockSyscallException(Exception):
    def __init__(self, error_code: int):
        self.error_code = error_code
        super().__init__(f"Landlock syscall failed with error code {error_code}")

