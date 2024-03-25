ACCESS_FS_NAMES = [
    "execute",
    "write_file",
    "read_file",
    "read_dir",
    "remove_dir",
    "remove_file",
    "make_char",
    "make_dir",
    "make_reg",
    "make_sock",
    "make_fifo",
    "make_block",
    "make_sym",
    "refer",
    "truncate",
]


class AccessFSSet(int):

    def __str__(self):
        if self == 0:
            return "∅"
        result = ["{"]
        for i in range(64):
            if self & (1 << i) == 0:
                continue
            if len(result) > 1:
                result.append(", ")
            if i < len(ACCESS_FS_NAMES):
                result.append(ACCESS_FS_NAMES[i])
            else:
                result.append(f"1<<{i}")
        result.append("}")
        return "".join(result)

    def is_subset(self, other: "AccessFSSet") -> bool:
        return self & other == self

    def intersection(self, other: "AccessFSSet") -> "AccessFSSet":
        return self & other

    def union(self, other: "AccessFSSet") -> "AccessFSSet":
        return self | other

    def is_empty(self) -> bool:
        return self == 0

    def valid(self) -> bool:
        return self.is_subset(SUPPORTED_ACCESS_FS)


SUPPORTED_ACCESS_FS = AccessFSSet((1 << len(ACCESS_FS_NAMES)) - 1)
