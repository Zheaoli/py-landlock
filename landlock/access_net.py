ACCESS_NET_NAMES = [
    "bind_tcp",
    "connect_tcp",
]


class AccessNetSet(int):
    def __str__(self):
        if self == 0:
            return "∅"
        result = ["{"]
        for i in range(64):
            if self & (1 << i) == 0:
                continue
            if len(result) > 1:
                result.append(", ")
            if i < len(ACCESS_NET_NAMES):
                result.append(ACCESS_NET_NAMES[i])
            else:
                result.append(f"1<<{i}")
        result.append("}")
        return "".join(result)

    def is_subset(self, other: "AccessNetSet") -> bool:
        return self & other == self

    def intersection(self, other: "AccessNetSet") -> "AccessNetSet":
        return self & other

    def union(self, other: "AccessNetSet") -> "AccessNetSet":
        return self | other

    def is_empty(self) -> bool:
        return self == 0

    def valid(self) -> bool:
        return self.is_subset(SUPPORTED_ACCESS_NET)


SUPPORTED_ACCESS_NET = AccessNetSet((1 << len(ACCESS_NET_NAMES)) - 1)
