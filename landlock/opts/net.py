from dataclasses import dataclass
from typing import Self

from landlock import syscall
from landlock.access_sets.access_net import AccessNetSet
from landlock.config import Config
from landlock.opts.base import BaseRule


@dataclass
class NetRule(BaseRule):
    access: AccessNetSet
    port: int

    def __str__(self):
        return f"ALLOW {self.access} on TCP port {self.port}"

    def compatible_with_config(self, config: Config) -> bool:
        return self.access.is_subset(config.handled_access_network)

    def downgrade(self, config: Config) -> tuple[Self, bool]:
        return NetRule(
            access=self.access.intersection(config.handled_access_network),
            port=self.port
        ), True

    def add_to_rule_set(self, rule_set_fd: int, config: Config) -> None:
        attr = syscall.NetServiceAttr(allowed_access=int(self.access), port=self.port)
        syscall.add_net_service_rule(rule_set_fd, attr, 0)
