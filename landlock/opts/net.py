from dataclasses import dataclass
from typing import Self

from landlock.access_sets.access_net import AccessNetSet
from landlock.config import Config
from landlock.opts.abstract import AbstractRule


@dataclass
class NetRule(AbstractRule):
    access: AccessNetSet
    port: int

    def __str__(self):
        return f"ALLOW {self.access} on TCP port {self.port}"

    def _compatible_with_config(self, config: Config) -> bool:
        return self.access.is_subset(config.handled_access_network)

    def _downgrade(self, config: Config) -> tuple[Self, bool]:
        return NetRule(
            access=self.access.intersection(config.handled_access_network),
            port=self.port
        ), True

    def _add_to_rule_set(self, rule_set_fd: int, config: Config) -> None:
        flags = 0

