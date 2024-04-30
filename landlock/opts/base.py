from abc import ABC, abstractmethod
from typing import Self

from landlock.config import Config


class BaseRule(ABC):
    @abstractmethod
    def compatible_with_config(self, config: Config) -> bool:
        pass

    @abstractmethod
    def downgrade(self, config: Config) -> tuple[Self, bool]:
        pass

    @abstractmethod
    def add_to_rule_set(self, rule_set_fd: int, config: Config) -> None:
        pass
