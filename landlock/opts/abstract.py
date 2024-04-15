from abc import ABC, abstractmethod
from typing import Self

from landlock.config import Config


class AbstractRule(ABC):
    @abstractmethod
    def _compatible_with_config(self, config: Config) -> bool:
        pass

    @abstractmethod
    def _downgrade(self, config: Config) -> tuple[Self, bool]:
        pass

    @abstractmethod
    def _add_to_rule_set(self, rule_set_fd: int, config: Config) -> None:
        pass
