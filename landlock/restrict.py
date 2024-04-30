from typing import Optional

from landlock import syscall
from landlock.abi_versions import ABIVersion, get_abi_info
from landlock.access_sets.access_net import AccessNetSet
from landlock.config import Config
from landlock.exceptions import LandLockUncompilableRuleException, LandLockABIVersionMissingException
from landlock.opts.base import BaseRule
from landlock.syscall import RulesetAttr


def downgrade(config: Config, rules: list[BaseRule], abi: ABIVersion) -> tuple[Optional["Config"], list[BaseRule]]:
    config = config.restrict_to(abi)
    results: list[BaseRule] = []
    for rule in rules:
        rule, flag = rule.downgrade(config)
        if not downgrade:
            return None, []
        results.append(rule)
    return config, results


def restrict(config: Config, rules: list[BaseRule]):
    for rule in rules:
        if not rule.compatible_with_config(config):
            raise LandLockUncompilableRuleException(rule)
    abi_version = get_abi_info()
    if config.best_effort:
        config, rules = downgrade(config, rules, abi_version)
        if not config:
            raise ValueError("No compatible configuration found")
    if not config.compatible_with_abi(abi_version):
        raise LandLockABIVersionMissingException(abi_version.version)
    if config.handled_access_fs.is_empty() and config.handled_access_network.is_empty():
        return
    ruleset_attr = RulesetAttr(handled_access_fs=config.handled_access_fs,
                               handled_access_network=config.handled_access_network)
    fd = syscall.create_ruleset(ruleset_attr, 0)
    for rule in rules:
        rule.add_to_rule_set(fd, config)
    syscall.all_threads_prctl(0x26, 1, 0, 0, 0)
    syscall.restrict_self(fd, 0)


def restrict_path(config: Config, rules: list[BaseRule]):
    config.handled_access_network = AccessNetSet(0)
    restrict(config, rules)


def restrict_net(config: Config, rules: list[BaseRule]):
    config.handled_access_fs = AccessNetSet(0)
    restrict(config, rules)
