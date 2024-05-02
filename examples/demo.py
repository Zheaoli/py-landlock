import os
from pathlib import Path

import pytest

from landlock.config import V4
from landlock.opts.path import read_only_dirs, read_write_dirs
from landlock.restrict import restrict


def overlay_test():
    directory_prefix = os.getenv("DIRECTORY_PREFIX") or "/opt/demo"
    lower = Path(os.path.join(directory_prefix, "lower"))
    upper = Path(os.path.join(directory_prefix, "upper"))
    work = Path(os.path.join(directory_prefix, "work"))
    merged = Path(os.path.join(directory_prefix, "merged"))
    if not lower.exists():
        lower.mkdir()
    if not upper.exists():
        upper.mkdir()
    if not work.exists():
        work.mkdir()
    if not merged.exists():
        merged.mkdir()
    os.system(f"sudo mount -t overlay -o lowerdir={lower},upperdir={upper},workdir={work} overlay {merged}")
    v4_config = V4
    rule = read_only_dirs([str(lower), str(upper)])
    new_rule = read_write_dirs([str(merged)])
    restrict(v4_config, [rule, new_rule])
    with pytest.raises(Exception):
        with open(os.path.join(lower, "test.txt"), "w") as f:
            f.write("test")
    with pytest.raises(Exception):
        with open(os.path.join(upper, "test.txt"), "w") as f:
            f.write("test")
    with open(os.path.join(merged, "test.txt"), "a+") as f:
        f.write("test")
    assert Path(os.path.join(merged, "test.txt")).exists()
    with pytest.raises(Exception):
        with open(os.path.join(lower, "test.txt"), "w") as f:
            f.write("test")
    with pytest.raises(Exception):
        with open(os.path.join("/tmp", "test.txt"), "w") as f:
            f.write("test")
    os.system(f"sudo umount {merged}")

if __name__ == '__main__':
    overlay_test()
