from __future__ import annotations

import hashlib
import os
import subprocess
from pathlib import Path
from typing import List, Optional, Tuple


def sha256_file(path: str | os.PathLike) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def run_cmd(cmd: List[str], timeout_s: int = 30) -> Tuple[int, str, str]:
    p = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        errors="replace",
        timeout=timeout_s,
        check=False,
    )
    return p.returncode, p.stdout, p.stderr


def which(prog: str) -> Optional[str]:
    from shutil import which as _which

    return _which(prog)


def ensure_dir(path: str | os.PathLike) -> None:
    Path(path).mkdir(parents=True, exist_ok=True)
