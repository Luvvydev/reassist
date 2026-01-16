from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Optional

from .ioc import extract_iocs
from .models import Analysis, FileInfo, IOCResult, StringsResult, ToolOutputs
from .util import run_cmd, sha256_file, which


def get_file_info(path: str) -> FileInfo:
    p = Path(path)
    if not p.exists() or not p.is_file():
        raise FileNotFoundError(path)

    fi = FileInfo(path=str(p), size_bytes=p.stat().st_size, sha256=sha256_file(p))

    if which("file"):
        _, out, _ = run_cmd(["file", "-b", str(p)], timeout_s=10)
        fi.file_output = out.strip() or None
        _, mout, _ = run_cmd(["file", "-b", "--mime-type", str(p)], timeout_s=10)
        fi.mime = mout.strip() or None

    return fi


def extract_strings(path: str, min_len: int = 10, max_sample: int = 8000) -> StringsResult:
    if not which("strings"):
        raise RuntimeError("strings not found on PATH")

    rc, out, err = run_cmd(["strings", "-n", str(min_len), path], timeout_s=60)
    if rc != 0 and not out:
        raise RuntimeError(f"strings failed: {err.strip()}")

    lines = [l.strip() for l in out.splitlines() if l.strip()]
    sample = lines[:max_sample]
    return StringsResult(min_len=min_len, total=len(lines), sample=sample)


def extract_import_hints(path: str, file_output: Optional[str]) -> Dict[str, List[str]]:
    hints: Dict[str, List[str]] = {}

    # ELF: readelf undefined symbols
    if which("readelf") and (file_output or "").lower().find("elf") != -1:
        rc, out, _ = run_cmd(["readelf", "-Ws", path], timeout_s=60)
        if rc == 0 and out:
            syms: List[str] = []
            for line in out.splitlines():
                parts = line.split()
                if len(parts) < 8:
                    continue
                # Ndx field is commonly at index 6
                if parts[6] != "UND":
                    continue
                name = parts[7]
                if name and name not in syms:
                    syms.append(name)
            if syms:
                hints["elf_undefined_symbols"] = syms

    # PE: objdump import tables (best effort)
    if which("objdump") and (file_output or "").lower().find("pe32") != -1:
        rc, out, _ = run_cmd(["objdump", "-p", path], timeout_s=60)
        if rc == 0 and out:
            dlls: List[str] = []
            for line in out.splitlines():
                t = line.strip()
                if t.startswith("DLL Name:"):
                    dlls.append(t.split(":", 1)[1].strip())
            if dlls:
                hints["pe_dlls"] = sorted(set(dlls))

    return hints


def triage(path: str, min_string_len: int = 10, max_strings: int = 8000) -> Analysis:
    fi = get_file_info(path)

    strings_res: Optional[StringsResult] = None
    iocs: Optional[IOCResult] = None
    notes: List[str] = []

    try:
        strings_res = extract_strings(path, min_len=min_string_len, max_sample=max_strings)
        iocs = extract_iocs(strings_res.sample)
    except Exception as e:
        notes.append(f"strings/ioc: {type(e).__name__}: {e}")

    imports: Dict[str, List[str]] = {}
    try:
        imports = extract_import_hints(path, fi.file_output)
    except Exception as e:
        notes.append(f"imports: {type(e).__name__}: {e}")

    tools = ToolOutputs(strings=strings_res, iocs=iocs, imports=imports, notes=notes)
    return Analysis(file=fi, tools=tools)
