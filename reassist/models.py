from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class FileInfo(BaseModel):
    path: str
    size_bytes: int
    sha256: str
    file_output: Optional[str] = None
    mime: Optional[str] = None


class StringsResult(BaseModel):
    min_len: int
    total: int
    sample: List[str] = Field(default_factory=list)


class IOCResult(BaseModel):
    ipv4: List[str] = Field(default_factory=list)
    ipv6: List[str] = Field(default_factory=list)
    domains: List[str] = Field(default_factory=list)
    urls: List[str] = Field(default_factory=list)
    emails: List[str] = Field(default_factory=list)
    file_paths: List[str] = Field(default_factory=list)
    registry_paths: List[str] = Field(default_factory=list)
    crypto_keywords: List[str] = Field(default_factory=list)


class ToolOutputs(BaseModel):
    strings: Optional[StringsResult] = None
    iocs: Optional[IOCResult] = None
    imports: Dict[str, List[str]] = Field(default_factory=dict)
    notes: List[str] = Field(default_factory=list)


class Analysis(BaseModel):
    schema_version: int = 1
    file: FileInfo
    tools: ToolOutputs
    ghidra_export: Optional[Dict[str, Any]] = None
    meta: Dict[str, Any] = Field(default_factory=dict)
