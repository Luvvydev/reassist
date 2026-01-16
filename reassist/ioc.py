from __future__ import annotations

import re
from typing import Iterable, Set

from .models import IOCResult

_IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b")
_IPV6 = re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b")
_URL = re.compile(r"\b(?:https?://|ftp://)[^\s\"\']+\b")
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_DOMAIN = re.compile(r"\b(?:[A-Za-z0-9-]{1,63}\.)+(?:[A-Za-z]{2,63})\b")
_WIN_PATH = re.compile(r"\b[A-Za-z]:\\\\[^\s\"\']{1,260}\b")
_UNIX_PATH = re.compile(r"(?:^|\s)(/[^\s\"\']{1,260})")
_REG = re.compile(r"\b(?:HKLM|HKCU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER)\\\\[^\s\"\']+\b", re.IGNORECASE)
_CRYPTO = re.compile(r"\b(?:AES|RC4|RSA|ChaCha20|Salsa20|DES|3DES|MD5|SHA1|SHA256|SHA512|BLAKE2|HMAC|XOR|BASE64)\b", re.IGNORECASE)


def _uniq(seq: Iterable[str]) -> list[str]:
    seen: Set[str] = set()
    out: list[str] = []
    for x in seq:
        x = x.strip()
        if not x or x in seen:
            continue
        seen.add(x)
        out.append(x)
    return out


def extract_iocs(lines: Iterable[str]) -> IOCResult:
    ipv4: list[str] = []
    ipv6: list[str] = []
    urls: list[str] = []
    emails: list[str] = []
    domains: list[str] = []
    file_paths: list[str] = []
    registry_paths: list[str] = []
    crypto: list[str] = []

    for s in lines:
        ipv4 += _IPV4.findall(s)
        ipv6 += _IPV6.findall(s)
        urls += _URL.findall(s)
        emails += _EMAIL.findall(s)
        domains += _DOMAIN.findall(s)
        file_paths += _WIN_PATH.findall(s)
        file_paths += [m.group(1) for m in _UNIX_PATH.finditer(s)]
        registry_paths += [m.group(0) for m in _REG.finditer(s)]
        crypto += _CRYPTO.findall(s)

    # Remove domains that are just email domains or URL hosts
    email_domains = {e.split("@", 1)[1].lower() for e in emails if "@" in e}
    url_hosts: Set[str] = set()
    for u in urls:
        try:
            host = u.split("//", 1)[1].split("/", 1)[0].split(":", 1)[0]
            if host:
                url_hosts.add(host.lower())
        except Exception:
            pass

    domains = [d for d in domains if d.lower() not in email_domains and d.lower() not in url_hosts]

    return IOCResult(
        ipv4=_uniq(ipv4),
        ipv6=_uniq(ipv6),
        domains=_uniq([d.lower() for d in domains if d.lower() not in {"localhost"}]),
        urls=_uniq(urls),
        emails=_uniq(emails),
        file_paths=_uniq(file_paths),
        registry_paths=_uniq(registry_paths),
        crypto_keywords=_uniq([c.upper() for c in crypto]),
    )
