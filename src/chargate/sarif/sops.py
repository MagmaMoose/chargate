"""Detect SOPS-encrypted values so secret scanners don't gate on them — pure.

Mozilla SOPS encrypts individual values in place, leaving the keys readable::

    API_KEY: ENC[AES256_GCM,data:xyu...,iv:...,tag:...,type:str]

A secret scanner (gitleaks, trufflehog, ...) sees the high-entropy blob and
reports a hardcoded secret, but an ``ENC[AES256_GCM,...]`` value is *already
encrypted* — a 100% false positive. SOPS always seals values with AES256_GCM
(only the data key is wrapped by KMS/age/PGP), so that marker is a reliable,
unambiguous signal. A *plaintext* value in the same file — partial encryption via
``encrypted_regex``/``unencrypted_suffix``, or a not-yet-encrypted secret — does
NOT match and still gates ("unless it's unencrypted").

This module is pure (stdlib ``re`` only): it turns file text into the set of line
numbers holding an encrypted value, wrapped in a :class:`SopsIndex` the net-new
filter consults. Reading the files is an IO concern handled by the CLI, exactly
as :mod:`chargate.git` feeds a pure ``DiffIndex`` to the filter.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass

# A SOPS-encrypted value. The encoded fields (data/iv/tag) are base64 and the
# type is a bare word, none of which contain ``]``, so a single negated class
# cleanly captures the whole blob. Matches encrypted comments (``type:comment``)
# and the ``sops.mac`` too — all of which are equally encrypted.
SOPS_VALUE_RE = re.compile(r"ENC\[AES256_GCM,data:[^\]]*\]")


def is_sops_encrypted_line(text: str) -> bool:
    """True if ``text`` contains a SOPS ``ENC[AES256_GCM,...]`` encrypted value."""
    return SOPS_VALUE_RE.search(text) is not None


def scan_encrypted_lines(text: str) -> frozenset[int]:
    """1-indexed line numbers in ``text`` that hold a SOPS-encrypted value."""
    return frozenset(
        lineno
        for lineno, line in enumerate(text.splitlines(), start=1)
        if SOPS_VALUE_RE.search(line)
    )


@dataclass(frozen=True)
class SopsIndex:
    """Which lines of which files hold a SOPS-encrypted value.

    Keys are normalized (repo-relative) paths — the same normalization the filter
    applies to SARIF URIs — each mapping to the set of encrypted line numbers.
    """

    encrypted_lines: Mapping[str, frozenset[int]]

    def is_encrypted(self, path: str, line: int | None) -> bool:
        """True if ``path``'s ``line`` holds a SOPS-encrypted value."""
        if line is None:
            return False
        return line in self.encrypted_lines.get(path, frozenset())

    def __bool__(self) -> bool:
        return any(self.encrypted_lines.values())


# Sentinel for "the feature is off / nothing to consult".
EMPTY_SOPS_INDEX = SopsIndex({})
