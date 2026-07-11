"""Unit tests for SOPS-encrypted-value detection (chargate.sarif.sops)."""

from __future__ import annotations

from chargate.sarif.sops import (
    EMPTY_SOPS_INDEX,
    SopsIndex,
    is_sops_encrypted_line,
    scan_encrypted_lines,
)

# A real SOPS-encrypted value (shape as emitted by `sops -e`).
ENC_VALUE = (
    "    DB_PORT: ENC[AES256_GCM,data:VoEcCA==,iv:Zf/QMzl/EhmN3jMn4XrUD5YAb"
    "SRqD0vucS/r2OyMmp8=,tag:J803kKvzOOF5Mo/xnx2fOQ==,type:str]"
)
ENC_COMMENT = "    #ENC[AES256_GCM,data:sd9QQ==,iv:yz==,tag:ak==,type:comment]"


# ── the encrypted-value pattern ──────────────────────────────────────────────


def test_matches_encrypted_value_and_comment():
    assert is_sops_encrypted_line(ENC_VALUE)
    assert is_sops_encrypted_line(ENC_COMMENT)
    # Quoting / JSON / dotenv styling around the value doesn't matter.
    assert is_sops_encrypted_line('password: "ENC[AES256_GCM,data:x==,type:str]"')
    assert is_sops_encrypted_line("PASSWORD=ENC[AES256_GCM,data:x==,type:str]")


def test_does_not_match_plaintext_or_partial():
    assert not is_sops_encrypted_line('REDIS_PASSWORD: ""')
    assert not is_sops_encrypted_line("SUPER_ADMIN_PASSWORD: hunter2")
    assert not is_sops_encrypted_line("")
    # A bare ENC[ without the AES256_GCM value marker is not a SOPS value.
    assert not is_sops_encrypted_line("note: ENC[whatever]")
    # sops metadata that isn't an encrypted value stays plaintext.
    assert not is_sops_encrypted_line("    version: 3.7.3")


# ── line scanning ────────────────────────────────────────────────────────────


def test_scan_encrypted_lines_returns_1_indexed_encrypted_lines():
    text = "\n".join(
        [
            "stringData:",  # 1
            ENC_VALUE,  # 2 (encrypted)
            'REDIS_PASSWORD: ""',  # 3 (plaintext)
            "SUPER_ADMIN_PASSWORD: hunter2",  # 4 (plaintext secret — still gates)
            ENC_COMMENT,  # 5 (encrypted comment)
        ]
    )
    assert scan_encrypted_lines(text) == frozenset({2, 5})


def test_scan_empty_text_is_empty():
    assert scan_encrypted_lines("") == frozenset()


# ── SopsIndex ────────────────────────────────────────────────────────────────


def test_index_membership_and_missing_path_and_none_line():
    index = SopsIndex({"k8s/prod/secret.yaml": frozenset({2, 5})})
    assert index.is_encrypted("k8s/prod/secret.yaml", 2)
    assert not index.is_encrypted("k8s/prod/secret.yaml", 3)  # plaintext line
    assert not index.is_encrypted("other.yaml", 2)  # file not indexed
    assert not index.is_encrypted("k8s/prod/secret.yaml", None)  # no region


def test_index_truthiness():
    assert not EMPTY_SOPS_INDEX
    assert not SopsIndex({"a.yaml": frozenset()})  # indexed but nothing encrypted
    assert SopsIndex({"a.yaml": frozenset({1})})
