"""Arc 11 phase 63 — backup envelope round-trip + safe-extract."""
from __future__ import annotations

import io
import os
import tarfile
from pathlib import Path

import pytest

import backup


def test_encrypt_decrypt_roundtrip():
    payload = b"the quick brown fox jumps over the lazy dog" * 100
    blob = backup.encrypt(payload, "passphrase-with-enough-len")
    assert blob.startswith(backup.MAGIC)
    assert backup.decrypt(blob, "passphrase-with-enough-len") == payload


def test_wrong_passphrase_rejected():
    blob = backup.encrypt(b"secret", "right-passphrase")
    with pytest.raises(ValueError):
        backup.decrypt(blob, "wrong-passphrase")


def test_bad_magic_rejected():
    with pytest.raises(ValueError):
        backup.decrypt(b"not-protek" + b"\x00" * 64, "any")


def test_local_backend_roundtrip(tmp_path: Path):
    b = backup.LocalBackend(tmp_path)
    b.put("daily/x.bin", b"hello")
    assert b.list_keys("daily/") == ["daily/x.bin"]
    assert b.get("daily/x.bin") == b"hello"
    b.delete("daily/x.bin")
    assert b.list_keys() == []


def test_local_backend_creates_dir(tmp_path: Path):
    base = tmp_path / "nested" / "deeper"
    b = backup.LocalBackend(base)
    assert base.exists()
    b.put("k.bin", b"x")
    assert (base / "k.bin").exists()


def test_passphrase_too_short_blocks_run(monkeypatch):
    monkeypatch.setenv("BACKUP_PASSPHRASE", "tooshort")
    with pytest.raises(RuntimeError, match="too short"):
        backup._passphrase_or_die()


def test_passphrase_missing_blocks_run(monkeypatch):
    monkeypatch.delenv("BACKUP_PASSPHRASE", raising=False)
    with pytest.raises(RuntimeError, match="not set"):
        backup._passphrase_or_die()
