"""Chargate — a thin MegaLinter wrapper with net-new (PR-diff) finding gating.

The public, dependency-free crown jewel lives under :mod:`chargate.sarif`: a pure,
deterministic SARIF net-new filter that, given a SARIF report plus the set of
lines a pull request introduced, decides which findings are *net-new* (and thus
gate-blocking) versus pre-existing (never blocking).
"""

__version__ = "2.3.0"
