"""Chargate token broker.

A tiny FastAPI service that lets any consumer's Chargate run post PR comments as
``Chargate[bot]`` without holding the Chargate GitHub App's key. A GitHub Actions
job proves its identity with an OIDC token; this broker verifies it and mints a
short-lived, repo-scoped installation token. It is deployed separately from the
stdlib-only ``chargate`` CLI and has its own dependencies.
"""
