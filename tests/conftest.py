"""Shared SARIF/diff factories for the test suite."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest


@pytest.fixture
def make_result() -> Callable[..., dict[str, Any]]:
    def _make(
        uri: str | None = None,
        start_line: int | None = None,
        *,
        level: str | None = None,
        rule_id: str | None = None,
        security_severity: float | str | None = None,
        message: str = "finding",
        locations: list[dict] | None = None,
    ) -> dict[str, Any]:
        result: dict[str, Any] = {"message": {"text": message}}
        if rule_id is not None:
            result["ruleId"] = rule_id
        if level is not None:
            result["level"] = level
        if security_severity is not None:
            result["properties"] = {"security-severity": str(security_severity)}
        if locations is not None:
            result["locations"] = locations
        elif uri is not None:
            physical: dict[str, Any] = {"artifactLocation": {"uri": uri}}
            if start_line is not None:
                physical["region"] = {"startLine": start_line}
            result["locations"] = [{"physicalLocation": physical}]
        return result

    return _make


@pytest.fixture
def make_sarif() -> Callable[..., dict[str, Any]]:
    def _make(
        results: list[dict],
        *,
        rules: list[dict] | None = None,
        tool_name: str = "TestTool",
    ) -> dict[str, Any]:
        driver: dict[str, Any] = {"name": tool_name}
        if rules is not None:
            driver["rules"] = rules
        return {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [{"tool": {"driver": driver}, "results": results}],
        }

    return _make
