"""Narrow host prerequisite checks for legacy live-permit integrations only."""
import os
import sys

import pytest


LIVE_PERMIT_TESTS = {
    "test_current_process_without_credentials_changes",
    "test_current_account_and_process_temporary_policy",
}


def pytest_collection_modifyitems(items):
    selected = [item for item in items if item.name in LIVE_PERMIT_TESTS]
    if not selected or not sys.platform.startswith("linux"):
        return
    import lsm
    decision = lsm.evaluate(lsm.inspect_process(os.getpid()), 0)
    if decision.status != "resolved":
        marker = pytest.mark.skip(reason="Live permit integration requires resolved host LSM context: " + " ".join(decision.reasons))
        for item in selected:
            item.add_marker(marker)
