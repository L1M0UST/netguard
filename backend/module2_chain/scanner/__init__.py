"""Shared-workspace discovery and claim handling."""

from backend.module2_chain.scanner.claim import TaskClaimer
from backend.module2_chain.scanner.manifest import (
    compute_sha256,
    load_manifest,
    manifest_checksum,
    verify_manifest,
)
from backend.module2_chain.scanner.workspace_scanner import WorkspaceScanner

__all__ = [
    "TaskClaimer",
    "WorkspaceScanner",
    "compute_sha256",
    "load_manifest",
    "manifest_checksum",
    "verify_manifest",
]
