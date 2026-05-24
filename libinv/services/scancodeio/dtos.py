"""
Typed return shapes for the ScanCode.io REST client.

Sprint 42.3: extracted from ``scancodeio/__init__.py`` so schema
declarations live independent of the client facade and the transport
plumbing. Endpoint methods (Sprint 42.4) and the public package
``__init__.py`` re-export every name defined here, so existing call-sites
(``from libinv.services.scancodeio import DiscoveredPackageDTO``) keep
working unchanged.

Only the fields actually consumed by libinv are listed; the upstream
serializer (``scancode.io/scanpipe/api/serializers.py``) returns many
more (license metadata, file paths, etc.).
"""

from __future__ import annotations

from typing import List
from typing import TypedDict


class DiscoveredPackageDTO(TypedDict, total=False):
    """Mirror of ``scanpipe_discoveredpackage`` columns libinv reads.

    Only the fields actually consumed by libinv are listed; the upstream
    serializer returns many more (license metadata, file paths, etc.).
    """

    purl: str
    type: str
    namespace: str
    name: str
    version: str
    qualifiers: str
    project_id: str
    affected_by_vulnerabilities: List[dict]


class SeverityCountDTO(TypedDict):
    """One row of the severity aggregate currently built via raw SQL."""

    severity_level: str
    count: int


class ScanpipeProjectDTO(TypedDict, total=False):
    """Subset of ``scanpipe_project`` columns libinv reads."""

    uuid: str
    name: str
    wasp_uuid_id: str


__all__ = [
    "DiscoveredPackageDTO",
    "ScanpipeProjectDTO",
    "SeverityCountDTO",
]
