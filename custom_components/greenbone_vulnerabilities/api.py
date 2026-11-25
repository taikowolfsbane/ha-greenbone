"""Thin sync client for the Greenbone Management Protocol (GMP) queries this integration needs.

Every call here is blocking (python-gvm talks over a raw socket, no asyncio support),
so the coordinator always runs this client's methods inside the event loop's executor.

This does NOT talk to gvmd's unix socket directly (not reachable off-box) or to gsad's
web UI (its HTTP bridge isn't a generic GMP-over-HTTP endpoint in current GSA versions).
Instead it connects to a plain TCP port that a `socat` relay on the Greenbone host forwards
to gvmd's unix socket - see the integration's README for how that relay is set up.
"""
from __future__ import annotations

import logging
import socket
from typing import Any

from gvm.protocols.gmp import Gmp
from gvm.errors import GvmError
from gvm.transforms import EtreeCheckCommandTransform

from .const import SEVERITY_THRESHOLDS

_LOGGER = logging.getLogger(__name__)


class GreenboneError(Exception):
    """Raised when a GMP request to Greenbone fails."""


class _PlainTcpConnection:
    """A minimal python-gvm connection over a plain (non-TLS) TCP socket.

    python-gvm ships TLSConnection/UnixSocketConnection/SSHConnection, but nothing
    for a bare TCP socket - which is what the `socat` relay on the Greenbone host
    speaks, since it's just forwarding to gvmd's plaintext unix socket.
    """

    def __init__(self, hostname: str, port: int, timeout: float = 20) -> None:
        self._hostname = hostname
        self._port = port
        self._timeout = timeout
        self._socket: socket.socket | None = None

    def connect(self) -> None:
        self._socket = socket.create_connection(
            (self._hostname, self._port), timeout=self._timeout
        )

    def send(self, data: bytes) -> None:
        assert self._socket is not None
        self._socket.sendall(data)

    def read(self) -> bytes:
        assert self._socket is not None
        return self._socket.recv(1024 * 1024)

    def finish_send(self) -> None:
        pass

    def disconnect(self) -> None:
        if self._socket is not None:
            self._socket.close()
            self._socket = None


def _severity_bucket(score: float) -> str | None:
    """Map a CVSS score to the critical/high/medium/low buckets, or None for Log/info."""
    if score >= SEVERITY_THRESHOLDS["critical"]:
        return "critical"
    if score >= SEVERITY_THRESHOLDS["high"]:
        return "high"
    if score >= SEVERITY_THRESHOLDS["medium"]:
        return "medium"
    if score >= SEVERITY_THRESHOLDS["low"]:
        return "low"
    return None


def _empty_counts() -> dict[str, int]:
    return {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0}


def _host_label(host_elem) -> str:
    """Prefer the scan's resolved hostname over the raw IP, falling back to the IP."""
    hostname = host_elem.findtext("hostname")
    ip = (host_elem.text or "").strip()
    return hostname.strip() if hostname and hostname.strip() else ip


class GreenboneClient:
    """Queries a Greenbone/GVM instance (via a GMP TCP relay) for vulnerability data."""

    def __init__(self, hostname: str, port: int, username: str, password: str) -> None:
        self._hostname = hostname
        self._port = port
        self._username = username
        self._password = password

    def _connect(self) -> Gmp:
        connection = _PlainTcpConnection(self._hostname, self._port)
        return Gmp(connection=connection, transform=EtreeCheckCommandTransform())

    def get_vulnerability_summary(self) -> dict[str, Any]:
        """Return global vulnerability counts by severity, a per-host breakdown, and
        the highest-severity findings, all drawn from each task's latest report.
        """
        global_counts = _empty_counts()
        by_host: dict[str, dict[str, int]] = {}
        top_candidates: list[dict[str, Any]] = []

        try:
            with self._connect() as gmp:
                gmp.authenticate(self._username, self._password)
                tasks = gmp.get_tasks()

                report_ids: list[str] = []
                for task in tasks.findall("task"):
                    # A Running task's most recent data lives under current_report,
                    # not last_report (which only ever points at a *completed* run,
                    # and is absent entirely until the task's first run finishes).
                    report_elem = task.find("current_report/report")
                    if report_elem is None:
                        report_elem = task.find("last_report/report")
                    if report_elem is not None:
                        report_ids.append(report_elem.get("id"))

                for report_id in report_ids:
                    results = gmp.get_results(
                        filter_string=f"apply_overrides=0 min_qod=70 rows=-1 report_id={report_id}"
                    )
                    for result in results.findall("result"):
                        severity_text = result.findtext("severity")
                        severity = float(severity_text) if severity_text else 0.0
                        bucket = _severity_bucket(severity)
                        if bucket is None:
                            continue

                        host_elem = result.find("host")
                        host_label = _host_label(host_elem) if host_elem is not None else "unknown"

                        global_counts[bucket] += 1
                        global_counts["total"] += 1

                        host_counts = by_host.setdefault(host_label, _empty_counts())
                        host_counts[bucket] += 1
                        host_counts["total"] += 1

                        if bucket in ("critical", "high"):
                            nvt = result.find("nvt")
                            cve_ref = None
                            if nvt is not None:
                                cve_ref = nvt.find("refs/ref[@type='cve']")
                            top_candidates.append(
                                {
                                    "name": result.findtext("name"),
                                    "severity": bucket,
                                    "cvss_score": severity,
                                    "cve": cve_ref.get("id") if cve_ref is not None else None,
                                    "host": host_label,
                                }
                            )
        except GvmError as err:
            raise GreenboneError(str(err)) from err
        except OSError as err:
            raise GreenboneError(f"Error connecting to Greenbone GMP relay: {err}") from err

        top_candidates.sort(
            key=lambda f: (0 if f["severity"] == "critical" else 1, -f["cvss_score"])
        )

        return {
            "global": global_counts,
            "by_host": by_host,
            "top_vulnerabilities": top_candidates[:15],
        }
