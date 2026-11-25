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


def _empty_host_details() -> dict[str, Any]:
    return {"ports": set(), "operating_systems": set(), "applications": set()}


def _host_label(host_elem) -> str:
    """Prefer the scan's resolved hostname over the raw IP, falling back to the IP."""
    hostname = host_elem.findtext("hostname")
    ip = (host_elem.text or "").strip()
    return hostname.strip() if hostname and hostname.strip() else ip


# OID of the "CPE Inventory" NVT, which reports every CPE (operating system, hardware,
# or application) it identified for a host as pipe-separated "<host>|<cpe>" lines in its
# description - the only place this data shows up in GMP's results, there's no separate
# structured field for it. Matched by OID rather than name since the NVT's human-readable
# name could vary by Greenbone feed version/locale, but the OID is permanent.
_CPE_INVENTORY_OID = "1.3.6.1.4.1.25623.1.0.810002"

# Placeholder "port" values GMP uses for results that aren't about a specific network
# port (host details, general CPE findings, etc.) - these aren't real open ports.
_NON_PORT_PREFIXES = ("general/",)


def _parse_cpe_inventory(description: str) -> tuple[set[str], set[str]]:
    """Split a CPE Inventory result's description into (os_cpes, app_cpes).

    Each line looks like "<host>|<cpe-string>", e.g. "10.0.0.1|cpe:/o:linux:kernel".
    cpe:/o:... is an operating system, cpe:/a:... is an application, cpe:/h:... is
    hardware (ignored here - not relevant to this integration).
    """
    os_cpes: set[str] = set()
    app_cpes: set[str] = set()
    for line in description.splitlines():
        line = line.strip()
        if "|" not in line:
            continue
        _, _, cpe = line.partition("|")
        cpe = cpe.strip()
        if cpe.startswith("cpe:/o:"):
            os_cpes.add(cpe)
        elif cpe.startswith("cpe:/a:"):
            app_cpes.add(cpe)
    return os_cpes, app_cpes


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
        """Return global vulnerability counts by severity, a per-host breakdown
        (including open ports/OS/applications), the highest-severity findings, and
        each task's current status/progress - all drawn from each task's latest
        (or currently in-progress) report.
        """
        global_counts = _empty_counts()
        by_host: dict[str, dict[str, int]] = {}
        host_details: dict[str, dict[str, Any]] = {}
        top_candidates: list[dict[str, Any]] = []
        task_summaries: list[dict[str, Any]] = []

        try:
            with self._connect() as gmp:
                gmp.authenticate(self._username, self._password)
                tasks = gmp.get_tasks()

                report_ids: list[str] = []
                for task in tasks.findall("task"):
                    task_summaries.append(
                        {
                            "id": task.get("id"),
                            "name": task.findtext("name"),
                            "status": task.findtext("status"),
                            "progress": int(task.findtext("progress") or 0),
                        }
                    )

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
                        host_elem = result.find("host")
                        host_label = _host_label(host_elem) if host_elem is not None else "unknown"
                        details = host_details.setdefault(host_label, _empty_host_details())

                        nvt = result.find("nvt")
                        port = result.findtext("port") or ""
                        if port and not port.startswith(_NON_PORT_PREFIXES):
                            details["ports"].add(port)

                        if nvt is not None and nvt.get("oid") == _CPE_INVENTORY_OID:
                            os_cpes, app_cpes = _parse_cpe_inventory(
                                result.findtext("description") or ""
                            )
                            details["operating_systems"].update(os_cpes)
                            details["applications"].update(app_cpes)

                        severity_text = result.findtext("severity")
                        severity = float(severity_text) if severity_text else 0.0
                        bucket = _severity_bucket(severity)
                        if bucket is None:
                            continue

                        global_counts[bucket] += 1
                        global_counts["total"] += 1

                        host_counts = by_host.setdefault(host_label, _empty_counts())
                        host_counts[bucket] += 1
                        host_counts["total"] += 1

                        if bucket in ("critical", "high"):
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

        # Every host that ever shows up should get a details entry, even if it had no
        # severity-bucketed findings at all (by_host only tracks hosts with findings).
        for host_label in host_details:
            by_host.setdefault(host_label, _empty_counts())

        host_details_out = {
            host: {
                "ports": sorted(details["ports"]),
                "operating_systems": sorted(details["operating_systems"]),
                "applications": sorted(details["applications"]),
            }
            for host, details in host_details.items()
        }

        return {
            "global": global_counts,
            "by_host": by_host,
            "host_details": host_details_out,
            "top_vulnerabilities": top_candidates[:15],
            "tasks": task_summaries,
        }

    def start_task(self, task_id: str) -> None:
        """Start (or resume) a scan task."""
        try:
            with self._connect() as gmp:
                gmp.authenticate(self._username, self._password)
                gmp.start_task(task_id)
        except GvmError as err:
            raise GreenboneError(str(err)) from err
        except OSError as err:
            raise GreenboneError(f"Error connecting to Greenbone GMP relay: {err}") from err
