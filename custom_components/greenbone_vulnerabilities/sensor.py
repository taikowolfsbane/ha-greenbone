"""Sensor platform for the Greenbone Vulnerabilities integration."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from homeassistant.components.sensor import SensorEntity, SensorEntityDescription, SensorStateClass
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN, SEVERITIES
from .coordinator import GreenboneDataUpdateCoordinator

SEVERITY_ICONS = {
    "critical": "mdi:shield-alert",
    "high": "mdi:shield-alert-outline",
    "medium": "mdi:shield-half-full",
    "low": "mdi:shield-outline",
}


@dataclass(frozen=True, kw_only=True)
class GreenboneSensorDescription(SensorEntityDescription):
    """Describes a global (not per-host) Greenbone sensor."""

    value_fn: Callable[[dict[str, Any]], Any]


GLOBAL_SENSORS: tuple[GreenboneSensorDescription, ...] = (
    GreenboneSensorDescription(
        key="vulnerabilities_total",
        name="Vulnerabilities Total",
        icon="mdi:shield-bug",
        native_unit_of_measurement="vulnerabilities",
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda data: data["global"]["total"],
    ),
    GreenboneSensorDescription(
        key="vulnerabilities_critical",
        name="Vulnerabilities Critical",
        icon="mdi:shield-alert",
        native_unit_of_measurement="vulnerabilities",
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda data: data["global"]["critical"],
    ),
    GreenboneSensorDescription(
        key="vulnerabilities_high",
        name="Vulnerabilities High",
        icon="mdi:shield-alert-outline",
        native_unit_of_measurement="vulnerabilities",
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda data: data["global"]["high"],
    ),
    GreenboneSensorDescription(
        key="vulnerabilities_medium",
        name="Vulnerabilities Medium",
        icon="mdi:shield-half-full",
        native_unit_of_measurement="vulnerabilities",
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda data: data["global"]["medium"],
    ),
    GreenboneSensorDescription(
        key="vulnerabilities_low",
        name="Vulnerabilities Low",
        icon="mdi:shield-outline",
        native_unit_of_measurement="vulnerabilities",
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda data: data["global"]["low"],
    ),
)


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
    coordinator: GreenboneDataUpdateCoordinator = hass.data[DOMAIN][entry.entry_id]

    async_add_entities(
        GreenboneGlobalSensor(coordinator, entry, description) for description in GLOBAL_SENSORS
    )
    async_add_entities([GreenboneTopVulnerabilitiesSensor(coordinator, entry)])

    known_hosts: set[str] = set()

    @callback
    def _add_new_host_sensors() -> None:
        current_hosts = set(coordinator.data["by_host"])
        new_hosts = current_hosts - known_hosts
        if not new_hosts:
            return
        known_hosts.update(new_hosts)
        new_entities: list[SensorEntity] = []
        for host_ip in new_hosts:
            new_entities.append(GreenboneHostVulnerabilitySensor(coordinator, entry, host_ip))
            new_entities.extend(
                GreenboneHostSeveritySensor(coordinator, entry, host_ip, severity)
                for severity in SEVERITIES
            )
        async_add_entities(new_entities)

    entry.async_on_unload(coordinator.async_add_listener(_add_new_host_sensors))
    _add_new_host_sensors()

    # Tasks are a small, user-managed set (you create them deliberately in GVM), unlike
    # scanned hosts, so dynamically adding one sensor per task doesn't have the same
    # "dozens of ever-changing entities" problem per-host sensors would.
    known_tasks: set[str] = set()

    @callback
    def _add_new_task_sensors() -> None:
        current_task_ids = {task["id"] for task in coordinator.data["tasks"]}
        new_task_ids = current_task_ids - known_tasks
        if not new_task_ids:
            return
        known_tasks.update(new_task_ids)
        async_add_entities(
            GreenboneTaskProgressSensor(coordinator, entry, task_id) for task_id in new_task_ids
        )

    entry.async_on_unload(coordinator.async_add_listener(_add_new_task_sensors))
    _add_new_task_sensors()


def _hub_device_info(entry: ConfigEntry) -> dict[str, Any]:
    return {
        "identifiers": {(DOMAIN, entry.entry_id)},
        "name": "Greenbone",
        "manufacturer": "Greenbone",
        "entry_type": "service",
    }


# Deliberately NOT a separate device per host: a home-LAN scan can turn up dozens of
# hosts, and DHCP churn means that set keeps changing. A device-per-host design makes
# HA prompt you to name/assign an area for every single one (see HA's "new devices"
# dialog) - an ever-growing chore for a list this volatile. Per-host sensors are still
# created dynamically and individually addressable; they just all live on the one
# Greenbone hub device instead of getting their own.


class GreenboneGlobalSensor(CoordinatorEntity[GreenboneDataUpdateCoordinator], SensorEntity):
    """A global (not per-host) Greenbone metric, driven by a GreenboneSensorDescription."""

    entity_description: GreenboneSensorDescription
    _attr_has_entity_name = True

    def __init__(
        self,
        coordinator: GreenboneDataUpdateCoordinator,
        entry: ConfigEntry,
        description: GreenboneSensorDescription,
    ) -> None:
        super().__init__(coordinator)
        self.entity_description = description
        self._attr_unique_id = f"{entry.entry_id}_{description.key}"
        self._attr_device_info = _hub_device_info(entry)

    @property
    def native_value(self) -> Any:
        return self.entity_description.value_fn(self.coordinator.data)


class GreenboneTopVulnerabilitiesSensor(
    CoordinatorEntity[GreenboneDataUpdateCoordinator], SensorEntity
):
    """The highest-severity critical/high vulnerabilities across all scanned hosts.

    The state is just a count; the actual findings (name, CVE, CVSS score, host) live
    in `extra_state_attributes` since there's no single native HA entity type for a
    list of structured records.
    """

    _attr_has_entity_name = True
    _attr_name = "Top Critical Vulnerabilities"
    _attr_icon = "mdi:alert-decagram"
    _attr_native_unit_of_measurement = "vulnerabilities"
    _attr_state_class = SensorStateClass.MEASUREMENT

    def __init__(self, coordinator: GreenboneDataUpdateCoordinator, entry: ConfigEntry) -> None:
        super().__init__(coordinator)
        self._attr_unique_id = f"{entry.entry_id}_top_vulnerabilities"
        self._attr_device_info = _hub_device_info(entry)

    @property
    def native_value(self) -> int:
        return len(self.coordinator.data["top_vulnerabilities"])

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        return {"vulnerabilities": self.coordinator.data["top_vulnerabilities"]}


class GreenboneHostVulnerabilitySensor(
    CoordinatorEntity[GreenboneDataUpdateCoordinator], SensorEntity
):
    """Total vulnerability count for a single scanned host, with a severity breakdown.

    Created dynamically as new hosts show up in Greenbone's results - no manual
    per-host configuration needed. Identified internally by IP (stable across scans),
    but displayed by the scan's resolved hostname when available - so a host doesn't
    get a brand-new entity the moment reverse lookup starts (or stops) resolving it.
    """

    _attr_has_entity_name = True
    _attr_icon = "mdi:monitor-shimmer"
    _attr_native_unit_of_measurement = "vulnerabilities"
    _attr_state_class = SensorStateClass.MEASUREMENT

    def __init__(
        self, coordinator: GreenboneDataUpdateCoordinator, entry: ConfigEntry, host_ip: str
    ) -> None:
        super().__init__(coordinator)
        self._host_ip = host_ip
        self._attr_unique_id = f"{entry.entry_id}_host_{host_ip}"
        self._attr_device_info = _hub_device_info(entry)

    @property
    def _host_label(self) -> str:
        return self.coordinator.data["host_details"].get(self._host_ip, {}).get(
            "label", self._host_ip
        )

    @property
    def name(self) -> str:
        # The host label has to be in the entity's own name (not just the device's),
        # since every per-host sensor now shares the one hub device.
        return f"{self._host_label} Total"

    @property
    def _host_data(self) -> dict[str, int]:
        return self.coordinator.data["by_host"].get(self._host_ip, {})

    @property
    def available(self) -> bool:
        return super().available and self._host_ip in self.coordinator.data["by_host"]

    @property
    def native_value(self) -> int:
        return self._host_data.get("total", 0)

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        data = self._host_data
        details = self.coordinator.data["host_details"].get(self._host_ip, {})
        return {
            "ip": self._host_ip,
            "critical": data.get("critical", 0),
            "high": data.get("high", 0),
            "medium": data.get("medium", 0),
            "low": data.get("low", 0),
            "open_ports": details.get("ports", []),
            "operating_systems": details.get("operating_systems", []),
            "applications": details.get("applications", []),
        }


class GreenboneHostSeveritySensor(
    CoordinatorEntity[GreenboneDataUpdateCoordinator], SensorEntity
):
    """Vulnerability count for one severity level, for a single scanned host.

    Lives alongside that host's Total sensor (both on the shared hub device), so
    dashboard tooling (e.g. auto-entities) can address a single host's full severity
    breakdown as real entities rather than attributes.
    """

    _attr_has_entity_name = True
    _attr_native_unit_of_measurement = "vulnerabilities"
    _attr_state_class = SensorStateClass.MEASUREMENT

    def __init__(
        self,
        coordinator: GreenboneDataUpdateCoordinator,
        entry: ConfigEntry,
        host_ip: str,
        severity: str,
    ) -> None:
        super().__init__(coordinator)
        self._host_ip = host_ip
        self._severity = severity
        self._attr_icon = SEVERITY_ICONS[severity]
        self._attr_unique_id = f"{entry.entry_id}_host_{host_ip}_{severity}"
        self._attr_device_info = _hub_device_info(entry)

    @property
    def name(self) -> str:
        label = self.coordinator.data["host_details"].get(self._host_ip, {}).get(
            "label", self._host_ip
        )
        return f"{label} {self._severity.capitalize()}"

    @property
    def _host_data(self) -> dict[str, int]:
        return self.coordinator.data["by_host"].get(self._host_ip, {})

    @property
    def available(self) -> bool:
        return super().available and self._host_ip in self.coordinator.data["by_host"]

    @property
    def native_value(self) -> int:
        return self._host_data.get(self._severity, 0)


class GreenboneTaskProgressSensor(CoordinatorEntity[GreenboneDataUpdateCoordinator], SensorEntity):
    """Current scan progress (0-100) for a single GVM task, plus its status as an attribute.

    This is still just polling-based, at whatever the scan interval (or a manual
    Refresh Now press) provides - GMP has no push/event stream for this - but a short
    scan interval or a few manual refreshes gives a reasonably live view while a scan
    is actively running.
    """

    _attr_has_entity_name = True
    _attr_icon = "mdi:progress-helper"
    _attr_native_unit_of_measurement = "%"
    _attr_state_class = SensorStateClass.MEASUREMENT

    def __init__(
        self, coordinator: GreenboneDataUpdateCoordinator, entry: ConfigEntry, task_id: str
    ) -> None:
        super().__init__(coordinator)
        self._task_id = task_id
        self._attr_unique_id = f"{entry.entry_id}_task_{task_id}_progress"
        self._attr_device_info = _hub_device_info(entry)

    @property
    def _task(self) -> dict[str, Any] | None:
        return next(
            (t for t in self.coordinator.data["tasks"] if t["id"] == self._task_id), None
        )

    @property
    def available(self) -> bool:
        return super().available and self._task is not None

    @property
    def name(self) -> str | None:
        task = self._task
        task_name = task["name"] if task else self._task_id
        return f"{task_name} Scan Progress"

    @property
    def native_value(self) -> int | None:
        task = self._task
        return task["progress"] if task else None

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        task = self._task
        return {"status": task["status"] if task else None}
