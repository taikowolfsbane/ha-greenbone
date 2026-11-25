"""Button platform for the Greenbone Vulnerabilities integration."""
from __future__ import annotations

import logging
from typing import Any

from homeassistant.components.button import ButtonEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .api import GreenboneError
from .const import DOMAIN
from .coordinator import GreenboneDataUpdateCoordinator

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
    coordinator: GreenboneDataUpdateCoordinator = hass.data[DOMAIN][entry.entry_id]
    async_add_entities([GreenboneRefreshButton(coordinator, entry)])

    known_tasks: set[str] = set()

    @callback
    def _add_new_scan_buttons() -> None:
        current_task_ids = {task["id"] for task in coordinator.data["tasks"]}
        new_task_ids = current_task_ids - known_tasks
        if not new_task_ids:
            return
        known_tasks.update(new_task_ids)
        async_add_entities(
            GreenboneStartScanButton(coordinator, entry, task_id) for task_id in new_task_ids
        )

    entry.async_on_unload(coordinator.async_add_listener(_add_new_scan_buttons))
    _add_new_scan_buttons()


class GreenboneRefreshButton(ButtonEntity):
    """Button that forces an immediate refresh of all Greenbone sensors, bypassing scan_interval."""

    _attr_has_entity_name = True
    _attr_name = "Refresh Now"
    _attr_icon = "mdi:refresh"

    def __init__(self, coordinator: GreenboneDataUpdateCoordinator, entry: ConfigEntry) -> None:
        self._coordinator = coordinator
        self._attr_unique_id = f"{entry.entry_id}_refresh_button"
        self._attr_device_info = {
            "identifiers": {(DOMAIN, entry.entry_id)},
            "name": "Greenbone",
            "manufacturer": "Greenbone",
            "entry_type": "service",
        }

    async def async_press(self) -> None:
        await self._coordinator.async_request_refresh()


class GreenboneStartScanButton(CoordinatorEntity[GreenboneDataUpdateCoordinator], ButtonEntity):
    """Button that starts (or resumes) one GVM scan task.

    Pressing this while the task is already running will surface GVM's own error
    (e.g. "already active") as a Home Assistant error notification, rather than
    silently failing.
    """

    _attr_has_entity_name = True
    _attr_icon = "mdi:play-circle"

    def __init__(
        self, coordinator: GreenboneDataUpdateCoordinator, entry: ConfigEntry, task_id: str
    ) -> None:
        super().__init__(coordinator)
        self._task_id = task_id
        self._attr_unique_id = f"{entry.entry_id}_task_{task_id}_start"
        self._attr_device_info = {
            "identifiers": {(DOMAIN, entry.entry_id)},
            "name": "Greenbone",
            "manufacturer": "Greenbone",
            "entry_type": "service",
        }

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
        return f"{task_name} Start Scan"

    async def async_press(self) -> None:
        try:
            await self.hass.async_add_executor_job(self.coordinator.client.start_task, self._task_id)
        except GreenboneError as err:
            raise HomeAssistantError(f"Could not start scan: {err}") from err
        await self.coordinator.async_request_refresh()
