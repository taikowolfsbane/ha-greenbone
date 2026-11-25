"""Button platform for the Greenbone Vulnerabilities integration."""
from __future__ import annotations

from homeassistant.components.button import ButtonEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN
from .coordinator import GreenboneDataUpdateCoordinator


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
    coordinator: GreenboneDataUpdateCoordinator = hass.data[DOMAIN][entry.entry_id]
    async_add_entities([GreenboneRefreshButton(coordinator, entry)])


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
