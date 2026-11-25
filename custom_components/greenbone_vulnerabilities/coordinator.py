"""DataUpdateCoordinator for the Greenbone Vulnerabilities integration."""
from __future__ import annotations

import logging
from datetime import timedelta

from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .api import GreenboneClient, GreenboneError

_LOGGER = logging.getLogger(__name__)


class GreenboneDataUpdateCoordinator(DataUpdateCoordinator[dict]):
    """Coordinates periodic polling of Greenbone for all entities.

    GreenboneClient is a blocking (sync) GMP client, so every call goes through
    the executor rather than being awaited directly.
    """

    def __init__(
        self, hass: HomeAssistant, client: GreenboneClient, scan_interval_minutes: int
    ) -> None:
        super().__init__(
            hass,
            _LOGGER,
            name="Greenbone Vulnerabilities",
            update_interval=timedelta(minutes=scan_interval_minutes),
        )
        self._client = client

    @property
    def client(self) -> GreenboneClient:
        """Expose the underlying client so other platforms (e.g. buttons) can act on it."""
        return self._client

    async def _async_update_data(self) -> dict:
        try:
            return await self.hass.async_add_executor_job(
                self._client.get_vulnerability_summary
            )
        except GreenboneError as err:
            raise UpdateFailed(f"Error communicating with Greenbone: {err}") from err
