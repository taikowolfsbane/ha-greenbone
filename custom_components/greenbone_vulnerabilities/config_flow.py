"""Config flow for the Greenbone Vulnerabilities integration."""
from __future__ import annotations

import logging
from typing import Any

import voluptuous as vol

from homeassistant import config_entries
from homeassistant.const import CONF_HOST, CONF_PASSWORD, CONF_USERNAME
from homeassistant.core import callback

from .api import GreenboneClient, GreenboneError
from .const import (
    CONF_PORT,
    CONF_SCAN_INTERVAL_MINUTES,
    DEFAULT_PORT,
    DEFAULT_SCAN_INTERVAL_MINUTES,
    DOMAIN,
)

_LOGGER = logging.getLogger(__name__)

STEP_USER_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_HOST): str,
        vol.Required(CONF_PORT, default=DEFAULT_PORT): int,
        vol.Required(CONF_USERNAME, default="admin"): str,
        vol.Required(CONF_PASSWORD): str,
    }
)


async def _async_validate_connection(hass, data: dict[str, Any]) -> None:
    """Raise GreenboneError if we can't actually reach and query Greenbone."""
    client = GreenboneClient(
        hostname=data[CONF_HOST],
        port=data[CONF_PORT],
        username=data[CONF_USERNAME],
        password=data[CONF_PASSWORD],
    )
    await hass.async_add_executor_job(client.get_vulnerability_summary)


class GreenboneVulnerabilitiesConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for Greenbone Vulnerabilities."""

    VERSION = 1

    async def async_step_user(self, user_input: dict[str, Any] | None = None):
        errors: dict[str, str] = {}
        if user_input is not None:
            try:
                await _async_validate_connection(self.hass, user_input)
            except GreenboneError:
                errors["base"] = "cannot_connect"
            except Exception:  # noqa: BLE001 - surface anything unexpected as a generic error
                _LOGGER.exception("Unexpected error validating Greenbone connection")
                errors["base"] = "unknown"
            else:
                await self.async_set_unique_id(f"{user_input[CONF_HOST]}:{user_input[CONF_PORT]}")
                self._abort_if_unique_id_configured()
                return self.async_create_entry(
                    title=f"Greenbone ({user_input[CONF_HOST]})", data=user_input
                )

        return self.async_show_form(step_id="user", data_schema=STEP_USER_SCHEMA, errors=errors)

    @staticmethod
    @callback
    def async_get_options_flow(config_entry: config_entries.ConfigEntry):
        return GreenboneVulnerabilitiesOptionsFlow(config_entry)


class GreenboneVulnerabilitiesOptionsFlow(config_entries.OptionsFlow):
    """Lets the user change the scan interval after setup."""

    def __init__(self, config_entry: config_entries.ConfigEntry) -> None:
        self._config_entry = config_entry

    async def async_step_init(self, user_input: dict[str, Any] | None = None):
        if user_input is not None:
            return self.async_create_entry(title="", data=user_input)

        options = self._config_entry.options
        schema = vol.Schema(
            {
                vol.Optional(
                    CONF_SCAN_INTERVAL_MINUTES,
                    default=options.get(CONF_SCAN_INTERVAL_MINUTES, DEFAULT_SCAN_INTERVAL_MINUTES),
                ): vol.All(vol.Coerce(int), vol.Range(min=1)),
            }
        )
        return self.async_show_form(step_id="init", data_schema=schema)
