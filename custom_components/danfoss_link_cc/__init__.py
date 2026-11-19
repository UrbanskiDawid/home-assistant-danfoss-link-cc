"""Danfoss Link CC: rooms, alarms and system state of the touch panel via the Danfoss cloud relay."""

from __future__ import annotations

import logging
from datetime import timedelta

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from . import link
from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)
PLATFORMS = [Platform.BINARY_SENSOR, Platform.CLIMATE, Platform.SENSOR]


class Coordinator(DataUpdateCoordinator[dict]):
    """Polls GET /api/world (rooms, system state and alarms in one call)."""

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry) -> None:
        super().__init__(hass, _LOGGER, config_entry=entry, name=DOMAIN, update_interval=timedelta(minutes=1))
        self.device = DeviceInfo(identifiers={(DOMAIN, entry.unique_id)}, name="Danfoss Link CC", manufacturer="Danfoss")

    async def request(self, method: str, uri: str, body: dict | None = None):
        try:
            return await self.hass.async_add_executor_job(link.request, self.config_entry.data, method, uri, body)
        except link.LinkError as err:
            raise UpdateFailed(str(err)) from err

    async def _async_update_data(self) -> dict:
        return await self.request("GET", "/api/world")


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    coordinator = Coordinator(hass, entry)
    await coordinator.async_config_entry_first_refresh()
    entry.runtime_data = coordinator
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    return await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
