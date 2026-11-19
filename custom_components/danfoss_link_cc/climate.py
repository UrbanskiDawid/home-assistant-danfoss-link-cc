"""One climate entity per room."""

from __future__ import annotations

from typing import Any

from homeassistant.components.climate import ClimateEntity, ClimateEntityFeature, HVACAction, HVACMode
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import ATTR_TEMPERATURE, UnitOfTemperature
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from . import Coordinator

# Panel regulation type <-> HA mode: the schedule runs the room (auto) or a fixed manual setpoint (heat).
MODES = {"Schedule": HVACMode.AUTO, "Manual": HVACMode.HEAT}


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback) -> None:
    coordinator: Coordinator = entry.runtime_data
    async_add_entities(Room(coordinator, room["id"]) for room in coordinator.data["allRooms"])


class Room(CoordinatorEntity[Coordinator], ClimateEntity):
    _attr_has_entity_name = True
    _attr_hvac_modes = list(MODES.values())
    _attr_supported_features = ClimateEntityFeature.TARGET_TEMPERATURE
    _attr_target_temperature_step = 0.5
    _attr_temperature_unit = UnitOfTemperature.CELSIUS

    def __init__(self, coordinator: Coordinator, room_id: int) -> None:
        super().__init__(coordinator)
        self._id = room_id
        self._attr_unique_id = f"{coordinator.config_entry.unique_id}_room_{room_id}"
        self._attr_device_info = coordinator.device
        self._attr_name = self._room["name"]

    @property
    def _room(self) -> dict:
        return next(r for r in self.coordinator.data["allRooms"] if r["id"] == self._id)

    @property
    def current_temperature(self) -> float | None:
        return self._room.get("ambientTemperature")

    @property
    def target_temperature(self) -> float | None:
        return (self._room.get("setpoint") or {}).get("temperature")

    @property
    def min_temp(self) -> float:
        return self._room["minSetpoint"]

    @property
    def max_temp(self) -> float:
        return self._room["maxSetpoint"]

    @property
    def hvac_mode(self) -> HVACMode:
        return MODES.get(self._room["regulation"]["type"], HVACMode.AUTO)

    @property
    def hvac_action(self) -> HVACAction:
        return HVACAction.HEATING if self._room.get("regulationState") == "Heating" else HVACAction.IDLE

    async def _patch(self, body: dict) -> None:
        await self.coordinator.request("PATCH", f"/api/rooms/{self._id}", {"id": self._id, **body})
        await self.coordinator.async_request_refresh()

    async def async_set_temperature(self, **kwargs: Any) -> None:
        await self._patch({"setpoint": {"temperature": kwargs[ATTR_TEMPERATURE]}})

    async def async_set_hvac_mode(self, hvac_mode: HVACMode) -> None:
        await self._patch({"regulation": {"type": "Manual" if hvac_mode == HVACMode.HEAT else "Schedule"}})
