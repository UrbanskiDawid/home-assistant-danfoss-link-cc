"""Battery problem: on while the panel reports a battery alarm (low, critical or dead) for any device."""

from __future__ import annotations

from homeassistant.components.binary_sensor import BinarySensorDeviceClass, BinarySensorEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from . import Coordinator


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback) -> None:
    async_add_entities([Battery(entry.runtime_data)])


def battery_alarms(data: dict) -> list[dict]:
    return [a for a in data["allUnresolvedAlarms"] if "BATTERY" in f"{a.get('titleTextId')}{a.get('descriptionTextId')}".upper()]


class Battery(CoordinatorEntity[Coordinator], BinarySensorEntity):
    _attr_has_entity_name = True
    _attr_device_class = BinarySensorDeviceClass.BATTERY
    _attr_translation_key = "battery"

    def __init__(self, coordinator: Coordinator) -> None:
        super().__init__(coordinator)
        self._attr_unique_id = f"{coordinator.config_entry.unique_id}_battery"
        self._attr_device_info = coordinator.device

    @property
    def is_on(self) -> bool:
        return bool(battery_alarms(self.coordinator.data))

    @property
    def extra_state_attributes(self) -> dict:
        return {"alarms": battery_alarms(self.coordinator.data)}
