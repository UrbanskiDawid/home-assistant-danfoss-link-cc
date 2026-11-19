"""System state (AtHome, Asleep, Away, ...) and the number of unresolved alarms."""

from __future__ import annotations

from homeassistant.components.sensor import SensorEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from . import Coordinator


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback) -> None:
    async_add_entities([SystemState(entry.runtime_data), Alarms(entry.runtime_data)])


class _Base(CoordinatorEntity[Coordinator], SensorEntity):
    _attr_has_entity_name = True

    def __init__(self, coordinator: Coordinator, key: str) -> None:
        super().__init__(coordinator)
        self._attr_unique_id = f"{coordinator.config_entry.unique_id}_{key}"
        self._attr_translation_key = key
        self._attr_device_info = coordinator.device


class SystemState(_Base):
    def __init__(self, coordinator: Coordinator) -> None:
        super().__init__(coordinator, "state")

    @property
    def native_value(self) -> str | None:
        return self.coordinator.data["systemStatus"].get("currentState")


class Alarms(_Base):
    _attr_icon = "mdi:alert"
    _unrecorded_attributes = frozenset({"alarms"})

    def __init__(self, coordinator: Coordinator) -> None:
        super().__init__(coordinator, "alarms")

    @property
    def native_value(self) -> int:
        return len(self.coordinator.data["allUnresolvedAlarms"])

    @property
    def extra_state_attributes(self) -> dict:
        return {"alarms": self.coordinator.data["allUnresolvedAlarms"]}
