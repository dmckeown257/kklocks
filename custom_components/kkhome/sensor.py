"""Sensor platform for KK Home."""

from __future__ import annotations

from dataclasses import dataclass

from homeassistant.components.sensor import SensorEntity, SensorEntityDescription
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import PERCENTAGE
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN
from .entity import KKHomeEntity


@dataclass(frozen=True, kw_only=True)
class KKHomeSensorDescription(SensorEntityDescription):
    """Describe a KK Home sensor."""

    value_key: str


SENSORS = [
    KKHomeSensorDescription(
        key="battery",
        translation_key="battery",
        native_unit_of_measurement=PERCENTAGE,
        value_key="battery",
    )
]


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up KK Home sensors."""
    coordinator = hass.data[DOMAIN][entry.entry_id]["coordinator"]
    entities: list[KKHomeBatterySensor] = []
    for device_id, lock in coordinator.data.locks.items():
        if lock.battery_level is None:
            continue
        entities.append(KKHomeBatterySensor(coordinator, device_id, SENSORS[0]))
    async_add_entities(entities)


class KKHomeBatterySensor(KKHomeEntity, SensorEntity):
    """Battery sensor for a KK Home lock."""

    entity_description: KKHomeSensorDescription
    _attr_name = None
    _entity_suffix = "battery"

    def __init__(self, coordinator, device_id: str, description: KKHomeSensorDescription) -> None:
        """Initialize battery sensor."""
        super().__init__(coordinator, device_id)
        self.entity_description = description

    @property
    def native_value(self) -> int | None:
        """Return sensor state."""
        return self.device.battery_level
