"""Shared entity helpers for KK Home."""

from __future__ import annotations

from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .coordinator import KKHomeCoordinator


class KKHomeEntity(CoordinatorEntity[KKHomeCoordinator]):
    """Base KK Home entity."""

    _attr_has_entity_name = True
    _entity_suffix = "entity"

    def __init__(self, coordinator: KKHomeCoordinator, device_id: str) -> None:
        """Initialize entity."""
        super().__init__(coordinator)
        self._device_id = device_id
        self._last_device = coordinator.data.locks[device_id]

    @property
    def device(self):
        """Return the current normalized device, falling back to the last seen one.

        Never raises: if the device is temporarily missing from coordinator
        data, the entity reports unavailable instead of crashing state writes.
        """
        device = self.coordinator.data.locks.get(self._device_id)
        if device is not None:
            self._last_device = device
        return self._last_device

    @property
    def available(self) -> bool:
        """Return True when polling works and the device is in the device list."""
        return super().available and self._device_id in self.coordinator.data.locks

    @property
    def device_info(self) -> DeviceInfo:
        """Return device metadata."""
        return DeviceInfo(
            identifiers={(DOMAIN, self._device_id)},
            manufacturer="Veise / Kaadas",
            model=self.device.raw.get("model") or self.device.raw.get("productName"),
            name=self.device.name,
        )

    @property
    def unique_id(self) -> str:
        """Return unique id."""
        return f"{self._device_id}_{self._entity_suffix}"
