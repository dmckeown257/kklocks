"""Lock platform for KK Home."""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from homeassistant.components.lock import LockEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .api import KKHomeApiError, KKHomeLockDevice
from .const import ATTR_RAW_STATE, DOMAIN
from .entity import KKHomeEntity


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up KK Home lock entities."""
    coordinator = hass.data[DOMAIN][entry.entry_id]["coordinator"]
    async_add_entities(
        KKHomeLockEntity(coordinator, device_id)
        for device_id in coordinator.data.locks
    )


class KKHomeLockEntity(KKHomeEntity, LockEntity):
    """Representation of a KK Home lock."""

    _attr_name = None
    _attr_translation_key = "lock"
    _entity_suffix = "lock"

    @property
    def is_locked(self) -> bool | None:
        """Return whether the lock is locked."""
        return self.device.is_locked

    @property
    def extra_state_attributes(self) -> dict[str, object]:
        """Return extra state."""
        return {
            ATTR_RAW_STATE: self.device.raw,
        }

    async def async_lock(self, **kwargs) -> None:
        """Lock the device."""
        await self._async_send_command(self.coordinator.api.async_lock, "lock")

    async def async_unlock(self, **kwargs) -> None:
        """Unlock the device."""
        await self._async_send_command(self.coordinator.api.async_unlock, "unlock")

    async def _async_send_command(
        self,
        command: Callable[[KKHomeLockDevice], Awaitable[None]],
        action: str,
    ) -> None:
        """Run a lock command and resync state even when it fails."""
        try:
            await command(self.device)
        except KKHomeApiError as err:
            raise HomeAssistantError(
                f"Failed to {action} {self.device.name}: {err}"
            ) from err
        finally:
            await self.coordinator.async_request_refresh()
