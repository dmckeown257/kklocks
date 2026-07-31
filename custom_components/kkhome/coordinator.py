"""Coordinator for KK Home."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
import logging
import time

from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .api import KKHomeApiClient, KKHomeApiError, KKHomeAuthError, KKHomeLockDevice
from .const import CONF_POLL_INTERVAL, DOMAIN

_LOGGER = logging.getLogger(__name__)

MISSING_DEVICE_GRACE_SECONDS = 300


@dataclass(slots=True)
class KKHomeData:
    """Coordinator payload."""

    locks: dict[str, KKHomeLockDevice]


class KKHomeCoordinator(DataUpdateCoordinator[KKHomeData]):
    """Poll KK Home devices."""

    def __init__(self, hass: HomeAssistant, api: KKHomeApiClient, config: dict) -> None:
        """Initialize coordinator."""
        super().__init__(
            hass,
            logger=_LOGGER,
            name=DOMAIN,
            update_interval=timedelta(seconds=config[CONF_POLL_INTERVAL]),
        )
        self.api = api
        self._missing_since: dict[str, float] = {}

    async def _async_update_data(self) -> KKHomeData:
        try:
            locks = await self.api.async_get_locks()
        except KKHomeAuthError as err:
            raise UpdateFailed(f"Authentication failed, will retry: {err}") from err
        except KKHomeApiError as err:
            raise UpdateFailed(f"Error communicating with KK Home: {err}") from err

        data = {lock.device_id: lock for lock in locks}
        self._carry_over_missing_devices(data)
        return KKHomeData(locks=data)

    def _carry_over_missing_devices(self, data: dict[str, KKHomeLockDevice]) -> None:
        """Keep last-known devices briefly when a poll omits them.

        The cloud occasionally returns a well-formed response that is missing
        known devices. Dropping them immediately would flap or break their
        entities, so reuse the previous state for a grace period and only mark
        them unavailable if they stay gone.
        """
        previous = self.data.locks if self.data else {}
        now = time.monotonic()

        for device_id in [key for key in self._missing_since if key in data]:
            self._missing_since.pop(device_id)
            _LOGGER.info("KK Home device %s reappeared in the device list", device_id)

        for device_id, lock in previous.items():
            if device_id in data:
                continue
            first_missing = self._missing_since.get(device_id)
            if first_missing is None:
                first_missing = self._missing_since[device_id] = now
                _LOGGER.warning(
                    "KK Home device %s (%s) is missing from the device list; "
                    "keeping its last known state for up to %s seconds",
                    lock.name,
                    device_id,
                    MISSING_DEVICE_GRACE_SECONDS,
                )
            if now - first_missing <= MISSING_DEVICE_GRACE_SECONDS:
                data[device_id] = lock
            else:
                _LOGGER.warning(
                    "KK Home device %s (%s) has been missing for more than %s "
                    "seconds; marking it unavailable until it reappears",
                    lock.name,
                    device_id,
                    MISSING_DEVICE_GRACE_SECONDS,
                )
