"""Coordinator for KK Home."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
import logging

from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator

from .api import KKHomeApiClient, KKHomeLockDevice
from .const import CONF_POLL_INTERVAL, DOMAIN

_LOGGER = logging.getLogger(__name__)


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

    async def _async_update_data(self) -> KKHomeData:
        locks = await self.api.async_get_locks()
        return KKHomeData(locks={lock.device_id: lock for lock in locks})
