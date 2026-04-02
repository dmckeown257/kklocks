"""Config flow for KK Home."""

from __future__ import annotations

import logging
from typing import Any

import voluptuous as vol

from homeassistant import config_entries
from homeassistant.core import callback
from homeassistant.data_entry_flow import FlowResult

from .api import KKHomeApiClient, KKHomeApiError, KKHomeAuthError
from .const import (
    CONF_ACCESS_TOKEN,
    CONF_BASE_URL,
    CONF_DEVICE_DETAIL_PATH,
    CONF_DEVICES_PATH,
    CONF_LOCK_PATH,
    CONF_LOGIN_PATH,
    CONF_NAME,
    CONF_PASSWORD,
    CONF_POLL_INTERVAL,
    CONF_STATUS_PATH,
    CONF_TENANT_ID,
    CONF_UNLOCK_PATH,
    CONF_USERNAME,
    DEFAULT_BASE_URL,
    DEFAULT_DEVICE_DETAIL_PATH,
    DEFAULT_DEVICES_PATH,
    DEFAULT_LOCK_PATH,
    DEFAULT_LOGIN_PATH,
    DEFAULT_POLL_INTERVAL,
    DEFAULT_STATUS_PATH,
    DEFAULT_TENANT_ID,
    DEFAULT_UNLOCK_PATH,
    DOMAIN,
)

_LOGGER = logging.getLogger(__name__)


class KKHomeConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for KK Home."""

    VERSION = 1

    async def async_step_user(self, user_input: dict[str, Any] | None = None) -> FlowResult:
        """Handle the initial step."""
        errors: dict[str, str] = {}
        if user_input is not None:
            entry_data = self._entry_data(user_input)
            try:
                await KKHomeApiClient(self.hass, entry_data).async_test_connection()
            except KKHomeAuthError:
                _LOGGER.exception("KK Home config flow auth failure")
                errors["base"] = "invalid_auth"
            except KKHomeApiError:
                _LOGGER.exception("KK Home config flow connection failure")
                errors["base"] = "cannot_connect"
            else:
                await self.async_set_unique_id(
                    f"{entry_data[CONF_BASE_URL]}::{entry_data[CONF_USERNAME] or 'token'}"
                )
                self._abort_if_unique_id_configured()
                return self.async_create_entry(
                    title=user_input[CONF_NAME].strip() or "KK Home",
                    data=entry_data,
                )

        return self.async_show_form(
            step_id="user",
            data_schema=self._user_schema(user_input),
            errors=errors,
        )

    @staticmethod
    @callback
    def async_get_options_flow(
        config_entry: config_entries.ConfigEntry,
    ) -> config_entries.OptionsFlow:
        """Return the options flow."""
        return KKHomeOptionsFlow(config_entry)

    def _user_schema(self, user_input: dict[str, Any] | None) -> vol.Schema:
        user_input = user_input or {}
        return vol.Schema(
            {
                vol.Required(CONF_NAME, default=user_input.get(CONF_NAME, "KK Home")): str,
                vol.Required(CONF_USERNAME, default=user_input.get(CONF_USERNAME, "")): str,
                vol.Required(CONF_PASSWORD, default=user_input.get(CONF_PASSWORD, "")): str,
            }
        )

    def _entry_data(self, user_input: dict[str, Any]) -> dict[str, Any]:
        """Merge user-facing config flow fields with protocol defaults."""
        return {
            CONF_NAME: user_input[CONF_NAME],
            CONF_USERNAME: user_input[CONF_USERNAME],
            CONF_PASSWORD: user_input[CONF_PASSWORD],
            CONF_ACCESS_TOKEN: user_input.get(CONF_ACCESS_TOKEN, ""),
            CONF_BASE_URL: user_input.get(CONF_BASE_URL, DEFAULT_BASE_URL),
            CONF_TENANT_ID: user_input.get(CONF_TENANT_ID, DEFAULT_TENANT_ID),
            CONF_LOGIN_PATH: user_input.get(CONF_LOGIN_PATH, DEFAULT_LOGIN_PATH),
            CONF_DEVICES_PATH: user_input.get(CONF_DEVICES_PATH, DEFAULT_DEVICES_PATH),
            CONF_DEVICE_DETAIL_PATH: user_input.get(
                CONF_DEVICE_DETAIL_PATH, DEFAULT_DEVICE_DETAIL_PATH
            ),
            CONF_LOCK_PATH: user_input.get(CONF_LOCK_PATH, DEFAULT_LOCK_PATH),
            CONF_STATUS_PATH: user_input.get(CONF_STATUS_PATH, DEFAULT_STATUS_PATH),
            CONF_UNLOCK_PATH: user_input.get(CONF_UNLOCK_PATH, DEFAULT_UNLOCK_PATH),
            CONF_POLL_INTERVAL: user_input.get(CONF_POLL_INTERVAL, DEFAULT_POLL_INTERVAL),
        }


class KKHomeOptionsFlow(config_entries.OptionsFlow):
    """KK Home options flow."""

    def __init__(self, config_entry: config_entries.ConfigEntry) -> None:
        """Initialize options flow."""
        self.config_entry = config_entry

    async def async_step_init(self, user_input: dict[str, Any] | None = None) -> FlowResult:
        """Manage options."""
        if user_input is not None:
            return self.async_create_entry(title="", data=user_input)

        current = {**self.config_entry.data, **self.config_entry.options}
        return self.async_show_form(
            step_id="init",
            data_schema=vol.Schema(
                {
                    vol.Optional(CONF_NAME, default=current.get(CONF_NAME, self.config_entry.title or "KK Home")): str,
                    vol.Optional(CONF_USERNAME, default=current.get(CONF_USERNAME, "")): str,
                    vol.Optional(CONF_PASSWORD, default=current.get(CONF_PASSWORD, "")): str,
                    vol.Optional(CONF_ACCESS_TOKEN, default=current.get(CONF_ACCESS_TOKEN, "")): str,
                    vol.Required(CONF_BASE_URL, default=current.get(CONF_BASE_URL, DEFAULT_BASE_URL)): str,
                    vol.Required(CONF_TENANT_ID, default=current.get(CONF_TENANT_ID, DEFAULT_TENANT_ID)): str,
                    vol.Required(CONF_LOGIN_PATH, default=current.get(CONF_LOGIN_PATH, DEFAULT_LOGIN_PATH)): str,
                    vol.Required(CONF_DEVICES_PATH, default=current.get(CONF_DEVICES_PATH, DEFAULT_DEVICES_PATH)): str,
                    vol.Required(
                        CONF_DEVICE_DETAIL_PATH,
                        default=current.get(CONF_DEVICE_DETAIL_PATH, DEFAULT_DEVICE_DETAIL_PATH),
                    ): str,
                    vol.Required(CONF_LOCK_PATH, default=current.get(CONF_LOCK_PATH, DEFAULT_LOCK_PATH)): str,
                    vol.Required(CONF_STATUS_PATH, default=current.get(CONF_STATUS_PATH, DEFAULT_STATUS_PATH)): str,
                    vol.Required(CONF_UNLOCK_PATH, default=current.get(CONF_UNLOCK_PATH, DEFAULT_UNLOCK_PATH)): str,
                    vol.Required(
                        CONF_POLL_INTERVAL,
                        default=current.get(CONF_POLL_INTERVAL, DEFAULT_POLL_INTERVAL),
                    ): vol.All(vol.Coerce(int), vol.Range(min=5, max=3600)),
                }
            ),
        )
