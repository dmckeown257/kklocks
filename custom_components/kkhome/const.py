"""Constants for the KK Home integration."""

from __future__ import annotations

DOMAIN = "kkhome"
PLATFORMS = ["lock", "sensor"]

CONF_ACCESS_TOKEN = "access_token"
CONF_BASE_URL = "base_url"
CONF_DEVICE_DETAIL_PATH = "device_detail_path"
CONF_DEVICES_PATH = "devices_path"
CONF_LOCK_PATH = "lock_path"
CONF_LOGIN_PATH = "login_path"
CONF_PASSWORD = "password"
CONF_POLL_INTERVAL = "poll_interval"
CONF_STATUS_PATH = "status_path"
CONF_TENANT_ID = "tenant_id"
CONF_UNLOCK_PATH = "unlock_path"
CONF_USERNAME = "username"

DEFAULT_BASE_URL = "https://api.kksecurityhome.com"
DEFAULT_TENANT_ID = "kawden"
DEFAULT_POLL_INTERVAL = 30

# Confirmed from captured KK Home mobile traffic and Android decompile on
# March 31, 2026.
DEFAULT_LOGIN_PATH = "/v3/user/login/get-user-by-mail"
DEFAULT_DEVICES_PATH = "/v3/user/device/list"
DEFAULT_DEVICE_DETAIL_PATH = "/v4/device/query-device-attr"
DEFAULT_LOCK_PATH = "/v3/device/close-device"
DEFAULT_STATUS_PATH = "/v3/device/get-open-status"
DEFAULT_UNLOCK_PATH = "/v3/device/open-device"

ATTR_RAW_STATE = "raw_state"
