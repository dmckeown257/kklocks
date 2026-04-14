"""Async API client for KK Home."""

from __future__ import annotations

import asyncio
from base64 import b64decode, b64encode, urlsafe_b64decode
from dataclasses import dataclass
import json
import logging
import time
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from httpx import HTTPError

from homeassistant.helpers.httpx_client import get_async_client

from .ble import KKHomeBleController, KKHomeBleError, KKHomeBleUnavailableError
from .const import (
    CONF_ACCESS_TOKEN,
    CONF_BASE_URL,
    CONF_DEVICE_DETAIL_PATH,
    CONF_DEVICES_PATH,
    CONF_LOCK_PATH,
    CONF_LOGIN_PATH,
    CONF_PASSWORD,
    CONF_STATUS_PATH,
    CONF_TENANT_ID,
    CONF_UNLOCK_PATH,
    CONF_USERNAME,
)

_LOGGER = logging.getLogger(__name__)

_APP_PRIVATE_KEY = b64decode(
    "MIICXgIBAAKBgQC7M6FvIfDuzM3/QHcYKz5LcPcBm3829kb2UCH/GJThmMjiPqWQzN7Zzh666lSnWIB1mPa6xLQMRUsd/eNH68fWTYcrqnBXunVgkf56ppD9QZTf4y8IbEAetWiyGDp/4rVG3nsPKXYQTFgN59gzZ++qdtAehsGaC+dce96cNcvowQIDAQABAoGAXDGtS6IXmkPbH96LyKdjYpwbyfreyB66DAyi8ZMVn5UzOdlIiOucxP+yOrO1RUVc3o2a1ZiSY4is2fRzvrPsElMVQaX/wxCF73dqeJvZ8w2Y5izaR04DO5Q3GReVAupXjS0aGuWVzik+w+oTzGxKr9JE5ZFT/de94dULxRzMvAECQQDiSikSfTYv7fHhknfOVhgSJ4lKsgj48x5Bb3MONIJl1yRnYVm8NnXzg7Zga7CurhyLTqaZl6Wz0QiepIFy0sHxAkEA08euJNXW0sMT+Qc3XXXiHITBDjCBHRyjX0xsIf3pcRwBPhgG90jGGuyKOJYNZhu8U/mV9CGd9JBVrlq73RHD0QJBAKs1swejJslyvWyO9ghuiT3LHgwe0b0RrNWTbjjUL8i/03JIbK2DgxCgme8v63jukPgxpMlWvG9le6EUFED9BvECQQCVEgInlYoQcxZ0/TpghCDz+BI4XbYUetsYsp+O0b7nSlIplhoZKFWiEAw/RogJ7s4CwjVmUd9wjcRx5RZFx0JxAkEA0g9KjPzq+duwEnqADu6ls0fzTD8rpkYzukxlNSAFdHMVLnXoRlbmAqS3VcnNkcDJOkYTWXLxPuMGbf4YT0f3BA=="
)
_SERVICE_PUBLIC_KEY = b64decode(
    "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDAhvfVLGrJ/M3xpUnT1xlN30E1UESxhAmGmFyTx3p3vpxF4zMYpUjwHckCvg/zvZwhNTgsm3CNT7LAdE8lCl2YK4BoUZ6IYbbXSOa02/brASX4kjpOPbTcaDfYud2CFWQba95d5dlf3Jf9Z3eTPwNK7YQ0LDDWMOQ6LxoGqcLciQIDAQAB"
)
_ENCRYPT_DATA_HEADER = "encrypt_data"
_AUTH_REFRESH_SKEW_SECONDS = 300
_APP_VERSION = "3.3.1"
_PHONE_NAME = "iPhone17,1"
_USER_AGENT = "KKHome/3.3.1 (iPhone; iOS 26.3.1; Scale/3.00)"
_COMMAND_STATE_GRACE_SECONDS = 90


class KKHomeApiError(Exception):
    """Raised when the KK Home API returns an error."""


class KKHomeAuthError(KKHomeApiError):
    """Raised when authentication fails."""


@dataclass(slots=True)
class KKHomeLockDevice:
    """Normalized lock device model."""

    device_id: str
    name: str
    is_locked: bool | None
    battery_level: int | None
    raw: dict[str, Any]


class KKHomeApiClient:
    """Cloud client for KK Home."""

    def __init__(self, hass, config: dict[str, Any]) -> None:
        """Initialize the client."""
        self._hass = hass
        self._client = get_async_client(hass)
        self._config = config
        self._token: str | None = config.get(CONF_ACCESS_TOKEN)
        self._token_expires_at = self._decode_token_expiration(self._token)
        self._private_key = serialization.load_der_private_key(
            _APP_PRIVATE_KEY,
            password=None,
        )
        self._public_key = serialization.load_der_public_key(_SERVICE_PUBLIC_KEY)
        self._ble = KKHomeBleController(hass)
        self._auth_lock = asyncio.Lock()
        self._command_state_overrides: dict[str, tuple[bool, float]] = {}

    @property
    def _headers(self) -> dict[str, str]:
        headers = {
            "Accept": "*/*",
            "k-language": "en_US",
            "k-signv": "1.0.0",
            "k-tenant": str(self._config[CONF_TENANT_ID]),
            "k-version": _APP_VERSION,
            "phoneName": _PHONE_NAME,
            "User-Agent": _USER_AGENT,
        }
        if self._token:
            headers["token"] = self._token
        return headers

    async def async_authenticate(self) -> None:
        """Authenticate if a static token was not configured."""
        async with self._auth_lock:
            if self._token and not self._token_needs_refresh():
                return

            username = self._config.get(CONF_USERNAME)
            password = self._config.get(CONF_PASSWORD)
            if not username or not password:
                if self._token:
                    return
                raise KKHomeAuthError(
                    "Set an access token or provide a username and password."
                )

            payload = {"mail": username, "password": password}
            try:
                data = await self._request(
                    "post",
                    self._config[CONF_LOGIN_PATH],
                    json_body=self._encrypt_payload(payload),
                    headers={_ENCRYPT_DATA_HEADER: _ENCRYPT_DATA_HEADER},
                    allow_unauthenticated=True,
                )
            except KKHomeAuthError:
                raise
            except KKHomeApiError as err:
                raise KKHomeAuthError(str(err)) from err
            token = self._find_token(data)
            if not token:
                raise KKHomeAuthError(
                    "Login succeeded but no token was found in the response."
                )
            self._set_token(token)

    async def async_test_connection(self) -> None:
        """Test authentication and device listing."""
        await self.async_authenticate()
        await self.async_get_locks()

    async def async_get_locks(self) -> list[KKHomeLockDevice]:
        """Fetch and normalize lock devices."""
        await self.async_authenticate()
        payload = await self._request("post", self._config[CONF_DEVICES_PATH])
        devices = self._extract_devices(payload)
        devices = await self._with_live_status(devices)
        locks: list[KKHomeLockDevice] = []
        for device in devices:
            if not self._looks_like_lock(device):
                continue
            lock = self._normalize_lock(device)
            if lock is not None:
                locks.append(lock)
        return locks

    async def async_refresh_lock(self, device_id: str) -> KKHomeLockDevice | None:
        """Refresh one device from the device list response."""
        locks = await self.async_get_locks()
        for lock in locks:
            if lock.device_id == device_id:
                return lock
        return None

    async def async_lock(self, device: KKHomeLockDevice) -> None:
        """Send a lock command."""
        if await self._try_ble_command(device):
            self._remember_command_state(device.device_id, True)
            await self._wait_for_lock_state(device, True)
            return

        payload = self._command_payload(device)
        response = await self._request(
            "post",
            self._config[CONF_LOCK_PATH],
            json_body=self._encrypt_payload(payload),
            headers={_ENCRYPT_DATA_HEADER: _ENCRYPT_DATA_HEADER},
        )
        _LOGGER.debug(
            "KK Home lock command response for %s using payload %s with ids %s: %s",
            device.device_id,
            payload,
            self._debug_device_ids(device.raw),
            response,
        )
        self._remember_command_state(device.device_id, True)
        await self._wait_for_lock_state(device, True)

    async def async_unlock(self, device: KKHomeLockDevice) -> None:
        """Send an unlock command."""
        if await self._try_ble_command(device):
            self._remember_command_state(device.device_id, False)
            await self._wait_for_lock_state(device, False)
            return

        payload = self._command_payload(device)
        response = await self._request(
            "post",
            self._config[CONF_UNLOCK_PATH],
            json_body=self._encrypt_payload(payload),
            headers={_ENCRYPT_DATA_HEADER: _ENCRYPT_DATA_HEADER},
        )
        _LOGGER.debug(
            "KK Home unlock command response for %s using payload %s with ids %s: %s",
            device.device_id,
            payload,
            self._debug_device_ids(device.raw),
            response,
        )
        self._remember_command_state(device.device_id, False)
        await self._wait_for_lock_state(device, False)

    async def async_get_open_status(self, device: KKHomeLockDevice) -> Any:
        """Fetch the current open status for one device."""
        detail_payload = self._device_detail_payload(device)
        try:
            return await self._request(
                "post",
                self._config[CONF_DEVICE_DETAIL_PATH],
                json_body=self._sign_payload(detail_payload),
            )
        except KKHomeApiError:
            _LOGGER.debug(
                "KK Home device detail fetch failed for %s, falling back to status endpoint",
                device.device_id,
                exc_info=True,
            )
            return await self._request(
                "post",
                self._config[CONF_STATUS_PATH],
                json_body=self._sign_payload({"esn": self._device_esn(device)}),
            )

    async def _with_live_status(
        self, devices: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Overlay per-device live open status onto the device list."""
        if not devices:
            return devices

        async def enrich(device: dict[str, Any]) -> dict[str, Any]:
            if not self._looks_like_lock(device):
                return device

            normalized = self._normalize_lock(device)
            if normalized is None:
                return device

            try:
                live_status = await self.async_get_open_status(normalized)
            except KKHomeApiError:
                _LOGGER.debug(
                    "KK Home live status fetch failed for %s",
                    normalized.device_id,
                    exc_info=True,
                )
                return device

            if not isinstance(live_status, dict):
                return device

            merged = dict(device)
            merged.update(live_status)
            return merged

        return await asyncio.gather(*(enrich(device) for device in devices))

    async def _wait_for_lock_state(
        self, device: KKHomeLockDevice, desired_locked: bool
    ) -> bool:
        """Wait briefly for the cloud status to reflect a lock/unlock command."""
        for _attempt in range(8):
            await asyncio.sleep(1)
            try:
                status = await self.async_get_open_status(device)
            except KKHomeApiError:
                _LOGGER.debug(
                    "KK Home polling after command failed for %s",
                    device.device_id,
                    exc_info=True,
                )
                continue

            locked = None
            if isinstance(status, dict):
                locked = self._extract_locked(status)
            _LOGGER.debug(
                "KK Home post-command status poll for %s attempt %s: locked=%s payload=%s",
                device.device_id,
                _attempt + 1,
                locked,
                status,
            )

            if locked is desired_locked:
                return True

        _LOGGER.warning(
            "KK Home command for %s (%s) was accepted but the device did not report "
            "the desired locked=%s state within the verification window. "
            "The coordinator will keep polling and the lock may still complete.",
            device.name,
            device.device_id,
            desired_locked,
        )
        _LOGGER.debug(
            "KK Home post-command verification timed out for %s; identifiers=%s",
            device.device_id,
            self._debug_device_ids(device.raw),
        )
        return False

    async def _try_ble_command(self, device: KKHomeLockDevice) -> bool:
        """Attempt direct BLE lock control when the device exposes BLE credentials."""
        if not self._supports_ble(device.raw) or device.is_locked is None:
            return False

        try:
            await self._ble.async_set_lock_state(
                device.raw,
                currently_locked=device.is_locked,
            )
        except KKHomeBleUnavailableError:
            _LOGGER.debug(
                "KK Home BLE support unavailable on this host for %s",
                device.device_id,
                exc_info=True,
            )
            return False
        except KKHomeBleError:
            _LOGGER.warning(
                "KK Home BLE command failed for %s (%s); falling back to cloud control",
                device.name,
                device.device_id,
                exc_info=True,
            )
            return False

        _LOGGER.debug(
            "KK Home BLE command sent for %s using ids %s",
            device.device_id,
            self._debug_device_ids(device.raw),
        )
        return True

    async def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json_body: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        allow_unauthenticated: bool = False,
        retry_on_auth_failure: bool = True,
    ) -> Any:
        if (
            not allow_unauthenticated
            and retry_on_auth_failure
            and self._token_needs_refresh()
            and self._credentials_available()
        ):
            await self.async_authenticate()

        url = self._build_url(path)
        request_headers = self._headers if not allow_unauthenticated else {
            key: value
            for key, value in self._headers.items()
            if key.lower() != "token"
        }
        if headers:
            request_headers.update(headers)
        if json_body is not None:
            request_headers["Content-Type"] = "application/json"
        try:
            response = await self._client.request(
                method,
                url,
                headers=request_headers,
                params=params,
                json=json_body,
            )
        except HTTPError as err:
            _LOGGER.exception("KK Home HTTP client error for %s", url)
            raise KKHomeApiError(f"Request failed for {url}: {err}") from err

        text = response.text
        parsed: Any
        try:
            parsed = json.loads(text) if text else {}
        except json.JSONDecodeError:
            parsed = text

        if isinstance(parsed, dict) and "encryptData" in parsed:
            parsed = self._decrypt_response(parsed["encryptData"])

        if response.status_code in (401, 403):
            if (
                not allow_unauthenticated
                and retry_on_auth_failure
                and self._credentials_available()
            ):
                _LOGGER.warning("KK Home auth rejected for %s; retrying with a fresh login", url)
                self._clear_token()
                await self.async_authenticate()
                return await self._request(
                    method,
                    path,
                    params=params,
                    json_body=json_body,
                    headers=headers,
                    allow_unauthenticated=allow_unauthenticated,
                    retry_on_auth_failure=False,
                )
            _LOGGER.warning("KK Home auth rejected for %s: %s", url, text)
            raise KKHomeAuthError(
                f"Authentication failed for {url}: HTTP {response.status_code}"
            )
        if response.status_code >= 400:
            _LOGGER.warning("KK Home HTTP error for %s: %s", url, text)
            raise KKHomeApiError(
                f"Request failed for {url}: HTTP {response.status_code}: {text}"
            )

        if isinstance(parsed, dict):
            if (
                not allow_unauthenticated
                and retry_on_auth_failure
                and self._response_needs_reauthentication(parsed)
                and self._credentials_available()
            ):
                _LOGGER.warning("KK Home token rejected for %s; retrying with a fresh login", url)
                self._clear_token()
                await self.async_authenticate()
                return await self._request(
                    method,
                    path,
                    params=params,
                    json_body=json_body,
                    headers=headers,
                    allow_unauthenticated=allow_unauthenticated,
                    retry_on_auth_failure=False,
                )
            if self._response_needs_reauthentication(parsed):
                raise KKHomeAuthError(
                    parsed.get("msg")
                    or parsed.get("message")
                    or "Authentication failed"
                )
            if parsed.get("success") is False:
                _LOGGER.warning("KK Home API returned success=false for %s: %s", url, parsed)
                raise KKHomeApiError(
                    parsed.get("msg") or parsed.get("message") or "API returned success=false"
                )
            if "code" in parsed and parsed["code"] not in (0, 200, "0", "200"):
                _LOGGER.warning("KK Home API returned non-success code for %s: %s", url, parsed)
                raise KKHomeApiError(
                    parsed.get("msg")
                    or parsed.get("message")
                    or f"Unexpected response code {parsed['code']}"
                )
            if "data" in parsed:
                return parsed["data"]
        return parsed

    def _build_url(self, path: str) -> str:
        base_url = self._config[CONF_BASE_URL].rstrip("/")
        if path.startswith("http://") or path.startswith("https://"):
            return path
        return f"{base_url}/{path.lstrip('/')}"

    def _extract_devices(self, payload: Any) -> list[dict[str, Any]]:
        if isinstance(payload, list):
            return [item for item in payload if isinstance(item, dict)]
        if not isinstance(payload, dict):
            return []

        for key in (
            "records",
            "rows",
            "list",
            "devices",
            "deviceList",
            "items",
            "data",
        ):
            value = payload.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]
        nested = payload.get("page")
        if isinstance(nested, dict):
            return self._extract_devices(nested)
        return [payload]

    def _looks_like_lock(self, device: dict[str, Any]) -> bool:
        haystack = " ".join(
            str(device.get(key, ""))
            for key in (
                "name",
                "lockNickname",
                "deviceName",
                "productName",
                "deviceType",
                "category",
                "model",
            )
        ).lower()
        return "lock" in haystack or "door" in haystack

    def _normalize_lock(self, device: dict[str, Any]) -> KKHomeLockDevice | None:
        device_id = self._first_value(
            device,
            "_id",
            "deviceId",
            "id",
            "did",
            "deviceNo",
            "wifiSN",
        )
        if not device_id:
            _LOGGER.debug("Skipping device without id: %s", device)
            return None
        name = (
            self._first_value(
                device,
                "lockNickname",
                "name",
                "deviceName",
                "productName",
            )
            or f"KK Home Lock {device_id}"
        )
        return KKHomeLockDevice(
            device_id=str(device_id),
            name=str(name),
            is_locked=self._effective_locked_state(str(device_id), device),
            battery_level=self._extract_battery(device),
            raw=device,
        )

    def _extract_locked(self, device: dict[str, Any]) -> bool | None:
        for key in (
            "isLocked",
            "locked",
            "lockState",
            "lockStatus",
            "status",
            "doorLockStatus",
            "openStatus",
            "state",
        ):
            value = device.get(key)
            normalized = self._normalize_lock_state(value)
            if normalized is not None:
                return normalized

        nested = device.get("statusVO") or device.get("properties") or device.get("stateVO")
        if isinstance(nested, dict):
            return self._extract_locked(nested)
        return None

    def _extract_battery(self, device: dict[str, Any]) -> int | None:
        for key in (
            "battery",
            "batteryLevel",
            "electricQuantity",
            "power",
        ):
            value = device.get(key)
            if isinstance(value, bool):
                continue
            if isinstance(value, (int, float)):
                return int(value)
            if isinstance(value, str) and value.strip().isdigit():
                return int(value.strip())

        nested = device.get("statusVO") or device.get("properties") or device.get("stateVO")
        if isinstance(nested, dict):
            return self._extract_battery(nested)
        return None

    def _effective_locked_state(
        self, device_id: str, device: dict[str, Any]
    ) -> bool | None:
        locked = self._extract_locked(device)
        override = self._command_state_overrides.get(device_id)
        if override is None:
            return locked

        desired_locked, expires_at = override
        if time.time() >= expires_at:
            self._command_state_overrides.pop(device_id, None)
            return locked

        if locked is desired_locked:
            self._command_state_overrides.pop(device_id, None)
            return locked

        return desired_locked

    def _find_token(self, payload: Any) -> str | None:
        if isinstance(payload, str):
            return payload
        if isinstance(payload, dict):
            for key in (
                "accessToken",
                "access_token",
                "token",
                "bearerToken",
            ):
                value = payload.get(key)
                if isinstance(value, str) and value:
                    return value
            for value in payload.values():
                token = self._find_token(value)
                if token:
                    return token
        if isinstance(payload, list):
            for item in payload:
                token = self._find_token(item)
                if token:
                    return token
        return None

    def _credentials_available(self) -> bool:
        username = self._config.get(CONF_USERNAME)
        password = self._config.get(CONF_PASSWORD)
        return bool(username and password)

    def _remember_command_state(self, device_id: str, desired_locked: bool) -> None:
        self._command_state_overrides[device_id] = (
            desired_locked,
            time.time() + _COMMAND_STATE_GRACE_SECONDS,
        )

    def _set_token(self, token: str | None) -> None:
        self._token = token or None
        self._token_expires_at = self._decode_token_expiration(self._token)

    def _clear_token(self) -> None:
        self._set_token(None)

    def _token_needs_refresh(self) -> bool:
        if not self._token:
            return True
        if self._token_expires_at is None:
            return False
        return time.time() >= self._token_expires_at - _AUTH_REFRESH_SKEW_SECONDS

    def _decode_token_expiration(self, token: str | None) -> int | None:
        claims = self._decode_jwt_claims(token)
        if not isinstance(claims, dict):
            return None
        expires_at = claims.get("exp")
        if isinstance(expires_at, (int, float)):
            return int(expires_at)
        if isinstance(expires_at, str) and expires_at.isdigit():
            return int(expires_at)
        return None

    def _decode_jwt_claims(self, token: str | None) -> dict[str, Any] | None:
        if not token or token.count(".") < 2:
            return None
        try:
            payload = token.split(".", 2)[1]
            padded = payload + "=" * (-len(payload) % 4)
            decoded = urlsafe_b64decode(padded.encode())
            claims = json.loads(decoded.decode())
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
            return None
        return claims if isinstance(claims, dict) else None

    def _response_needs_reauthentication(self, payload: dict[str, Any]) -> bool:
        code = str(payload.get("code", "")).strip()
        if code in {"401", "403", "444"}:
            return True

        message = " ".join(
            str(payload.get(key, ""))
            for key in ("msg", "message", "error", "detail")
        ).lower()
        return any(
            marker in message
            for marker in (
                "not logged in",
                "login expired",
                "token expired",
                "invalid token",
                "unauthorized",
                "forbidden",
            )
        )

    def _first_value(self, payload: dict[str, Any], *keys: str) -> Any:
        for key in keys:
            value = payload.get(key)
            if value not in (None, ""):
                return value
        return None

    def _normalize_lock_state(self, value: Any) -> bool | None:
        if isinstance(value, bool):
            return value
        if isinstance(value, (int, float)):
            if int(value) == 1:
                return True
            if int(value) in (0, 2):
                return False
        if isinstance(value, str):
            normalized = value.strip().lower()
            if normalized in {"locked", "lock", "closed", "secure", "1", "true"}:
                return True
            if normalized in {"unlocked", "unlock", "open", "ajar", "0", "2", "false"}:
                return False
        return None

    def _device_esn(self, device: KKHomeLockDevice) -> str:
        esn = self._first_value(device.raw, "wifiSN", "esn", "deviceSn", "sn")
        if esn:
            return str(esn)
        raise KKHomeApiError(f"Device {device.device_id} does not expose an ESN/wifiSN")

    def _supports_ble(self, payload: dict[str, Any]) -> bool:
        required_fields = ("bleMac", "password1", "password2")
        return all(isinstance(payload.get(key), str) and payload.get(key) for key in required_fields)

    def _command_payload(self, device: KKHomeLockDevice) -> dict[str, Any]:
        user_number_id = self._first_value(device.raw, "userNumberId")
        if user_number_id is None:
            raise KKHomeApiError(
                f"Device {device.device_id} does not expose userNumberId"
            )
        return {
            "esn": self._device_esn(device),
            "userNumberId": int(user_number_id),
        }

    def _device_detail_payload(self, device: KKHomeLockDevice) -> dict[str, Any]:
        """Build the richer device-detail query payload."""
        payload: dict[str, Any] = {"esn": self._device_esn(device)}
        device_id = self._first_value(device.raw, "_id", "deviceId", "id")
        if device_id is not None:
            payload["deviceId"] = str(device_id)
        return payload

    def _debug_device_ids(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Return the most relevant device identifiers for diagnostics."""
        keys = (
            "_id",
            "deviceId",
            "id",
            "did",
            "deviceNo",
            "wifiSN",
            "esn",
            "deviceSn",
            "sn",
            "userNumberId",
            "lockId",
            "gatewayId",
            "type",
            "deviceType",
            "model",
            "productName",
            "openStatus",
            "lockStatus",
            "status",
        )
        return {key: payload.get(key) for key in keys if key in payload}

    def _sign_payload(self, payload: dict[str, Any]) -> dict[str, Any]:
        signed_payload = dict(payload)
        signed_payload["reqTime"] = str(int(time.time() * 1000))
        sorted_json = json.dumps(signed_payload, sort_keys=True, separators=(",", ":"))
        signature = self._private_key.sign(
            sorted_json.encode(),
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
        signed_payload["sign"] = b64encode(signature).decode()
        return signed_payload

    def _encrypt_payload(self, payload: dict[str, Any]) -> dict[str, str]:
        signed_payload = self._sign_payload(payload)
        json_payload = json.dumps(signed_payload, separators=(",", ":"))
        payload_bytes = json_payload.encode()
        block_size = (self._public_key.key_size // 8) - 11
        encrypted_chunks: list[bytes] = []
        for offset in range(0, len(payload_bytes), block_size):
            encrypted_chunks.append(
                self._public_key.encrypt(
                    payload_bytes[offset : offset + block_size],
                    padding.PKCS1v15(),
                )
            )
        return {"encryptData": b64encode(b"".join(encrypted_chunks)).decode()}

    def _decrypt_response(self, encrypted_data: str) -> Any:
        encrypted_bytes = b64decode(encrypted_data)
        block_size = self._private_key.key_size // 8
        decrypted_chunks: list[bytes] = []
        for offset in range(0, len(encrypted_bytes), block_size):
            decrypted_chunks.append(
                self._private_key.decrypt(
                    encrypted_bytes[offset : offset + block_size],
                    padding.PKCS1v15(),
                )
            )
        decrypted_text = b"".join(decrypted_chunks).decode()
        return json.loads(decrypted_text)
