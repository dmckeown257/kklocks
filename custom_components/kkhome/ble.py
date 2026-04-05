"""BLE transport for KK Home locks."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

try:
    from bleak import BleakClient
except ImportError:  # pragma: no cover - depends on host environment
    BleakClient = None

_LOGGER = logging.getLogger(__name__)

_CONTROL_NOTIFY_UUID = "ffe4"
_CONTROL_WRITE_UUID = "ffe9"
_AUTH_CMD = 0x01
_AUTH_RESPONSE_CMD = 0x08
_LOCK_CONTROL_CMD = 0x02
_MODE_PLAIN = 0x00
_MODE_ENCRYPTED = 0x01
_PACKET_SIZE = 20
_PAYLOAD_SIZE = 16
_MODE_BYTE_1 = 0x04
_MODE_BYTE_2 = 0x00


class KKHomeBleError(Exception):
    """Raised when BLE lock control fails."""


class KKHomeBleUnavailableError(KKHomeBleError):
    """Raised when BLE support is unavailable on the host."""


class KKHomeBleController:
    """Implements the KK Home lock BLE protocol."""

    def __init__(self, hass) -> None:
        """Initialize the controller."""
        self._hass = hass

    async def async_set_lock_state(
        self,
        device: dict[str, Any],
        *,
        currently_locked: bool | None,
    ) -> None:
        """Connect to the lock and send the BLE toggle command."""
        if BleakClient is None:
            raise KKHomeBleUnavailableError("The host does not have the bleak package installed.")

        ble_mac = self._require_hex_field(device, "bleMac")
        esn = self._require_text_field(device, "wifiSN", "esn", "deviceSn", "sn")
        pwd1 = self._decode_hex(self._require_text_field(device, "password1"), expected_length=12)
        pwd2 = self._decode_hex(self._require_text_field(device, "password2"), expected_length=4)
        toggle_value = self._toggle_value(currently_locked)
        responses: asyncio.Queue[dict[str, Any]] = asyncio.Queue()

        client = BleakClient(ble_mac, timeout=15.0)
        try:
            await client.connect()
            notify_char = self._resolve_characteristic(client, _CONTROL_NOTIFY_UUID)
            write_char = self._resolve_characteristic(client, _CONTROL_WRITE_UUID)

            def handle_notification(_: Any, data: bytearray) -> None:
                parsed = self._parse_frame(bytes(data), pwd1, pwd2)
                if parsed is None:
                    return
                self._hass.loop.call_soon_threadsafe(responses.put_nowait, parsed)

            await client.start_notify(notify_char, handle_notification)
            await client.write_gatt_char(write_char, self._build_auth_command(esn, pwd1, pwd2), response=True)
            auth_response = await self._wait_for_response(responses, _AUTH_RESPONSE_CMD)
            auth_payload = auth_response["payload"]
            if not auth_payload or auth_payload[0] != 0x02 or len(auth_payload) < 5:
                raise KKHomeBleError(f"Unexpected auth payload from {ble_mac}: {auth_payload.hex()}")

            pwd3 = auth_payload[1:5]
            ack = self._build_ack_command(auth_response["tsn"], _AUTH_RESPONSE_CMD)
            await client.write_gatt_char(write_char, ack, response=True)
            await asyncio.sleep(0.1)

            lock_command = self._build_lock_command(toggle_value, pwd1, pwd3)
            await client.write_gatt_char(write_char, lock_command, response=True)
            await asyncio.sleep(1.0)
        except asyncio.TimeoutError as err:
            raise KKHomeBleError(f"Timed out waiting for BLE response from {ble_mac}") from err
        except KKHomeBleError:
            raise
        except Exception as err:
            raise KKHomeBleError(f"BLE control failed for {ble_mac}: {err}") from err
        finally:
            if client.is_connected:
                try:
                    await client.disconnect()
                except Exception:  # pragma: no cover - disconnect best effort
                    _LOGGER.debug("BLE disconnect failed for %s", ble_mac, exc_info=True)

    async def _wait_for_response(
        self, responses: asyncio.Queue[dict[str, Any]], command: int
    ) -> dict[str, Any]:
        deadline = self._hass.loop.time() + 10
        while True:
            remaining = deadline - self._hass.loop.time()
            if remaining <= 0:
                raise asyncio.TimeoutError
            response = await asyncio.wait_for(responses.get(), timeout=remaining)
            if response["cmd"] == command:
                return response

    def _parse_frame(
        self,
        frame: bytes,
        pwd1: bytes,
        pwd2_or_3: bytes | None,
    ) -> dict[str, Any] | None:
        if len(frame) < 4:
            return None

        encrypted = frame[0] in (_MODE_ENCRYPTED, 0x03)
        payload = frame[4:]
        if frame[0] < 2 and len(payload) != _PAYLOAD_SIZE:
            return None
        if frame[0] >= 2 and len(payload) % _PAYLOAD_SIZE != 0:
            payload += b"\x00" * (_PAYLOAD_SIZE - (len(payload) % _PAYLOAD_SIZE))

        if encrypted:
            key = self._combine_key(pwd1, pwd2_or_3)
            payload = self._aes_ecb_decrypt(payload, key)
        checksum = self._checksum(payload)
        if checksum != frame[2]:
            _LOGGER.debug(
                "Ignoring BLE frame with invalid checksum: expected=%s actual=%s frame=%s",
                frame[2],
                checksum,
                frame.hex(),
            )
            return None

        return {
            "mode": frame[0],
            "tsn": frame[1],
            "cmd": frame[3],
            "payload": payload,
            "frame": frame,
        }

    def _build_auth_command(self, esn: str, pwd1: bytes, pwd2: bytes) -> bytes:
        return self._build_encrypted_command(_AUTH_CMD, esn.encode(), pwd1, pwd2)

    def _build_lock_command(self, toggle_value: int, pwd1: bytes, pwd3: bytes) -> bytes:
        payload = bytes((toggle_value, _MODE_BYTE_1, _MODE_BYTE_2, 0))
        return self._build_encrypted_command(_LOCK_CONTROL_CMD, payload, pwd1, pwd3)

    def _build_ack_command(self, tsn: int, command: int) -> bytes:
        payload = bytes((0,))
        frame = bytearray(_PACKET_SIZE)
        frame[0] = _MODE_PLAIN
        frame[1] = tsn & 0xFF
        frame[2] = self._checksum(payload)
        frame[3] = command & 0xFF
        frame[4 : 4 + len(payload)] = payload
        return bytes(frame)

    def _build_encrypted_command(
        self,
        command: int,
        payload: bytes,
        pwd1: bytes,
        pwd2_or_3: bytes,
    ) -> bytes:
        padded_payload = payload.ljust(_PAYLOAD_SIZE, b"\x00")
        frame = bytearray(_PACKET_SIZE)
        frame[0] = _MODE_ENCRYPTED
        frame[1] = self._next_tsn()
        frame[2] = self._checksum(padded_payload)
        frame[3] = command & 0xFF
        encrypted = self._aes_ecb_encrypt(padded_payload, self._combine_key(pwd1, pwd2_or_3))
        frame[4:] = encrypted
        return bytes(frame)

    def _resolve_characteristic(self, client: BleakClient, uuid_suffix: str) -> Any:
        for service in client.services:
            for characteristic in service.characteristics:
                if characteristic.uuid.lower().endswith(uuid_suffix):
                    return characteristic
        raise KKHomeBleError(f"Could not find BLE characteristic ending with {uuid_suffix}")

    def _next_tsn(self) -> int:
        last = getattr(self, "_command_tsn", 1)
        if last == 0xFF:
            last = 1
        self._command_tsn = last + 1
        return last

    def _toggle_value(self, currently_locked: bool | None) -> int:
        if currently_locked is None:
            raise KKHomeBleError("BLE control requires a known current lock state.")
        return 1 if currently_locked else 0

    def _require_text_field(self, payload: dict[str, Any], *keys: str) -> str:
        for key in keys:
            value = payload.get(key)
            if isinstance(value, str) and value:
                return value
        raise KKHomeBleError(f"Device does not expose any of the required BLE fields: {keys}")

    def _require_hex_field(self, payload: dict[str, Any], key: str) -> str:
        value = payload.get(key)
        if isinstance(value, str) and value:
            return value.upper()
        raise KKHomeBleError(f"Device does not expose required BLE field {key}")

    def _decode_hex(self, value: str, *, expected_length: int) -> bytes:
        try:
            decoded = bytes.fromhex(value)
        except ValueError as err:
            raise KKHomeBleError(f"Invalid BLE credential hex {value!r}") from err
        if len(decoded) != expected_length:
            raise KKHomeBleError(
                f"Unexpected BLE credential length for {value!r}: {len(decoded)}"
            )
        return decoded

    def _combine_key(self, pwd1: bytes, pwd2_or_3: bytes | None) -> bytes:
        if len(pwd1) != 12:
            raise KKHomeBleError(f"Expected 12-byte pwd1, got {len(pwd1)} bytes")
        if pwd2_or_3 is None or len(pwd2_or_3) != 4:
            raise KKHomeBleError("Expected a 4-byte pwd2/pwd3 value for BLE encryption")
        return pwd1 + pwd2_or_3

    def _aes_ecb_encrypt(self, payload: bytes, key: bytes) -> bytes:
        cipher = Cipher(algorithms.AES(key), modes.ECB())
        encryptor = cipher.encryptor()
        return encryptor.update(payload) + encryptor.finalize()

    def _aes_ecb_decrypt(self, payload: bytes, key: bytes) -> bytes:
        cipher = Cipher(algorithms.AES(key), modes.ECB())
        decryptor = cipher.decryptor()
        return decryptor.update(payload) + decryptor.finalize()

    def _checksum(self, payload: bytes) -> int:
        return sum(payload) & 0xFF
