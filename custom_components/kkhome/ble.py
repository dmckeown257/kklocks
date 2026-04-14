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
_PAIR_CMD = 0x1B
_AUTH_CMD = 0x01
_KEY_RESPONSE_CMD = 0x08
_LOCK_CONTROL_CMD = 0x02
_MODE_PLAIN = 0x00
_MODE_ENCRYPTED = 0x01
_MODE_PLAIN_2 = 0x02
_MODE_ENCRYPTED_2 = 0x03
_PACKET_SIZE = 20
_PAYLOAD_SIZE = 16
_SYSTEM_ID_UUID = "2a23"
_MODE_BYTE_1 = 0x04
_MODE_BYTE_2 = 0x00
_PWD2_MARKER = 0x01
_PWD3_MARKER = 0x02


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
        pwd2 = self._decode_optional_hex(device.get("password2"), expected_length=4)
        toggle_value = self._toggle_value(currently_locked)
        responses: asyncio.Queue[bytes] = asyncio.Queue()

        client = BleakClient(ble_mac, timeout=15.0)
        try:
            await client.connect()
            control_notify_char = self._resolve_characteristic(client, _CONTROL_NOTIFY_UUID)
            write_char = self._resolve_characteristic(client, _CONTROL_WRITE_UUID)
            write_with_response = self._should_write_with_response(write_char)

            def handle_notification(_: Any, data: bytearray) -> None:
                self._hass.loop.call_soon_threadsafe(responses.put_nowait, bytes(data))

            await client.start_notify(control_notify_char, handle_notification)
            if pwd2 is not None:
                try:
                    pwd3, _ = await self._run_short_auth_flow(
                        client,
                        write_char,
                        write_with_response,
                        responses,
                        pwd1,
                        pwd2,
                    )
                    lock_command, lock_tsn = self._build_lock_command(toggle_value, pwd1, pwd3)
                    await client.write_gatt_char(
                        write_char,
                        lock_command,
                        response=write_with_response,
                    )
                    await self._wait_for_lock_ack(responses, tsn=lock_tsn)
                    return
                except asyncio.TimeoutError:
                    self._drain_queue(responses)
                    _LOGGER.debug("Short BLE auth timed out for %s, falling back to pair/auth flow", ble_mac)

            pwd3 = await self._run_pair_auth_flow(
                client,
                write_char,
                write_with_response,
                responses,
                esn,
                pwd1,
            )
            lock_command, lock_tsn = self._build_lock_command(toggle_value, pwd1, pwd3)
            await client.write_gatt_char(
                write_char,
                lock_command,
                response=write_with_response,
            )
            await self._wait_for_lock_ack(responses, tsn=lock_tsn)
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

    async def _wait_for_key_response(
        self,
        responses: asyncio.Queue[bytes],
        *,
        pwd1: bytes,
        pwd2_or_3: bytes | None,
        marker: int,
    ) -> dict[str, Any]:
        deadline = self._hass.loop.time() + 10
        while True:
            remaining = deadline - self._hass.loop.time()
            if remaining <= 0:
                raise asyncio.TimeoutError
            frame = await asyncio.wait_for(responses.get(), timeout=remaining)
            parsed = self._parse_frame(frame, pwd1, pwd2_or_3)
            if parsed is None or parsed["cmd"] != _KEY_RESPONSE_CMD:
                continue
            payload = parsed["payload"]
            if len(payload) >= 5 and payload[0] == marker:
                return parsed

    async def _wait_for_lock_ack(self, responses: asyncio.Queue[bytes], *, tsn: int) -> bytes:
        deadline = self._hass.loop.time() + 5
        while True:
            remaining = deadline - self._hass.loop.time()
            if remaining <= 0:
                raise asyncio.TimeoutError
            frame = await asyncio.wait_for(responses.get(), timeout=remaining)
            if len(frame) >= 5 and frame[0] == _MODE_PLAIN and frame[1] == tsn:
                return frame

    async def _run_short_auth_flow(
        self,
        client: BleakClient,
        write_char: Any,
        write_with_response: bool,
        responses: asyncio.Queue[bytes],
        pwd1: bytes,
        pwd2: bytes,
    ) -> tuple[bytes, int]:
        system_id = bytes(await client.read_gatt_char(_SYSTEM_ID_UUID))
        auth_command, _ = self._build_encrypted_command(_AUTH_CMD, system_id, pwd1, pwd2, None)
        await client.write_gatt_char(write_char, auth_command, response=write_with_response)
        auth_response = await self._wait_for_key_response(
            responses,
            pwd1=pwd1,
            pwd2_or_3=pwd2,
            marker=_PWD3_MARKER,
        )
        pwd3 = auth_response["payload"][1:5]
        await client.write_gatt_char(
            write_char,
            self._build_ack_command(auth_response["tsn"], 0),
            response=write_with_response,
        )
        return pwd3, 0

    async def _run_pair_auth_flow(
        self,
        client: BleakClient,
        write_char: Any,
        write_with_response: bool,
        responses: asyncio.Queue[bytes],
        esn: str,
        pwd1: bytes,
    ) -> bytes:
        pair_command, _ = self._build_pair_command(esn, pwd1)
        await client.write_gatt_char(write_char, pair_command, response=write_with_response)
        pair_response = await self._wait_for_key_response(
            responses,
            pwd1=pwd1,
            pwd2_or_3=None,
            marker=_PWD2_MARKER,
        )
        pwd2 = pair_response["payload"][1:5]
        await client.write_gatt_char(
            write_char,
            self._build_ack_command(pair_response["tsn"], pair_response["cmd"]),
            response=write_with_response,
        )

        auth_command, _ = self._build_auth_command(esn, pwd1, pwd2)
        await client.write_gatt_char(write_char, auth_command, response=write_with_response)
        auth_response = await self._wait_for_key_response(
            responses,
            pwd1=pwd1,
            pwd2_or_3=pwd2,
            marker=_PWD3_MARKER,
        )
        pwd3 = auth_response["payload"][1:5]
        await client.write_gatt_char(
            write_char,
            self._build_ack_command(auth_response["tsn"], auth_response["cmd"]),
            response=write_with_response,
        )
        return pwd3

    def _drain_queue(self, responses: asyncio.Queue[bytes]) -> None:
        while not responses.empty():
            try:
                responses.get_nowait()
            except asyncio.QueueEmpty:
                break

    def _parse_frame(
        self,
        frame: bytes,
        pwd1: bytes,
        pwd2_or_3: bytes | None,
    ) -> dict[str, Any] | None:
        if len(frame) < 4:
            return None

        encrypted = frame[0] in (_MODE_ENCRYPTED, _MODE_ENCRYPTED_2)
        payload = frame[4:]
        if frame[0] < _MODE_PLAIN_2 and len(payload) != _PAYLOAD_SIZE:
            return None
        if frame[0] >= _MODE_PLAIN_2 and len(payload) % _PAYLOAD_SIZE != 0:
            payload += b"\x00" * (_PAYLOAD_SIZE - (len(payload) % _PAYLOAD_SIZE))

        if encrypted:
            key = self._build_key(pwd1, pwd2_or_3)
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

    def _build_pair_command(self, esn: str, pwd1: bytes) -> tuple[bytes, int]:
        return self._build_encrypted_command(_PAIR_CMD, esn.encode(), pwd1, None, None)

    def _build_auth_command(self, esn: str, pwd1: bytes, pwd2: bytes) -> tuple[bytes, int]:
        return self._build_encrypted_command(_AUTH_CMD, esn.encode(), pwd1, pwd2, None)

    def _build_lock_command(self, toggle_value: int, pwd1: bytes, pwd3: bytes) -> tuple[bytes, int]:
        payload = bytes((toggle_value, _MODE_BYTE_1, _MODE_BYTE_2, 0))
        return self._build_encrypted_command(_LOCK_CONTROL_CMD, payload, pwd1, pwd3, None)

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
        pwd2_or_3: bytes | None,
        tsn: int | None,
    ) -> tuple[bytes, int]:
        padded_payload = payload.ljust(_PAYLOAD_SIZE, b"\x00")
        frame = bytearray(_PACKET_SIZE)
        frame[0] = _MODE_ENCRYPTED
        frame[1] = self._next_tsn() if tsn is None else tsn & 0xFF
        frame[2] = self._checksum(padded_payload)
        frame[3] = command & 0xFF
        encrypted = self._aes_ecb_encrypt(padded_payload, self._build_key(pwd1, pwd2_or_3))
        frame[4:] = encrypted
        return bytes(frame), frame[1]

    def _resolve_characteristic(self, client: BleakClient, uuid_suffix: str) -> Any:
        for service in client.services:
            for characteristic in service.characteristics:
                if self._uuid_matches(characteristic.uuid, uuid_suffix):
                    return characteristic
        raise KKHomeBleError(f"Could not find BLE characteristic ending with {uuid_suffix}")

    def _uuid_matches(self, uuid_value: str, uuid_suffix: str) -> bool:
        normalized = uuid_value.lower()
        suffix = uuid_suffix.lower()
        if normalized == suffix:
            return True
        if normalized.startswith("0000") and normalized.endswith("-0000-1000-8000-00805f9b34fb"):
            return normalized[4:8] == suffix
        return normalized.rsplit("-", 1)[0].endswith(suffix)

    def _should_write_with_response(self, characteristic: Any) -> bool:
        properties = {str(value).lower() for value in getattr(characteristic, "properties", [])}
        return "write-without-response" not in properties

    def _next_tsn(self) -> int:
        last = getattr(self, "_command_tsn", 1)
        if last == 0xFF:
            last = 1
        self._command_tsn = last + 1
        return last

    def _toggle_value(self, currently_locked: bool | None) -> int:
        if currently_locked is None:
            raise KKHomeBleError("BLE control requires a known current lock state.")
        return 0 if currently_locked else 1

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

    def _decode_optional_hex(self, value: Any, *, expected_length: int) -> bytes | None:
        if not isinstance(value, str) or not value:
            return None
        return self._decode_hex(value, expected_length=expected_length)

    def _build_key(self, pwd1: bytes, pwd2_or_3: bytes | None) -> bytes:
        if len(pwd1) != 12:
            raise KKHomeBleError(f"Expected 12-byte pwd1, got {len(pwd1)} bytes")
        if pwd2_or_3 is None:
            return pwd1.ljust(16, b"\x00")
        if len(pwd2_or_3) != 4:
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
