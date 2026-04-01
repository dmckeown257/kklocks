# KK Home Home Assistant Integration

Custom Home Assistant integration for Veise / KK Home smart locks.

Built by OpenAI Codex from live KK Home traffic captures and app reverse engineering.

This integration is working for my Veise locks in Home Assistant, but it is unofficial software and you use it at your own risk.

## Status

This integration now implements the KK Home cloud protocol recovered from your captures and the Android app:

- token auth or mail/password login
- lock and unlock commands
- device list polling
- battery reporting
- signed status queries
- RSA-encrypted command bodies

Confirmed protocol details:

- Base URL: `https://api.kksecurityhome.com`
- tenant header: `k-tenant: kawden`
- auth header: `token: <jwt>`
- login path: `/v3/user/login/get-user-by-mail`
- device list path: `/v3/user/device/list`
- lock path: `/v3/device/close-device`
- unlock path: `/v3/device/open-device`
- status path: `/v3/device/get-open-status`
- attribute path: `/v4/device/query-device-attr`

The lock and unlock requests send encrypted `encryptData`, and status requests send `esn`, `reqTime`, and `sign`.

## Install

Copy `custom_components/kkhome` into your Home Assistant config directory, or install through HACS as a custom repository.

Current custom repository URL:

- `https://github.com/dmckeown257/kklocks`

## Configure

Add the integration from the Home Assistant UI:

1. Settings
2. Devices & Services
3. Add Integration
4. Search for `KK Home`

Authentication options:

- recommended: use your KK Home email and password
- optional: paste a captured app token

The setup form still exposes the API paths in case KK changes them later.

## Default values

- Base URL: `https://api.kksecurityhome.com`
- Tenant ID: `kawden`
- Login path: `/v3/user/login/get-user-by-mail`
- Devices path: `/v3/user/device/list`
- Device detail path: `/v4/device/query-device-attr`
- Lock path: `/v3/device/close-device`
- Status path: `/v3/device/get-open-status`
- Unlock path: `/v3/device/open-device`

## Notes

- The app signs requests with an embedded RSA private key and encrypts command/login payloads with the service public key.
- Live lock state is refreshed with `/v3/device/get-open-status`, and command completion waits briefly for the KK Home cloud to catch up.
- In my environment, `openStatus = 2` maps to unlocked and `openStatus = 1` maps to locked.
- This project is not affiliated with Veise, KK Home, Kaadas, or Home Assistant.

## Publishing

For HACS, publish this project to a GitHub repository and add it in Home Assistant as a custom repository with category `Integration`.
