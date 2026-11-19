# Danfoss Link CC for Home Assistant

[![Test](https://github.com/UrbanskiDawid/home-assistant-danfoss-link-cc/actions/workflows/test.yaml/badge.svg)](https://github.com/UrbanskiDawid/home-assistant-danfoss-link-cc/actions/workflows/test.yaml)
[![HACS Custom](https://img.shields.io/badge/HACS-Custom-orange.svg)](https://hacs.xyz/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Control a **Danfoss Link™ CC** heating touch panel from Home Assistant now that the official
*Danfoss Link* app is discontinued. It needs no Danfoss account: the integration pairs with
the panel using the code the panel shows, just like the app did.

> [!NOTE]
> This is an **unofficial** community project and is not affiliated with or endorsed by
> Danfoss or Trifork. The protocol was reverse-engineered for interoperability; see
> [danfoss-link-cc](https://github.com/UrbanskiDawid/danfoss-link-cc) for the details and
> audit trail.

## Entities

| Entity | Content |
|---|---|
| `climate.<room>` (one per room) | Current and target temperature. Set the target temperature. Mode `auto` follows the panel's schedule; `heat` is a fixed manual setpoint. The action shows `heating` or `idle`. |
| `sensor.danfoss_link_cc_state` | System state: `AtHome`, `Asleep`, `Away`, ... |
| `sensor.danfoss_link_cc_alarms` | Number of unresolved alarms, with the list in the `alarms` attribute. |
| `binary_sensor.danfoss_link_cc_battery` | On while any device reports a battery alarm (low, critical or dead). The panel reports no battery levels. |

The panel is polled once a minute.

## Installation

### HACS

In HACS open ⋮ → *Custom repositories*, add
`https://github.com/UrbanskiDawid/home-assistant-danfoss-link-cc` as an *Integration*,
download **Danfoss Link CC** and restart Home Assistant.

### Manually

Download [`danfoss_link_cc.zip`](https://github.com/UrbanskiDawid/home-assistant-danfoss-link-cc/releases/latest/download/danfoss_link_cc.zip),
unzip it to `config/custom_components/danfoss_link_cc` and restart Home Assistant.

## Configuration

1. On the touch panel, start adding a new app/device. It shows a 9-digit code.
2. In Home Assistant go to Settings → Devices & services → Add integration →
   **Danfoss Link CC** and enter the code.

## How it works

The panel only talks through Trifork's MDG cloud relay (`mdg-danfoss.hosted.trifork.com`),
the same service the app used. The integration opens an end-to-end encrypted channel to the
panel through it and uses the panel's REST API (`/api/world`, `/api/rooms/{id}`). Pairing
uses PACE, so the relay can't read the traffic. If Trifork switches the relay off, this
integration stops working too.

## License

[MIT](LICENSE)
