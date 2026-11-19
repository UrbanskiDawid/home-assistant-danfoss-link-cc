"""Config flow and entities, with the panel mocked."""

from unittest.mock import patch

from homeassistant import config_entries
from homeassistant.data_entry_flow import FlowResultType

from custom_components.danfoss_link_cc.const import DOMAIN
from custom_components.danfoss_link_cc.link import LinkError

LINK = "custom_components.danfoss_link_cc.link"
ENTRY = {"key": "1", "cert": "", "panel_cert": "", "panel_id": "aa:bb"}
ROOM = {
    "id": 0, "name": "Salon", "ambientTemperature": 21.5, "setpoint": {"temperature": 22.0},
    "minSetpoint": 6.5, "maxSetpoint": 28.0, "regulation": {"type": "Schedule"}, "regulationState": "Heating",
}
ALARM = {"id": 1, "titleTextId": "IDS_UA1_ALERTVIEWER_BATTERY_LOW_ALERT", "room": "0"}
WORLD = {"allRooms": [ROOM], "systemStatus": {"currentState": "AtHome"}, "allUnresolvedAlarms": [ALARM]}


def fake_request(calls):
    def request(entry, method, uri, body=None):
        calls.append((method, uri, body))
        return WORLD
    return request


async def setup(hass, calls):
    with patch(f"{LINK}.pair", return_value=ENTRY), patch(f"{LINK}.request", side_effect=fake_request(calls)):
        result = await hass.config_entries.flow.async_init(DOMAIN, context={"source": config_entries.SOURCE_USER})
        result = await hass.config_entries.flow.async_configure(result["flow_id"], {"code": "123-456-789"})
        assert result["type"] is FlowResultType.CREATE_ENTRY
        await hass.async_block_till_done()


async def test_entities_and_set_temperature(enable_custom_integrations, hass):
    calls = []
    await setup(hass, calls)

    room = hass.states.get("climate.danfoss_link_cc_salon")
    assert room.state == "auto"
    assert room.attributes["current_temperature"] == 21.5
    assert room.attributes["temperature"] == 22.0
    assert room.attributes["hvac_action"] == "heating"
    assert hass.states.get("sensor.danfoss_link_cc_state").state == "AtHome"
    assert hass.states.get("sensor.danfoss_link_cc_alarms").state == "1"
    assert hass.states.get("binary_sensor.danfoss_link_cc_battery").state == "on"

    with patch(f"{LINK}.request", side_effect=fake_request(calls)):
        await hass.services.async_call(
            "climate", "set_temperature", {"entity_id": room.entity_id, "temperature": 20.5}, blocking=True
        )
    assert ("PATCH", "/api/rooms/0", {"id": 0, "setpoint": {"temperature": 20.5}}) in calls


async def test_pairing_failed(enable_custom_integrations, hass):
    with patch(f"{LINK}.pair", side_effect=LinkError("wrong code")):
        result = await hass.config_entries.flow.async_init(DOMAIN, context={"source": config_entries.SOURCE_USER})
        result = await hass.config_entries.flow.async_configure(result["flow_id"], {"code": "1"})
    assert result["type"] is FlowResultType.FORM
    assert result["errors"] == {"base": "pairing_failed"}
