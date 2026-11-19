"""Config flow: pair with the panel using the code it shows."""

from __future__ import annotations

import logging
from typing import Any

import voluptuous as vol
from homeassistant.config_entries import ConfigFlow, ConfigFlowResult

from . import link
from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)


class DanfossLinkConfigFlow(ConfigFlow, domain=DOMAIN):
    VERSION = 1

    async def async_step_user(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        errors: dict[str, str] = {}
        if user_input is not None:
            try:
                data = await self.hass.async_add_executor_job(link.pair, user_input["code"])
            except link.LinkError as err:
                _LOGGER.warning("Pairing failed: %s", err)
                errors["base"] = "pairing_failed"
            else:
                await self.async_set_unique_id(data["panel_id"])
                self._abort_if_unique_id_configured()
                return self.async_create_entry(title="Danfoss Link CC", data=data)
        return self.async_show_form(step_id="user", data_schema=vol.Schema({vol.Required("code"): str}), errors=errors)
