#
# Licensed to Elasticsearch under one or more contributor
# license agreements. See the NOTICE file distributed with
# this work for additional information regarding copyright
# ownership. Elasticsearch licenses this file to you under
# the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
#

# Reset all MFA factors for an Okta user

import logging.config

import click

from dorothy.core import (
    Module,
    index_event,
)
from dorothy.modules.persistence.persistence import persistence

LOGGER = logging.getLogger(__name__)
MODULE_DESCRIPTION = "Reset all MFA factors for an Okta user"
TACTICS = ["Persistence"]
URL_OR_API_TOKEN_ERROR = "ERROR. Verify that the Okta URL and API token in your configuration profile are correct"

MODULE_OPTIONS = {"id": {"value": None, "required": True, "help": "The unique ID for the user"}}
MODULE = Module(MODULE_OPTIONS)


@persistence.subshell(name="reset-factors")
@click.pass_context
def reset_factors(ctx):
    """Reset all MFA factors for an Okta user.

    This action can only be completed if the user is currently enrolled in one or more MFA factors.
    The user's status remains ACTIVE. An email notification will be sent to the user."""


@reset_factors.command()
def info():
    """Show available options and their current values for this module"""

    MODULE.print_info()


@reset_factors.command()
@click.pass_context
@click.option("--id", help=MODULE_OPTIONS["id"]["help"])
def set(ctx, **kwargs):
    """Set one or more options for this module"""

    MODULE.set_options(ctx, kwargs)


@reset_factors.command()
def reset():
    """Reset the options for this module"""

    MODULE.reset_options()


@reset_factors.command()
@click.pass_context
def execute(ctx):
    """Execute this module with the configured options"""

    error = MODULE.check_options()

    if error:
        return

    msg = f'Attempting to reset MFA factors for user ID {MODULE_OPTIONS["id"]["value"]}'
    LOGGER.info(msg)
    index_event(ctx.obj.es, module=__name__, event_type="INFO", event=msg)
    click.echo(f"[*] {msg}")

    url = f'{ctx.obj.base_url}/users/{MODULE_OPTIONS["id"]["value"]}/lifecycle/reset_factors'

    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Authorization": f"SSWS {ctx.obj.api_token}",
    }

    params = {}
    payload = {}

    try:
        response = ctx.obj.session.post(url, headers=headers, params=params, json=payload, timeout=7)
    except Exception as e:
        LOGGER.error(e, exc_info=True)
        index_event(ctx.obj.es, module=__name__, event_type="ERROR", event=e)
        click.secho(f"[!] {URL_OR_API_TOKEN_ERROR}", fg="red")
        response = None

    if response.ok:
        msg = f'MFA factors reset for user {MODULE_OPTIONS["id"]["value"]}'
        LOGGER.info(msg)
        index_event(ctx.obj.es, module=__name__, event_type="INFO", event=msg)
        click.secho(f"[*] {msg}", fg="green")

        ctx.obj.okta.get_user(ctx, MODULE_OPTIONS["id"]["value"])

    else:
        msg = (
            f"Error resetting MFA factors for Okta user\n"
            f"    Response Code: {response.status_code} | Response Reason: {response.reason}\n"
            f'    Error Code: {response.json().get("errorCode")} | Error Summary: {response.json().get("errorSummary")}'
        )
        LOGGER.error(msg)
        index_event(ctx.obj.es, module=__name__, event_type="ERROR", event=msg)
        click.secho(f"[!] {msg}", fg="red")
        click.echo("Check that the user's status is ACTIVE and that they have at least one factor enrolled")

        return
