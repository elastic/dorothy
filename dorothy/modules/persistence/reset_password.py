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

# Generate a one-time token (OTT) to reset a user's password

import logging.config

import click

from dorothy.core import Module, index_event
from dorothy.modules.persistence.persistence import persistence

LOGGER = logging.getLogger(__name__)
MODULE_DESCRIPTION = "Generate a one-time token to reset a user's password"
TACTICS = ["Persistence"]
URL_OR_API_TOKEN_ERROR = "ERROR. Verify that the Okta URL and API token in your configuration profile are correct"

MODULE_OPTIONS = {"id": {"value": None, "required": True, "help": "The unique ID for the user"}}
MODULE = Module(MODULE_OPTIONS)


@persistence.subshell(name="reset-password")
@click.pass_context
def reset_password(ctx):
    """Generate a one-time token that can be used to reset a user's password

    The user's status must be ACTIVE. A URL to the OTT will be displayed after the module is executed.

    The user will have the status of RECOVERY and will not be able to login or initiate the forgot password flow
    until the password is reset.
    """


@reset_password.command()
def info():
    """Show available options and their current values for this module"""

    MODULE.print_info()


@reset_password.command()
@click.pass_context
@click.option("--id", help=MODULE_OPTIONS["id"]["help"])
def set(ctx, **kwargs):
    """Set one or more options for this module"""

    MODULE.set_options(ctx, kwargs)


@reset_password.command()
def reset():
    """Reset the options for this module"""

    MODULE.reset_options()


@reset_password.command()
def clear():
    """Clear the terminal screen"""
    click.clear()


@reset_password.command()
@click.pass_context
def execute(ctx):
    """Execute this module with the configured options"""

    error = MODULE.check_options()

    if error:
        return

    msg = f'Attempting to generate a one-time token to reset the password for user ID {MODULE_OPTIONS["id"]["value"]}'
    LOGGER.info(msg)
    index_event(ctx.obj.es, module=__name__, event_type="INFO", event=msg)
    click.echo(f"[*] {msg}")

    url = f'{ctx.obj.base_url}/users/{MODULE_OPTIONS["id"]["value"]}/lifecycle/reset_password'

    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Authorization": f"SSWS {ctx.obj.api_token}",
    }

    # Set sendEmail to False. The default value for sendEmail is True, which will send the one-time token to the
    # target user
    params = {"sendEmail": "False"}
    payload = {}

    try:
        response = ctx.obj.session.post(url, headers=headers, params=params, json=payload, timeout=7)
    except Exception as e:
        LOGGER.error(e, exc_info=True)
        index_event(ctx.obj.es, module=__name__, event_type="ERROR", event=e)
        click.secho(f"[!] {URL_OR_API_TOKEN_ERROR}", fg="red")
        response = None

    if response.ok:
        msg = f'One-time password reset token generated for user {MODULE_OPTIONS["id"]["value"]}'
        LOGGER.info(msg)
        index_event(ctx.obj.es, module=__name__, event_type="INFO", event=msg)
        click.secho(f"[*] {msg}", fg="green")
        click.echo(
            "[*] The user will have the status of RECOVERY and will not be able to login or initiate the "
            "forgot password flow until the password is reset"
        )

        response = response.json()
        click.echo(f'Reset password URL: {response["resetPasswordUrl"]}')

    else:
        msg = (
            f"Error resetting password for user\n"
            f"    Response Code: {response.status_code} | Response Reason: {response.reason}\n"
            f'    Error Code: {response.json().get("errorCode")} | Error Summary: {response.json().get("errorSummary")}'
        )
        LOGGER.error(msg)
        index_event(ctx.obj.es, module=__name__, event_type="ERROR", event=msg)
        click.secho(f"[!] {msg}", fg="red")
        click.echo("Check the status of the user. The user's status must be ACTIVE")

        return
