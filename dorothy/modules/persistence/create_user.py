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

# Create and activate an Okta user with an assigned password

import logging.config

import click

from dorothy.core import Module, index_event
from dorothy.modules.persistence.persistence import persistence

LOGGER = logging.getLogger(__name__)
MODULE_DESCRIPTION = "Create and activate an Okta user with an assigned password"
TACTICS = ["Persistence"]
URL_OR_API_TOKEN_ERROR = "ERROR. Verify that the Okta URL and API token in your configuration profile are correct"

MODULE_OPTIONS = {
    "first_name": {"value": None, "required": True, "help": "Given name of the user"},
    "last_name": {"value": None, "required": True, "help": "Family name of the user"},
    "email": {"value": None, "required": True, "help": "Primary email address of user"},
    "login": {"value": None, "required": True, "help": "Unique identifier for the user (username)"},
    "group_ids": {
        "value": None,
        "required": False,
        "help": "The unique ID(s) of the group(s) to put the user in.\nSeparate group IDs using a comma",
    },
}
MODULE = Module(MODULE_OPTIONS)


@persistence.subshell(name="create-user")
@click.pass_context
def create_user(ctx):
    """Create and activate an Okta user with an assigned password.

    New Okta users are added to the built in "Everyone" group by default.
    """


@create_user.command()
def info():
    """Show available options and their current values for this module"""

    MODULE.print_info()


@create_user.command()
@click.pass_context
@click.option("--first-name", help=MODULE_OPTIONS["first_name"]["help"])
@click.option("--last-name", help=MODULE_OPTIONS["last_name"]["help"])
@click.option("--email", help=MODULE_OPTIONS["email"]["help"])
@click.option("--login", help=MODULE_OPTIONS["login"]["help"])
@click.option("--group-ids", help=MODULE_OPTIONS["group_ids"]["help"])
def set(ctx, **kwargs):
    """Set one or more options for this module"""

    MODULE.set_options(ctx, kwargs)


@create_user.command()
def reset():
    """Reset the options for this module"""

    MODULE.reset_options()


@create_user.command()
@click.pass_context
def execute(ctx):
    """Execute this module with the configured options"""

    error = MODULE.check_options()

    if error:
        return

    password = click.prompt(
        "[*] Enter a password for the new user. The input for this value is hidden", hide_input=True
    )

    msg = f'Attempting to create new Okta user {MODULE_OPTIONS["login"]["value"]}'
    LOGGER.info(msg)
    index_event(ctx.obj.es, module=__name__, event_type="INFO", event=msg)
    click.echo(f"[*] {msg}")

    url = f"{ctx.obj.base_url}/users"

    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Authorization": f"SSWS {ctx.obj.api_token}",
    }
    # Activate the new user when it's created
    params = {"activate": "true"}
    payload = {
        "profile": {
            "firstName": MODULE_OPTIONS["first_name"]["value"],
            "lastName": MODULE_OPTIONS["last_name"]["value"],
            "email": MODULE_OPTIONS["email"]["value"],
            "login": MODULE_OPTIONS["login"]["value"],
        },
        "groupIds": MODULE_OPTIONS["group_ids"]["value"],
        "credentials": {"password": {"value": password}},
    }

    try:
        response = ctx.obj.session.post(url, headers=headers, params=params, json=payload, timeout=7)
    except Exception as e:
        LOGGER.error(e, exc_info=True)
        index_event(ctx.obj.es, module=__name__, event_type="ERROR", event=e)
        click.secho(f"[!] {URL_OR_API_TOKEN_ERROR}", fg="red")
        response = None

    if response.ok:
        msg = f'Created new Okta user {MODULE_OPTIONS["login"]["value"]}'
        LOGGER.info(msg)
        index_event(ctx.obj.es, module=__name__, event_type="INFO", event=msg)
        click.secho(f"[*] {msg}", fg="green")
    else:
        msg = (
            f"Error creating new Okta user\n"
            f"    Response Code: {response.status_code} | Response Reason: {response.reason}\n"
            f'    Error Code: {response.json().get("errorCode")} | Error Summary: {response.json().get("errorSummary")}'
        )
        LOGGER.error(msg)
        index_event(ctx.obj.es, module=__name__, event_type="ERROR", event=msg)
        click.secho(f"[!] {msg}", fg="red")
        click.echo('Did you try and add the new user to a built-in group? E.g. "Everyone"')

        return
