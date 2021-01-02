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

# Make a temporary modification to an Okta policy

import logging.config
import time

import click

from dorothy.core import (
    Module,
    index_event,
)
from dorothy.modules.defense_evasion.defense_evasion import defense_evasion

LOGGER = logging.getLogger(__name__)
MODULE_DESCRIPTION = "Make a temporary change to an Okta policy"
TACTICS = ["Defense Evasion", "Impact"]
URL_OR_API_TOKEN_ERROR = "ERROR. Verify that the Okta URL and API token in your configuration profile are correct"

MODULE_OPTIONS = {"id": {"value": None, "required": True, "help": "The unique ID for the policy"}}
MODULE = Module(MODULE_OPTIONS)


@defense_evasion.subshell(name="modify-policy")
@click.pass_context
def modify_policy(ctx):
    """Make a temporary change to an Okta policy.

    This module renames the specified policy and then reverts the change. This basic operation is enough for defenders
    to test their ability to monitor for and detect unexpected changes to Okta policies.
    """

    # Change prompt depending on name of parent shell
    if ctx.parent.command.name == "impact":
        ctx.command.shell.prompt = "dorothy > impact > modify-policy > "
    else:
        ctx.command.shell.prompt = "dorothy > defense-evasion > modify-policy > "


@modify_policy.command()
def info():
    """Show available options and their current values for this module"""

    MODULE.print_info()


@modify_policy.command()
@click.pass_context
@click.option("--id", help=MODULE_OPTIONS["id"]["help"])
def set(ctx, **kwargs):
    """Set one or more options for this module"""

    MODULE.set_options(ctx, kwargs)


@modify_policy.command()
def reset():
    """Reset the options for this module"""

    MODULE.reset_options()


@modify_policy.command()
@click.pass_context
def execute(ctx):
    """Execute this module with the configured options"""

    error = MODULE.check_options()

    if error:
        return

    policy_id = MODULE_OPTIONS["id"]["value"]

    policy = ctx.obj.okta.get_policy(ctx, policy_id)

    if policy:
        original_name = policy["name"]
        new_name = f'{policy["name"]} TEMP_STRING'

        # Rename the policy
        rename_policy(ctx, policy_id, policy["type"], original_name, new_name)
        # Change the policy name back to its original value
        rename_policy(ctx, policy_id, policy["type"], new_name, original_name)

        return


def rename_policy(ctx, policy_id, policy_type, original_name, new_name):
    """Update an existing policy with a new name"""

    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Authorization": f"SSWS {ctx.obj.api_token}",
    }

    params = {}
    # Values for "type" and "name" are required when updating a policy object
    payload = {"type": policy_type, "name": new_name}

    url = f"{ctx.obj.base_url}/policies/{policy_id}"

    try:
        msg = f'Attempting to rename policy "{original_name}" ({policy_id}) to "{new_name}"'
        LOGGER.info(msg)
        index_event(ctx.obj.es, module=__name__, event_type="INFO", event=msg)
        click.echo(f"[*] {msg}")
        response = ctx.obj.session.put(url, headers=headers, params=params, json=payload, timeout=7)
    except Exception as e:
        LOGGER.error(e, exc_info=True)
        index_event(ctx.obj.es, module=__name__, event_type="ERROR", event=e)
        click.secho(f"[!] {URL_OR_API_TOKEN_ERROR}", fg="red")
        response = None

    if response.ok:
        msg = f'Policy "{original_name}" ({policy_id}) changed to "{new_name}"'
        LOGGER.info(msg)
        index_event(ctx.obj.es, module=__name__, event_type="INFO", event=msg)
        click.secho(f"[*] {msg}", fg="green")
        time.sleep(1)

    else:
        msg = (
            f"Error modifying policy {policy_id}\n"
            f"    Response Code: {response.status_code} | Response Reason: {response.reason}\n"
            f'    Error Code: {response.json().get("errorCode")} | Error Summary: {response.json().get("errorSummary")}'
        )
        LOGGER.error(msg)
        index_event(ctx.obj.es, module=__name__, event_type="ERROR", event=msg)
        click.secho(f"[!] {msg}", fg="red")
