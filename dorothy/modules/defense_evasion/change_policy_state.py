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

# Deactivate or activate an Okta policy

import logging.config

import click

from dorothy.core import (
    print_module_info,
    set_module_options,
    reset_module_options,
    check_module_options,
    get_policy_object,
    set_policy_state,
    index_event,
)
from dorothy.modules.defense_evasion.defense_evasion import defense_evasion

LOGGER = logging.getLogger(__name__)
MODULE_DESCRIPTION = "Deactivate or activate an Okta policy"
TACTICS = ["Defense Evasion", "Impact"]

MODULE_OPTIONS = {"id": {"value": None, "required": True, "help": "The unique ID for the policy"}}


@defense_evasion.subshell(name="change-policy-state")
@click.pass_context
def change_policy_state(ctx):
    """Deactivate or activate an Okta policy"""

    # Change prompt depending on name of parent shell
    if ctx.parent.command.name == "impact":
        ctx.command.shell.prompt = "dorothy > impact > change-policy-state > "


@change_policy_state.command()
def info():
    """Show available options and their current values for this module"""

    print_module_info(MODULE_OPTIONS)


@change_policy_state.command()
@click.pass_context
@click.option("--id", help=MODULE_OPTIONS["id"]["help"])
def set(ctx, **kwargs):
    """Set one or more options for this module"""

    if all(value is None for value in kwargs.values()):
        return click.echo(ctx.get_help())

    else:
        global MODULE_OPTIONS
        MODULE_OPTIONS = set_module_options(MODULE_OPTIONS, kwargs)


@change_policy_state.command()
def reset():
    """Reset the options for this module"""

    global MODULE_OPTIONS
    MODULE_OPTIONS = reset_module_options(MODULE_OPTIONS)


@change_policy_state.command()
@click.pass_context
def execute(ctx):
    """Execute this module with the configured options"""

    error = check_module_options(MODULE_OPTIONS)

    if error:
        return

    policy_id = MODULE_OPTIONS["id"]["value"]

    policy = get_policy_object(ctx, policy_id, rules=False)

    if policy:
        if policy["status"] == "ACTIVE":
            click.echo("[*] Policy is ACTIVE")
            if click.confirm(f'[*] Do you want to deactivate policy {policy_id} ({policy["name"]})?', default=True):
                msg = f'Attempting to deactivate policy {policy_id} ({policy["name"]})'
                LOGGER.info(msg)
                index_event(ctx.obj.es, module=__name__, event_type="INFO", event=msg)
                click.echo(f"[*] {msg}")
                set_policy_state(ctx, policy["id"], operation="DEACTIVATE")

        elif policy["status"] == "INACTIVE":
            click.echo("[*] Policy is INACTIVE")
            if click.confirm(f'[*] Do you want to activate policy {policy_id} ({policy["name"]})?', default=True):
                msg = f'Attempting to activate policy {policy_id} ({policy["name"]})'
                LOGGER.info(msg)
                index_event(ctx.obj.es, module=__name__, event_type="INFO", event=msg)
                click.echo(f"[*] {msg}")
                set_policy_state(ctx, policy["id"], operation="ACTIVATE")

        else:
            click.echo(f'[*] Policy status is {policy["status"]}')
