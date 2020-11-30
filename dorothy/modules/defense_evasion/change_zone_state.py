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

# Deactivate or activate an Okta network zone

import logging.config

import click

from dorothy.core import (
    print_module_info,
    set_module_options,
    reset_module_options,
    check_module_options,
    get_zone_object,
    set_zone_state,
    index_event,
)
from dorothy.modules.defense_evasion.defense_evasion import defense_evasion

LOGGER = logging.getLogger(__name__)
MODULE_DESCRIPTION = "Deactivate or activate an Okta network zone"
TACTICS = ["Defense Evasion", "Impact"]

MODULE_OPTIONS = {"id": {"value": None, "required": True, "help": "The unique ID for the network zone"}}


@defense_evasion.subshell(name="change-zone-state")
@click.pass_context
def change_zone_state(ctx):
    """Deactivate or activate an Okta network zone"""


@change_zone_state.command()
def info():
    """Show available options and their current values for this module"""

    print_module_info(MODULE_OPTIONS)


@change_zone_state.command()
@click.pass_context
@click.option("--id", help=MODULE_OPTIONS["id"]["help"])
def set(ctx, **kwargs):
    """Set one or more options for this module"""

    if all(value is None for value in kwargs.values()):
        return click.echo(ctx.get_help())

    else:
        global MODULE_OPTIONS
        MODULE_OPTIONS = set_module_options(MODULE_OPTIONS, kwargs)


@change_zone_state.command()
def reset():
    """Reset the options for this module"""

    global MODULE_OPTIONS
    MODULE_OPTIONS = reset_module_options(MODULE_OPTIONS)


@change_zone_state.command()
@click.pass_context
def execute(ctx):
    """Execute this module with the configured options"""

    error = check_module_options(MODULE_OPTIONS)

    if error:
        return

    zone_id = MODULE_OPTIONS["id"]["value"]

    zone = get_zone_object(ctx, zone_id)

    if zone:
        if zone["status"] == "ACTIVE":
            click.echo("[*] Zone is ACTIVE")
            if click.confirm(f'[*] Do you want to deactivate zone {zone_id} ({zone["name"]})?', default=True):
                msg = f'Attempting to deactivate zone {zone_id} ({zone["name"]})'
                LOGGER.info(msg)
                index_event(ctx.obj.es, module=__name__, event_type="INFO", event=msg)
                click.echo(f"[*] {msg}")
                set_zone_state(ctx, zone["id"], operation="DEACTIVATE")

        elif zone["status"] == "INACTIVE":
            click.echo("[*] Zone is INACTIVE")
            if click.confirm(f'[*] Do you want to activate zone {zone_id} ({zone["name"]})?', default=True):
                msg = f'Attempting to activate zone {zone_id} ({zone["name"]})'
                LOGGER.info(msg)
                index_event(ctx.obj.es, module=__name__, event_type="INFO", event=msg)
                click.echo(f"[*] {msg}")
                set_zone_state(ctx, zone["id"], operation="ACTIVATE")

        else:
            click.echo(f'[*] Policy status is {zone["status"]}')
