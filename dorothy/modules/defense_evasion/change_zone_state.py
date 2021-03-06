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
    Module,
    index_event,
)
from dorothy.modules.defense_evasion.defense_evasion import defense_evasion

LOGGER = logging.getLogger(__name__)
MODULE_DESCRIPTION = "Deactivate or activate an Okta network zone"
TACTICS = ["Defense Evasion", "Impact"]

MODULE_OPTIONS = {"id": {"value": None, "required": True, "help": "The unique ID for the network zone"}}
MODULE = Module(MODULE_OPTIONS)


@defense_evasion.subshell(name="change-zone-state")
@click.pass_context
def change_zone_state(ctx):
    """Deactivate or activate an Okta network zone"""

    # Change prompt depending on name of parent shell
    if ctx.parent.command.name == "impact":
        ctx.command.shell.prompt = "dorothy > impact > change-zone-state > "
    else:
        ctx.command.shell.prompt = "dorothy > defense-evasion > change-zone-state > "


@change_zone_state.command()
def info():
    """Show available options and their current values for this module"""

    MODULE.print_info()


@change_zone_state.command()
@click.pass_context
@click.option("--id", help=MODULE_OPTIONS["id"]["help"])
def set(ctx, **kwargs):
    """Set one or more options for this module"""

    MODULE.set_options(ctx, kwargs)


@change_zone_state.command()
def reset():
    """Reset the options for this module"""

    MODULE.reset_options()


@change_zone_state.command()
@click.pass_context
def execute(ctx):
    """Execute this module with the configured options"""

    error = MODULE.check_options()

    if error:
        return

    zone_id = MODULE_OPTIONS["id"]["value"]

    zone = ctx.obj.okta.get_zone(ctx, zone_id)

    if zone:
        if zone.obj["status"] == "ACTIVE":
            click.echo("[*] Zone is ACTIVE")
            if click.confirm(
                f'[*] Do you want to deactivate zone {zone.obj["id"]} ({zone.obj["name"]})?', default=True
            ):
                msg = f'Attempting to deactivate zone {zone.obj["id"]} ({zone.obj["name"]})'
                LOGGER.info(msg)
                index_event(ctx.obj.es, module=__name__, event_type="INFO", event=msg)
                click.echo(f"[*] {msg}")
                zone.change_state(ctx, operation="DEACTIVATE")

        elif zone.obj["status"] == "INACTIVE":
            click.echo("[*] Zone is INACTIVE")
            if click.confirm(f'[*] Do you want to activate zone {zone.obj["id"]} ({zone.obj["name"]})?', default=True):
                msg = f'Attempting to activate zone {zone.obj["id"]} ({zone.obj["name"]})'
                LOGGER.info(msg)
                index_event(ctx.obj.es, module=__name__, event_type="INFO", event=msg)
                click.echo(f"[*] {msg}")
                zone.change_state(ctx, operation="ACTIVATE")

        else:
            click.echo(f'[*] Zone status is {zone.obj["status"]}')
