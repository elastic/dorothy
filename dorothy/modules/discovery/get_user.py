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

# Get an Okta user's profile info and their group memberships

import logging.config

import click

from dorothy.core import (
    Module,
    index_event,
)
from dorothy.modules.discovery.discovery import discovery

LOGGER = logging.getLogger(__name__)
MODULE_DESCRIPTION = "Get an Okta user's profile info and group memberships"
TACTICS = ["Discovery"]

MODULE_OPTIONS = {"id": {"value": None, "required": True, "help": "The unique ID for the user"}}
MODULE = Module(MODULE_OPTIONS)


@discovery.subshell(name="get-user")
def get_user():
    """Get an Okta user's profile info and group memberships.

    This module gets a user's profile info and their group memberships using the user's ID.
    """


@get_user.command()
def info():
    """Show available options and their current values for this module"""

    MODULE.print_info()


@get_user.command()
@click.pass_context
@click.option("--id", help=MODULE_OPTIONS["id"]["help"])
def set(ctx, **kwargs):
    """Set one or more options for this module"""

    MODULE.set_options(ctx, kwargs)


@get_user.command()
def reset():
    """Reset the options for this module"""

    MODULE.reset_options()


@get_user.command()
@click.pass_context
def execute(ctx):
    """Execute this module with the configured options"""

    error = MODULE.check_options()

    if error:
        return

    msg = f'Attempting to get profile and group memberships for user ID {MODULE_OPTIONS["id"]["value"]}'
    LOGGER.info(msg)
    index_event(ctx.obj.es, module=__name__, event_type="INFO", event=msg)
    click.echo(f"[*] {msg}")

    user = ctx.obj.okta.get_user(ctx, MODULE_OPTIONS["id"]["value"])
    user.get_groups(ctx)
