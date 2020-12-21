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

# Get an Okta policy and its rules

import logging.config

import click

from dorothy.core import (
    Module,
    OktaPolicy,
    write_json_file,
    index_event,
)
from dorothy.modules.discovery.discovery import discovery

LOGGER = logging.getLogger(__name__)
MODULE_DESCRIPTION = "Get an Okta policy and its rules"
TACTICS = ["Discovery"]

MODULE_OPTIONS = {"id": {"value": None, "required": True, "help": "The unique ID for policy"}}
MODULE = Module(MODULE_OPTIONS)


@discovery.subshell(name="get-policy")
def get_policy():
    """Get an Okta policy and its rules.

    This module gets a policy object and its rules using the policy's ID."""


@get_policy.command()
def info():
    """Show available options and their current values for this module"""

    MODULE.print_info()


@get_policy.command()
@click.pass_context
@click.option("--id", help=MODULE_OPTIONS["id"]["help"])
def set(ctx, **kwargs):
    """Set one or more options for this module"""

    MODULE.set_options(ctx, kwargs)


@get_policy.command()
def reset():
    """Reset the options for this module"""

    MODULE.reset_options()


@get_policy.command()
@click.pass_context
def execute(ctx):
    """Execute this module with the configured options"""

    error = MODULE.check_options()

    if error:
        return

    msg = f'Attempting to get policy object for policy ID {MODULE_OPTIONS["id"]["value"]}'
    LOGGER.info(msg)
    index_event(ctx.obj.es, module=__name__, event_type="INFO", event=msg)
    click.echo(f"[*] {msg}")

    okta_policy = ctx.obj.okta.get_policy(ctx, MODULE_OPTIONS["id"]["value"], rules=True)

    if okta_policy:
        policy = OktaPolicy(okta_policy)
        policy.print_info()
        if click.confirm(
            f"[*] Do you want to save policy {policy.obj['id']} ({policy.obj['name']}) to a file?", default=True
        ):
            file_path = f'{ctx.obj.data_dir}/{ctx.obj.profile_id}_policy_{policy.obj["id"]}'
            write_json_file(file_path, okta_policy)
