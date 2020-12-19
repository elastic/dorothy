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

# Assign an admin role to an Okta user

import logging.config

import click

from dorothy.core import (
    Module,
    OktaUser,
    index_event,
)
from dorothy.modules.persistence.persistence import persistence

LOGGER = logging.getLogger(__name__)
MODULE_DESCRIPTION = "Assign an admin role to an Okta user"
TACTICS = ["Persistence"]

MODULE_OPTIONS = {"id": {"value": None, "required": True, "help": "The unique ID for the user"}}
MODULE = Module(MODULE_OPTIONS)


@persistence.subshell(name="create-admin-user")
@click.pass_context
def create_admin_user(ctx):
    """Assign an Okta administrator role to a user.

    Only the SUPER_ADMIN role can view, assign, or remove admin roles for administrators."""


@create_admin_user.command()
def info():
    """Show available options and their current values for this module"""

    MODULE.print_info()


@create_admin_user.command()
@click.pass_context
@click.option("--id", help=MODULE_OPTIONS["id"]["help"])
def set(ctx, **kwargs):
    """Set one or more options for this module"""

    MODULE.set_options(ctx, kwargs)


@create_admin_user.command()
def reset():
    """Reset the options for this module"""

    MODULE.reset_options()


@create_admin_user.command()
@click.pass_context
def execute(ctx):
    """Execute this module with the configured options"""

    error = MODULE.check_options()

    if error:
        return

    admin_roles = ctx.obj.admin_roles
    user_id = MODULE_OPTIONS["id"]["value"]

    click.echo("[*] Available admin roles:")
    for index, role in enumerate(admin_roles):
        click.echo(f"{index + 1}. {role}")

    while True:
        choice = click.prompt("[*] Which admin role do you want to assign to the user?", type=int)

        if (choice > 0) and (choice <= len(admin_roles)):
            role_type = admin_roles[choice - 1]

            msg = f"Attempting to assign admin role, {role_type} to user ID, {user_id}"
            LOGGER.info(msg)
            index_event(ctx.obj.es, module=__name__, event_type="INFO", event=msg)
            click.echo(f"[*] {msg}")

            user = OktaUser({"id": user_id})
            user.assign_admin_role(ctx, role_type)

            return

        else:
            click.secho("[!] Invalid option selected", fg="red")
