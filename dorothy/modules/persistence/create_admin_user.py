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
    assign_admin_role,
    print_module_info,
    set_module_options,
    reset_module_options,
    check_module_options,
    index_event,
)
from dorothy.modules.persistence.persistence import persistence

LOGGER = logging.getLogger(__name__)
MODULE_DESCRIPTION = "Assign an admin role to an Okta user"
TACTICS = ["Persistence"]

MODULE_OPTIONS = {"id": {"value": None, "required": True, "help": "The unique ID for the user"}}


@persistence.subshell(name="create-admin-user")
@click.pass_context
def create_admin_user(ctx):
    """Assign an Okta administrator role to a user.

    Only the SUPER_ADMIN role can view, assign, or remove admin roles for administrators."""


@create_admin_user.command()
def info():
    """Show available options and their current values for this module"""

    print_module_info(MODULE_OPTIONS)


@create_admin_user.command()
@click.pass_context
@click.option("--id", help=MODULE_OPTIONS["id"]["help"])
def set(ctx, **kwargs):
    """Set one or more options for this module"""

    if all(value is None for value in kwargs.values()):
        return click.echo(ctx.get_help())

    else:
        global MODULE_OPTIONS
        MODULE_OPTIONS = set_module_options(MODULE_OPTIONS, kwargs)


@create_admin_user.command()
def reset():
    """Reset the options for this module"""

    global MODULE_OPTIONS
    MODULE_OPTIONS = reset_module_options(MODULE_OPTIONS)


@create_admin_user.command()
@click.pass_context
def execute(ctx):
    """Execute this module with the configured options"""

    error = check_module_options(MODULE_OPTIONS)

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

            assign_admin_role(ctx, user_id, role_type, target="user")

            return

        else:
            click.secho("[!] Invalid option selected", fg="red")
