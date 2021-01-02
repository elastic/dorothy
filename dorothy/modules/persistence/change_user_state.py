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

# Change an Okta user's state by executing lifecycle operations

import logging.config

import click

from dorothy.core import (
    Module,
    OktaUser,
    index_event,
)
from dorothy.modules.persistence.persistence import persistence

LOGGER = logging.getLogger(__name__)
MODULE_DESCRIPTION = "Change an Okta user's state by executing lifecycle operations"
TACTICS = ["Persistence", "Impact"]

MODULE_OPTIONS = {"id": {"value": None, "required": True, "help": "The unique ID for the user"}}
MODULE = Module(MODULE_OPTIONS)

LIFECYCLE_OPERATIONS = [
    {"operation": "ACTIVATE", "description": "This operation can only be performed on users with a STAGED status"},
    {
        "operation": "REACTIVATE",
        "description": "This operation can only be performed on users with a PROVISIONED status",
    },
    {
        "operation": "DEACTIVATE",
        "description": "This operation can only be performed on users that do not have a DEPROVISIONED status",
    },
    {"operation": "SUSPEND", "description": "This operation can only be performed on users with an ACTIVE status"},
    {
        "operation": "UNSUSPEND",
        "description": "This operation can only be performed on users that have a SUSPENDED status",
    },
    {
        "operation": "DELETE",
        "description": "Deletes a user permanently. This operation can only be performed on users that have a "
        "DEPROVISIONED status. This action cannot be recovered! ",
    },
    {"operation": "UNLOCK", "description": "Unlocks a user with a LOCKED_OUT status and returns them to ACTIVE status"},
    {
        "operation": "EXPIRE_PASSWORD",
        "description": "This operation transitions the user status to PASSWORD_EXPIRED so that the user is required "
        "to change their password at their next login. ",
    },
]


@persistence.subshell(name="change-user-state")
@click.pass_context
def change_user_state(ctx):
    """Change an Okta user's state by executing lifecycle operations.

    This module executes lifecycle operations on a user object to change its state.

    This module can change the state of a user object to suspend, unsuspend, deactivate, activate, reactivate,
    unlock, expire password, or delete. The user's current status limits what operations are allowed. For
    example, you can't unlock a user that is ACTIVE.

    Reference: https://developer.okta.com/docs/reference/api/users/#lifecycle-operations
    """

    # Change prompt depending on name of parent shell
    if ctx.parent.command.name == "impact":
        ctx.command.shell.prompt = "dorothy > impact > change-user-state > "


@change_user_state.command()
def info():
    """Show available options and their current values for this module"""

    MODULE.print_info()


@change_user_state.command()
@click.pass_context
@click.option("--id", help=MODULE_OPTIONS["id"]["help"])
def set(ctx, **kwargs):
    """Set one or more options for this module"""

    MODULE.set_options(ctx, kwargs)


@change_user_state.command()
def reset():
    """Reset the options for this module"""

    MODULE.reset_options()


@change_user_state.command()
@click.pass_context
def execute(ctx):
    """Execute this module with the configured options"""

    error = MODULE.check_options()

    if error:
        return

    user_id = MODULE_OPTIONS["id"]["value"]

    click.echo("""[*] Attempting to retrieve user's current state""")
    user = ctx.obj.okta.get_user(ctx, user_id)
    if not user:
        return

    click.echo("[*] Available lifecycle operations:")
    for index, operation in enumerate(LIFECYCLE_OPERATIONS):
        click.echo(f'{index + 1}. {operation["operation"]} - {operation["description"]}')

    while True:
        choice = click.prompt("[*] Which state do you want to transition the user to?", type=int)

        if (choice > 0) and (choice <= len(LIFECYCLE_OPERATIONS)):
            lifecycle_operation = LIFECYCLE_OPERATIONS[choice - 1]["operation"]

            msg = f"Attempting to {lifecycle_operation} user ID {user_id}"
            LOGGER.info(msg)
            index_event(ctx.obj.es, module=__name__, event_type="INFO", event=msg)
            click.echo(f"[*] {msg}")

            user = OktaUser({"id": user_id})
            user.execute_lifecycle_operation(ctx, lifecycle_operation)

            return
        else:
            click.secho("[!] Invalid option selected", fg="red")
