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

# Identify Okta users with admin roles assigned

import logging.config
import time
from pathlib import Path

import click

from dorothy.core import (
    OktaUser,
    write_json_file,
    load_json_file,
    print_role_info,
    index_event,
)
from dorothy.modules.discovery.discovery import discovery

LOGGER = logging.getLogger(__name__)
MODULE_DESCRIPTION = "Identify Okta users with admin roles assigned"
TACTICS = ["Discovery"]


@discovery.subshell(name="find-admins")
@click.pass_context
def find_admins(ctx):
    """Check if any Okta users have one or more administrator roles assigned.

    Note: Only the SUPER_ADMIN role can view, assign, or remove admin roles.
    """


@find_admins.command()
@click.pass_context
def execute(ctx):
    """Execute this module with the configured options"""

    """
    Can't I just make an API call to get all users that have a specific role assigned? Good question. There is no
    Okta API yet to get all users that have a specific role assigned to them. It is necessary to enumerate through
    all Okta users and then get the roles assigned to each user
    """

    options = (
        "[*] Available options\n"
        "[1] Load harvested users from json file and check their assigned roles for administrator permissions\n"
        "[2] Harvest all users and check their assigned roles for administrator permissions\n"
        "[0] Exit this menu\n"
        "[*] Choose from the above options"
    )

    while True:
        value = click.prompt(options, type=int)

        if value == 1:
            file_path = Path(
                click.prompt(
                    "[*] Enter full path of file containing harvested Okta users",
                )
            )

            if file_path.exists():
                msg = f"Attempting to check roles for users in file, {file_path}"
                LOGGER.info(msg)
                index_event(ctx.obj.es, module=__name__, event_type="INFO", event=msg)
                click.echo(f"[*] {msg}")
                users = load_json_file(file_path)
                check_assigned_roles(ctx, users)
                return

            else:
                msg = f"File not found, {file_path}"
                LOGGER.error(msg)
                index_event(ctx.obj.es, module=__name__, event_type="ERROR", event=msg)
                click.secho(f"[!] {msg}", fg="red")

        elif value == 2:
            if click.confirm(
                "[*] Do you want to attempt to harvest information for all users? This may take a while "
                "to avoid exceeding API rate limits",
                default=True,
            ):
                msg = "Attempting to harvest all Okta users"
                LOGGER.info(msg)
                index_event(ctx.obj.es, module=__name__, event_type="INFO", event=msg)
                click.echo(f"[*] {msg}")
                users = ctx.obj.okta.get_users(ctx)
                check_assigned_roles(ctx, users)
                return

        elif value == 0:
            return

        else:
            click.secho("[!] Invalid option selected", fg="red")


def check_assigned_roles(ctx, users):
    """Check if any users have admin roles assigned"""

    admin_users = []

    msg = (
        f"Checking assigned roles for {len(users)} users. This may take a while to avoid exceeding API " f"rate limits"
    )
    LOGGER.info(msg)
    index_event(ctx.obj.es, module=__name__, event_type="INFO", event=msg)
    click.echo(f"[*] {msg}")

    # Don't put print statements under click.progressbar otherwise the progress bar will be interrupted
    with click.progressbar(users, label="[*] Checking users for admin roles") as users:
        for okta_user in users:
            user = OktaUser(okta_user)
            assigned_roles, error = user.list_roles(ctx, mute=True)
            # Stop trying to check roles if the current API token doesn't have that permission
            if error:
                return

            if assigned_roles:
                admin_user = {"user": user.obj, "roles": assigned_roles}
                admin_users.append(admin_user)

                for role in assigned_roles:
                    if role["type"] in ctx.obj.admin_roles:
                        msg = f'User ID {user.obj["id"]} has admin role {role["type"]} assigned'
                        LOGGER.info(msg)
                        index_event(ctx.obj.es, module=__name__, event_type="INFO", event=msg)

            # Sleep for 1s to avoid exceeding API rate limits
            time.sleep(1)

    if admin_users:
        for user in admin_users:
            print_role_info(user["user"]["id"], user["roles"], object_type="user")

        msg = f"Found {len(admin_users)} users with admin roles assigned"
        LOGGER.info(msg)
        index_event(ctx.obj.es, module=__name__, event_type="INFO", event=msg)
        click.secho(f"[*] {msg}", fg="green")

        file_path = f"{ctx.obj.data_dir}/{ctx.obj.profile_id}_admin_users"

        if click.confirm("[*] Do you want to save harvested admin user information to a file?", default=True):
            write_json_file(file_path, admin_users)

    else:
        msg = "No users found with admin roles assigned"
        LOGGER.info(msg)
        index_event(ctx.obj.es, module=__name__, event_type="INFO", event=msg)
        click.echo(f"[*] {msg}")

    return admin_users
