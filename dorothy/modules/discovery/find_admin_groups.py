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

# Identify Okta groups with admin roles assigned

import logging.config
import time
from pathlib import Path

import click

from dorothy.core import OktaGroup, write_json_file, load_json_file, print_role_info, index_event
from dorothy.modules.discovery.discovery import discovery

LOGGER = logging.getLogger(__name__)
MODULE_DESCRIPTION = "Identify Okta groups with admin roles assigned"
TACTICS = ["Discovery"]


@discovery.subshell(name="find-admin-groups")
@click.pass_context
def find_admin_groups(ctx):
    """Check if any Okta groups have one or more administrator roles assigned.

    Note: Only the SUPER_ADMIN role can view, assign, or remove admin roles.
    """


@find_admin_groups.command()
@click.pass_context
def execute(ctx):
    """Execute this module with the configured options"""

    options = (
        "[*] Available options\n"
        "[1] Load harvested groups from json file and check their assigned roles for administrator "
        "permissions\n"
        "[2] Harvest all groups and check their assigned roles for administrator permissions\n"
        "[0] Exit this menu\n"
        "[*] Choose from the above options"
    )

    while True:
        value = click.prompt(options, type=int)

        if value == 1:
            file_path = Path(
                click.prompt(
                    "[*] Enter full path of file containing harvested Okta groups",
                )
            )

            if file_path.exists():
                msg = f"Attempting to check roles for groups in file, {file_path}"
                LOGGER.info(msg)
                index_event(ctx.obj.es, module=__name__, event_type="INFO", event=msg)
                click.echo(f"[*] {msg}")
                groups = load_json_file(file_path)
                check_assigned_roles(ctx, groups)
                return

            else:
                msg = f"File not found, {file_path}"
                LOGGER.error(msg)
                index_event(ctx.obj.es, module=__name__, event_type="ERROR", event=msg)
                click.secho(f"[!] {msg}", fg="red")

        elif value == 2:
            if click.confirm("[*] Do you want to attempt to harvest information for all groups?", default=True):
                msg = "Attempting to harvest all Okta groups"
                LOGGER.info(msg)
                index_event(ctx.obj.es, module=__name__, event_type="INFO", event=msg)
                click.echo(f"[*] {msg}")
                groups = ctx.obj.okta.get_groups(ctx)
                check_assigned_roles(ctx, groups)
                return

        elif value == 0:
            return

        else:
            click.secho("[!] Invalid option selected", fg="red")


def check_assigned_roles(ctx, groups):
    """Check if any groups have admin roles assigned"""

    admin_groups = []

    msg = (
        f"Checking assigned roles for {len(groups)} groups. This may take a while to avoid exceeding API "
        f"rate limits"
    )
    LOGGER.info(msg)
    index_event(ctx.obj.es, module=__name__, event_type="INFO", event=msg)
    click.echo(f"[*] {msg}")

    # Don't put print statements under click.progressbar otherwise the progress bar will be interrupted
    with click.progressbar(groups, label="[*] Checking groups for admin roles") as groups:
        for okta_group in groups:
            group = OktaGroup(okta_group)
            assigned_roles, error = group.list_roles(ctx, mute=True)

            # Stop trying to check roles if the current API token doesn't have that permission
            if error:
                return

            if assigned_roles:
                admin_group = {"group": group.obj, "roles": assigned_roles}
                admin_groups.append(admin_group)

                for role in assigned_roles:
                    if role["type"] in ctx.obj.admin_roles:
                        msg = f'Group ID {group.obj["id"]} has admin role {role["type"]} assigned'
                        LOGGER.info(msg)
                        index_event(ctx.obj.es, module=__name__, event_type="INFO", event=msg)

            # Sleep for 1s to avoid exceeding API rate limits
            time.sleep(1)

    if admin_groups:
        for group in admin_groups:
            print_role_info(group["group"]["id"], group["roles"], object_type="group")

        msg = f"Found {len(admin_groups)} groups with admin roles assigned"
        LOGGER.info(msg)
        index_event(ctx.obj.es, module=__name__, event_type="INFO", event=msg)
        click.secho(f"[*] {msg}", fg="green")

        file_path = f"{ctx.obj.data_dir}/{ctx.obj.profile_id}_admin_groups"

        if click.confirm("[*] Do you want to save harvested admin group information to a file?", default=True):
            write_json_file(file_path, admin_groups)

    else:
        msg = "No groups found with admin roles assigned"
        LOGGER.info(msg)
        index_event(ctx.obj.es, module=__name__, event_type="INFO", event=msg)
        click.echo(f"[*] {msg}")

    return admin_groups
