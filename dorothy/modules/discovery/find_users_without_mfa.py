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

# Identify Okta users with no MFA factors enrolled

import logging.config
import time
from pathlib import Path

import click

from dorothy.core import OktaUser, write_json_file, load_json_file, index_event
from dorothy.modules.discovery.discovery import discovery

LOGGER = logging.getLogger(__name__)
MODULE_DESCRIPTION = "Identify Okta users with no MFA factors enrolled"
TACTICS = ["Discovery"]


@discovery.subshell(name="find-users-without-mfa")
@click.pass_context
def find_users_without_mfa(ctx):
    """Identify Okta users with no MFA factors enrolled.

    This module enumerates the MFA factors enrolled for each user and identifies users that have no MFA factors
    enrolled.
    """


@find_users_without_mfa.command()
@click.pass_context
def execute(ctx):
    """Execute this module with the configured options"""

    options = (
        "[*] Available options\n"
        "[1] Load harvested users from a json file and check their enrolled MFA factors\n"
        "[2] Harvest all users and check their enrolled MFA factors\n"
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
                msg = f"Attempting to check MFA factors for users in file, {file_path}"
                LOGGER.info(msg)
                index_event(ctx.obj.es, module=__name__, event_type="INFO", event=msg)
                click.echo(f"[*] {msg}")
                users = load_json_file(file_path)
                check_enrolled_factors(ctx, users)
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
                check_enrolled_factors(ctx, users)
                return

        elif value == 0:
            return

        else:
            click.secho("[!] Invalid option selected", fg="red")


def check_enrolled_factors(ctx, users):
    """Check for users that have no MFA factors enrolled"""

    users_without_mfa = []

    msg = (
        f"Checking enrolled MFA factors for {len(users)} users. This may take a while to avoid exceeding API "
        f"rate limits"
    )
    LOGGER.info(msg)
    index_event(ctx.obj.es, module=__name__, event_type="INFO", event=msg)
    click.echo(f"[*] {msg}")

    # Don't put print statements under click.progressbar otherwise the progress bar will be interrupted
    with click.progressbar(users, label="[*] Checking for users without MFA enrolled") as users:
        for okta_user in users:
            user = OktaUser(okta_user)
            factors, error = user.list_enrolled_factors(ctx, mute=True)

            # Stop trying to check enrolled MFA factors if the current API token doesn't have that permission
            if error:
                return

            if not factors:
                users_without_mfa.append(user.obj)

                msg = f'User {user.obj["id"]} does not have any MFA factors enrolled'
                LOGGER.info(msg)
                index_event(ctx.obj.es, module=__name__, event_type="INFO", event=msg)

            # Sleep for 1s to avoid exceeding API rate limits
            time.sleep(1)

    if users_without_mfa:
        msg = f"Found {len(users_without_mfa)} users without any MFA factors enrolled"
        LOGGER.info(msg)
        index_event(ctx.obj.es, module=__name__, event_type="INFO", event=msg)
        click.secho(f"[*] {msg}", fg="green")

        if click.confirm("[*] Do you want to print information for users without MFA?", default=True):
            for user in users_without_mfa:
                okta_user = OktaUser(user)
                okta_user.print_info()

        if click.confirm("[*] Do you want to save users without any MFA factors enrolled to a file?", default=True):
            file_path = f"{ctx.obj.data_dir}/{ctx.obj.profile_id}_users_without_mfa"
            write_json_file(file_path, users_without_mfa)

    else:
        msg = "No users found without any MFA factors enrolled"
        LOGGER.info(msg)
        index_event(ctx.obj.es, module=__name__, event_type="INFO", event=msg)
        click.echo(f"[*] {msg}")

    return users_without_mfa
