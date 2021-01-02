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

# Remove a MFA factor for a specified Okta user

import logging.config

import click
from tabulate import tabulate

from dorothy.core import (
    Module,
    OktaUser,
    index_event,
)
from dorothy.modules.persistence.persistence import persistence

LOGGER = logging.getLogger(__name__)
MODULE_DESCRIPTION = "Remove a MFA factor for a specified Okta user"
TACTICS = ["Persistence"]

MODULE_OPTIONS = {"id": {"value": None, "required": True, "help": "The unique ID for the user"}}
MODULE = Module(MODULE_OPTIONS)


@persistence.subshell(name="delete-factor")
@click.pass_context
def delete_factor(ctx):
    """Remove a MFA factor for a specified Okta user.

    This module attempts to retrieve all MFA factors for the specified user and provides the option to remove a
    factor from the user's profile. Once a factor is deleted, the user has the option to enroll a new factor.
    """


@delete_factor.command()
def info():
    """Show available options and their current values for this module"""

    MODULE.print_info()


@delete_factor.command()
@click.pass_context
@click.option("--id", help=MODULE_OPTIONS["id"]["help"])
def set(ctx, **kwargs):
    """Set one or more options for this module"""

    MODULE.set_options(ctx, kwargs)


@delete_factor.command()
def reset():
    """Reset the options for this module"""

    MODULE.reset_options()


@delete_factor.command()
@click.pass_context
def execute(ctx):
    """Execute this module with the configured options"""

    error = MODULE.check_options()

    if error:
        return

    user = OktaUser({"id": MODULE_OPTIONS["id"]["value"]})
    enrolled_factors, error = user.list_enrolled_factors(ctx)

    if error:
        return

    if not enrolled_factors:
        msg = f'No enrolled MFA factors found for user {user.obj["id"]}'
        LOGGER.info(msg)
        index_event(ctx.obj.es, module=__name__, event_type="INFO", event=msg)
        click.echo(f"[*] {msg}")
        return

    else:
        msg = f'Found {len(enrolled_factors)} enrolled MFA factors for user {user.obj["id"]}'
        LOGGER.info(msg)
        index_event(ctx.obj.es, module=__name__, event_type="INFO", event=msg)
        click.secho(f"[*] {msg}", fg="green")

        # Print the user's enrolled factors
        factors = []
        for index, factor in enumerate(enrolled_factors):
            factors.append(
                (
                    index + 1,
                    factor["id"],
                    factor.get("factorType", "-"),
                    factor.get("provider", "-"),
                    factor.get("vendorName", "-"),
                    factor.get("status", "-"),
                )
            )

        headers = ["#", "Factor ID", "Type", "Provider", "Vendor Name", "Status"]
        click.echo(tabulate(factors, headers=headers, tablefmt="pretty"))

        # Prompt to delete a factor
        while True:
            if click.confirm("[*] Do you want to delete a MFA factor from the user's profile?", default=True):
                choice = click.prompt("[*] Enter the number (#) of the MFA factor to delete", type=int)

                if (choice > 0) and (choice <= len(factors)):
                    factor_id = enrolled_factors[choice - 1]["id"]
                    user.reset_factor(ctx, factor_id)
                    return
                else:
                    click.secho("[!] Invalid choice", fg="red")
                    return
            else:
                return
