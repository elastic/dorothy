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
    print_module_info,
    set_module_options,
    reset_module_options,
    check_module_options,
    list_enrolled_factors,
    reset_factor,
    index_event,
)
from dorothy.modules.persistence.persistence import persistence

LOGGER = logging.getLogger(__name__)
MODULE_DESCRIPTION = "Remove a MFA factor for a specified Okta user"
TACTICS = ["Persistence"]

MODULE_OPTIONS = {"id": {"value": None, "required": True, "help": "The unique ID for the user"}}


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

    print_module_info(MODULE_OPTIONS)


@delete_factor.command()
@click.pass_context
@click.option("--id", help=MODULE_OPTIONS["id"]["help"])
def set(ctx, **kwargs):
    """Set one or more options for this module"""

    if all(value is None for value in kwargs.values()):
        return click.echo(ctx.get_help())

    else:
        global MODULE_OPTIONS
        MODULE_OPTIONS = set_module_options(MODULE_OPTIONS, kwargs)


@delete_factor.command()
def reset():
    """Reset the options for this module"""

    global MODULE_OPTIONS
    MODULE_OPTIONS = reset_module_options(MODULE_OPTIONS)


@delete_factor.command()
@click.pass_context
def execute(ctx):
    """Execute this module with the configured options"""

    error = check_module_options(MODULE_OPTIONS)

    if error:
        return

    user_id = MODULE_OPTIONS["id"]["value"]

    enrolled_factors, error = list_enrolled_factors(ctx, user_id)

    if error:
        return

    if not enrolled_factors:
        msg = f"No enrolled MFA factors found for user {user_id}"
        LOGGER.info(msg)
        index_event(ctx.obj.es, module=__name__, event_type="INFO", event=msg)
        click.echo(f"[*] {msg}")
        return

    else:
        msg = f"Found {len(enrolled_factors)} enrolled MFA factors for user {user_id}"
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
                    reset_factor(ctx, user_id, factor_id)
                    return
                else:
                    click.secho("[!] Invalid choice", fg="red")
                    return
            else:
                return
