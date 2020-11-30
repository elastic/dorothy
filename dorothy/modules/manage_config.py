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

# Manage Dorothy's configuration profiles

import logging.config
from pathlib import Path

import click
from tabulate import tabulate

from dorothy.config import load_config_profiles, choose_profile, create_profile
from dorothy.core import index_event, setup_elasticsearch_client
from dorothy.main import dorothy_shell

LOGGER = logging.getLogger(__name__)
MODULE_DESCRIPTION = "Manage Dorothy's configuration profiles"
TACTICS = ["-"]


@dorothy_shell.subshell(name="manage-config")
@click.pass_context
def manage_config(ctx):
    """Manage Dorothy's configuration profiles"""
    pass


@manage_config.command()
@click.pass_context
def create_new_profile(ctx):
    """Create a configuration profile"""

    create_profile(ctx.obj.config_dir)
    config_files = load_config_profiles(ctx.obj.config_dir)
    config = choose_profile(config_files)
    es_client = setup_elasticsearch_client(config["okta_url"])

    # Update the Dorothy class object with the values from the chosen configuration profile
    ctx.obj.base_url = config["okta_url"]
    ctx.obj.api_token = config["api_token"]
    ctx.obj.profile_id = config["id"]
    ctx.obj.es_client = es_client
    pass


@manage_config.command()
@click.pass_context
def load_profile(ctx):
    """Load a configuration profile"""

    config_files = load_config_profiles(ctx.obj.config_dir)
    config = choose_profile(config_files)
    es_client = setup_elasticsearch_client(config["okta_url"])

    # Update the Dorothy class object with the values from the chosen configuration profile
    ctx.obj.base_url = config["okta_url"]
    ctx.obj.api_token = config["api_token"]
    ctx.obj.profile_id = config["id"]
    ctx.obj.es_client = es_client


@manage_config.command()
@click.pass_context
def show_current(ctx):
    """Show info on the loaded configuration profiles"""

    headers = ["URL", "Profile ID"]
    profile_info = [(ctx.obj.base_url, ctx.obj.profile_id)]
    click.echo(tabulate(profile_info, headers=headers, tablefmt="pretty"))


@manage_config.command()
@click.pass_context
def delete_profile(ctx):
    """Delete a configuration profile and (optionally) its associated saved data"""

    config_files = load_config_profiles(ctx.obj.config_dir)

    while True:
        choice = click.prompt("[*] Enter the number of the configuration profile to delete", type=int)

        if (choice > 0) and (choice <= len(config_files)):
            config = config_files[choice - 1]

            delete_configuration_profile(ctx, config)

            # Prompt the user to select a configuration profile again in case the current one was just deleted
            config_files = load_config_profiles(ctx.obj.config_dir)

            if config_files:
                if click.confirm(
                    "[*] Do you want to load an existing configuration profile? Answer no to create a new one",
                    default=True,
                ):
                    config = choose_profile(config_files)
                    es_client = setup_elasticsearch_client(config["okta_url"])
                else:
                    config = create_profile(ctx.obj.config_dir)
                    es_client = setup_elasticsearch_client(config["okta_url"])
            else:
                config = create_profile(ctx.obj.config_dir)
                es_client = setup_elasticsearch_client(config["okta_url"])

            # Update the Dorothy class object with the values from the chosen configuration profile
            ctx.obj.base_url = config["okta_url"]
            ctx.obj.api_token = config["api_token"]
            ctx.obj.profile_id = config["id"]
            ctx.obj.es_client = es_client

            return

        else:
            click.secho("[!] Invalid choice. Try again", fg="red")


def delete_configuration_profile(ctx, config):
    msg = f'[*] Do you want to delete the configuration profile for {config["description"]} ({config["okta_url"]})?'

    if click.confirm(msg, default=True):
        file = Path(ctx.obj.config_dir / (config["id"] + ".json"))
        file.unlink()
        msg = f"Configuration file deleted ({file})"
        LOGGER.info(msg)
        index_event(ctx.obj.es, module=__name__, event_type="INFO", event=msg)
        click.secho(f"[*] {msg}", fg="green")

        delete_saved_data(ctx, config["id"])


def delete_saved_data(ctx, profile_id):
    # Get a list of files associated with the configuration profile that was deleted
    files = list(ctx.obj.data_dir.rglob(f"{profile_id}*"))
    if not files:
        click.echo("[*] No associated saved data found for configuration profile")
    else:
        if click.confirm(
            f"[*] Do you want to delete the {len(files)} saved files associated with the " f"configuration profile?",
            default=True,
        ):
            for file in files:
                file.unlink()

                msg = f"File deleted ({file})"
                LOGGER.info(msg)
                index_event(ctx.obj.es, module=__name__, event_type="INFO", event=msg)
                click.secho(f"[*] {msg}", fg="green")
