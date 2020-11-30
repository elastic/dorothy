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

# Manage configuration profiles and saved data

import hashlib
import json
import logging.config
import os
from datetime import datetime

import click
from tabulate import tabulate

LOGGER = logging.getLogger(__name__)


def check_saved_data(data_dir):
    """Check size of data directory"""

    dir_size = 0
    files = list(data_dir.rglob("*"))

    for file in files:
        dir_size += os.path.getsize(file)

    dir_size = round(dir_size / 1024 / 1024)

    if dir_size > 100:
        click.secho(
            f"[!] Data directory {data_dir} is over 100 MB. Consider deleting files that are no longer needed", fg="red"
        )


def load_config_profiles(config_dir):
    """Load all configuration profiles from the config dir"""

    # Get a list of all available configuration profiles
    files = list(config_dir.glob("*.json"))

    msg = f"{len(files)} configuration profiles found in directory {config_dir}"
    LOGGER.info(msg)
    click.echo(f"[*] {msg}")

    config_files = []

    # Load all config files that were found
    for file in files:
        with open(file, "r") as f:
            config_files.append(json.load(f))

    config_profiles = []

    # Append tuples to config_profiles ready to print in table
    for index, config in enumerate(config_files):
        config_profiles.append((index + 1, config["description"], config["okta_url"]))

    if config_profiles:
        headers = ["#", "Description", "URL"]
        click.echo(tabulate(config_profiles, headers=headers, tablefmt="pretty"))

    return config_files


def choose_profile(config_files):
    """Show brief info on each Okta environment found in loaded configuration profiles"""

    click.echo("[*] Choose a configuration profile to load. E.g. 1")

    while True:
        choice = click.prompt("[*] Enter the number of the configuration profile to load", type=int)

        if (choice > 0) and (choice <= len(config_files)):
            config = config_files[choice - 1]
            msg = f'Using configuration profile "{config["description"]}" ({config["okta_url"]})'
            LOGGER.info(msg)
            click.secho(f"[*] {msg}", fg="green")

            if not config.get("api_token"):
                click.secho("[!] No API token found in configuration profile", fg="red")
                config["api_token"] = click.prompt(
                    "[*] Enter your Okta API token to execute actions. The input for this value is hidden",
                    hide_input=True,
                ).strip()

            return config
        else:
            click.secho("[!] Invalid choice. Try again", fg="red")


def create_profile(config_dir):
    """Create a new configuration profile for an Okta environment"""

    now = datetime.now()
    profile_id = hashlib.md5(str(now).encode()).hexdigest()
    file_path = config_dir / f"{profile_id}.json"

    click.echo("[*] Creating a new configuration profile")

    description = click.prompt("[*] Enter description for target Okta environment").strip()
    okta_url = click.prompt("[*] Enter URL for target Okta environment. E.g. https://my-company.okta.com").strip()
    api_token = click.prompt(
        "[*] Enter your Okta API token to execute actions. The input for this value is hidden", hide_input=True
    ).strip()

    config = {
        "id": profile_id,
        "description": description,
        # Append /api/v1 to base URL
        "okta_url": okta_url + "/api/v1",
        "api_token": api_token,
    }

    if click.confirm("[*] Do you want to store the API token in the local config file?", default=True):
        with open(file_path, "w") as f:
            json.dump(config, f, indent=4)
    else:
        config_without_token = {
            "id": profile_id,
            "description": description,
            # Append /api/v1 to base URL
            "okta_url": okta_url + "/api/v1",
        }
        with open(file_path, "w") as f:
            json.dump(config_without_token, f, indent=4)

    return config
