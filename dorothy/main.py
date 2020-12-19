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

# Load shell utility, setup logging, and add commands to main menu

import logging.config
from dataclasses import dataclass
from pathlib import Path

import click
from elasticsearch import Elasticsearch
from requests.sessions import Session

import dorothy.core as core
from dorothy.config import check_saved_data, load_config_profiles, choose_profile, create_profile
from dorothy.core import OktaOrg, setup_session_instance, setup_elasticsearch_client
from dorothy.wrappers import rootshell

BANNER = r"""
██████   ██████  ██████   ██████  ████████ ██   ██ ██    ██ 
██   ██ ██    ██ ██   ██ ██    ██    ██    ██   ██  ██  ██  
██   ██ ██    ██ ██████  ██    ██    ██    ███████   ████  
██   ██ ██    ██ ██   ██ ██    ██    ██    ██   ██    ██  
██████   ██████  ██   ██  ██████     ██    ██   ██    ██ 
"""

ROOT_DIR = Path(__file__).parent
DATA_DIR = Path.home() / "dorothy/data"
CONFIG_DIR = Path.home() / "dorothy/config"

# Reference for admin role types: https://developer.okta.com/docs/reference/api/roles/#role-types
# Reference for comparison of admin role permissions:
# https://help.okta.com/en/prod/Content/Topics/Security/administrators-admin-comparison.htm
ADMIN_ROLES = [
    "API_ACCESS_MANAGEMENT_ADMIN",
    "APP_ADMIN",
    "GROUP_MEMBERSHIP_ADMIN",
    "HELP_DESK_ADMIN",
    "MOBILE_ADMIN",
    "ORG_ADMIN",
    "READ_ONLY_ADMIN",
    "REPORT_ADMIN",
    "SUPER_ADMIN",
    "USER_ADMIN",
]

POLICY_TYPES = ["OKTA_SIGN_ON", "PASSWORD", "MFA_ENROLL", "OAUTH_AUTHORIZATION_POLICY", "IDP_DISCOVERY"]


@dataclass
class Dorothy:
    """
    Data class used to store relevant attributes in an object and pass it between Dorothy's modules
    """

    # Data class for Okta organization
    okta: OktaOrg
    # Base URL for Okta API
    base_url: str
    # Okta API token to use for operations
    api_token: str
    # Local path for Dorothy repo
    root_dir: Path
    # Local path to store harvested data
    data_dir: Path
    # Local path to store configuration files
    config_dir: Path
    # Admin roles as per Okta's documentation
    admin_roles: list
    # Policy types as per Okta's documentation
    policy_types: list
    # Configuration profile ID
    profile_id: str
    # Session instance for HTTP requests
    session: Session
    # Elasticsearch client
    es: Elasticsearch


LOGGER = logging.getLogger(__name__)


@rootshell(
    name="dorothy",
    prompt="dorothy > ",
    intro='Type "help" to get started',
    context_settings={"help_option_names": ["-h", "--help"]},
)
@click.pass_context
# Main entry point for Dorothy CLI
def dorothy_shell(ctx):
    """Set configuration profile for target environment and setup Dorothy CLI"""

    # Documentation on Okta rate limits can be found here: https://developer.okta.com/docs/reference/rate-limits/
    click.secho(message=BANNER, fg="red")
    click.echo("A tool to test security monitoring and detection for Okta environments\n")
    click.echo("Created by David French (@threatpunter) at Elastic\n")
    click.secho("Caution", nl=False, underline=True)
    click.echo(": Dorothy can change the configuration of your Okta environment")
    click.echo(
        "Consider using Dorothy in a test environment to avoid any risk of impacting your production " "environment\n"
    )

    LOGGER.info("Dorothy started")

    for handler in LOGGER.root.handlers:
        if hasattr(handler, "baseFilename"):
            logging_path = handler.baseFilename
            click.echo(f"[*] Logs will be written to {logging_path}")

    check_saved_data(DATA_DIR)

    config_files = load_config_profiles(CONFIG_DIR)

    if config_files:
        if click.confirm(
            "[*] Do you want to load an existing configuration profile? Answer no to create a new one", default=True
        ):
            config = choose_profile(config_files)
        else:
            config = create_profile(CONFIG_DIR)
    else:
        config = create_profile(CONFIG_DIR)

    session = setup_session_instance(config["okta_url"])

    es_client = setup_elasticsearch_client(config["okta_url"])

    ctx.obj = Dorothy(
        okta=OktaOrg(config["api_token"], config["okta_url"]),
        base_url=config["okta_url"],
        api_token=config["api_token"],
        root_dir=ROOT_DIR,
        data_dir=DATA_DIR,
        config_dir=CONFIG_DIR,
        admin_roles=ADMIN_ROLES,
        policy_types=POLICY_TYPES,
        profile_id=config["id"],
        session=session,
        es=es_client,
    )

    click.echo('[*] Consider executing "whoami" to get user information and roles associated with current API token')
    click.echo("""[*] Execute "list-modules" to show all of Dorothy's modules""")


@dorothy_shell.command()
@click.pass_obj
def list_modules(obj):
    """List all of Dorothy's modules"""
    core.list_modules(obj)


@dorothy_shell.command()
@click.pass_context
def whoami(ctx):
    """Get info for user linked with current API token"""
    core.whoami(ctx)


@dorothy_shell.command()
def clear():
    """Clear the terminal screen"""
    click.clear()
