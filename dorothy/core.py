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

# Miscellaneous functions used by a number of modules

import hashlib
import json
import logging.config
import time
from datetime import datetime
from importlib import import_module
from dataclasses import dataclass

import click
import requests
import yaml
from elasticsearch import Elasticsearch
from requests.adapters import HTTPAdapter
from tabulate import tabulate

LOGGER = logging.getLogger(__name__)
URL_OR_API_TOKEN_ERROR = "ERROR. Verify that the Okta URL and API token in your configuration profile are correct"


@dataclass
class Module:
    """Dorothy module"""

    module_options: dict

    def print_info(self):
        """Print the module's available options and current values"""

        # Print module options in table format
        headers = ["Option", "Value", "Required", "Description"]
        options = [(k.replace("_", "-"), v["value"], v["required"], v["help"]) for k, v in self.module_options.items()]
        click.echo(tabulate(options, headers=headers, tablefmt="pretty"))

    def set_options(self, ctx, new_options):
        """Set one or more options for the module"""

        if all(value is None for value in new_options.values()):
            return click.echo(ctx.get_help())

        for k, v in new_options.items():
            # Split the provided group id values into a list
            if k == "group_ids" and v:
                v = list(v.strip().split(","))
                self.module_options[k]["value"] = v
            # Only set the option's value if the user entered one to avoid overwriting previous settings
            elif v:
                self.module_options[k]["value"] = v.strip()
            else:
                pass

        return self.module_options

    def reset_options(self):
        """Reset all options for the module"""
        for k, v in self.module_options.items():
            v["value"] = None

        return self.module_options

    def check_options(self):
        """Check the module's configured options for issues"""

        # Check for any required options that are missing
        for k, v in self.module_options.items():
            if v["required"] is True and not v.get("value"):
                click.secho(
                    f'[!] Unable to execute module. Required value not set: {k.replace("_", "-")}. '
                    f"Set required value and try again",
                    fg="red",
                )
                error = True
                return error
            else:
                error = False
                return error


@dataclass
class OktaOrg:
    """Data class for an Okta organization"""

    api_token: str
    base_url: str

    def get_current_user(self, ctx):
        """Get the user linked to the current API token"""

        payload = {}
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f"SSWS {self.api_token}",
        }
        url = f"{self.base_url}/users/me"

        try:
            response = ctx.obj.session.get(url, headers=headers, data=payload, timeout=7)
        except Exception as e:
            LOGGER.error(e, exc_info=True)
            index_event(ctx.obj.es, module=__name__, event_type="ERROR", event=e)
            click.secho(f"[!] {URL_OR_API_TOKEN_ERROR}", fg="red")
            response = None

        if not response.ok:
            msg = (
                f"Error retrieving user information\n"
                f"    Response Code: {response.status_code} | Response Reason: {response.reason}\n"
                f'    Error Code: {response.json().get("errorCode")} | Error Summary: {response.json().get("errorSummary")}'
            )
            LOGGER.error(msg)
            index_event(ctx.obj.es, module=__name__, event_type="ERROR", event=msg)
            click.secho(f"[!] {msg}", fg="red")
            return

        if response.ok:
            user = OktaUser(response.json())
            user.print_info()
            return user

    def get_user(self, ctx, user_id):
        """Get a user from the Okta environment using the user's ID"""

        payload = {}
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f"SSWS {self.api_token}",
        }

        url = f"{self.base_url}/users/{user_id}"

        try:
            response = ctx.obj.session.get(url, headers=headers, data=payload, timeout=7)
        except Exception as e:
            LOGGER.error(e, exc_info=True)
            index_event(ctx.obj.es, module=__name__, event_type="ERROR", event=e)
            click.secho(f"[!] {URL_OR_API_TOKEN_ERROR}", fg="red")
            response = None

        if not response.ok:
            msg = (
                f"Error retrieving user information\n"
                f"    Response Code: {response.status_code} | Response Reason: {response.reason}\n"
                f'    Error Code: {response.json().get("errorCode")} | Error Summary: {response.json().get("errorSummary")}'
            )
            LOGGER.error(msg)
            index_event(ctx.obj.es, module=__name__, event_type="ERROR", event=msg)
            click.secho(f"[!] {msg}", fg="red")
            click.echo("[*] This error is expected if the user object was deleted")
            user = None
            return user

        if response.ok:
            user = OktaUser(response.json())
            user.print_info()
            return user

    def get_users(self, ctx, query=None, search_filter=None, search=None):
        """Get all users from the Okta environment with pagination in most cases

        If no parameters are provided, all users that do not have a status of DEPROVISIONED are listed
        """

        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f"SSWS {self.api_token}",
        }
        # Default 'limit' value (number of results returned) is 200
        params = {}
        payload = {}

        url = f"{self.base_url}/users"

        next_page = 1
        harvested_users = []

        while next_page:
            try:
                response = ctx.obj.session.get(url, headers=headers, params=params, data=payload, timeout=7)
            except Exception as e:
                LOGGER.error(e, exc_info=True)
                index_event(ctx.obj.es, module=__name__, event_type="ERROR", event=e)
                click.secho(f"[!] {URL_OR_API_TOKEN_ERROR}", fg="red")
                response = None

            if response.ok:
                msg = f"Retrieved information for {len(response.json())} users"
                LOGGER.info(msg)
                index_event(ctx.obj.es, module=__name__, event_type="INFO", event=msg)
                click.secho(f"[*] {msg}", fg="green")
            else:
                msg = (
                    f"Error retrieving users\n"
                    f"    Response Code: {response.status_code} | Response Reason: {response.reason}\n"
                    f'    Error Code: {response.json().get("errorCode")} | '
                    f'Error Summary: {response.json().get("errorSummary")}'
                )
                LOGGER.error(msg)
                index_event(ctx.obj.es, module=__name__, event_type="ERROR", event=msg)
                click.secho(f"[!] {msg}", fg="red")
                return

            users = response.json()
            links = response.links

            harvested_users.extend(users)
            time.sleep(1)

            if links.get("next"):
                next_page = links["next"]["url"]
                url = next_page
            else:
                next_page = None
                click.echo("[*] No more users found")

        if harvested_users:
            msg = f"Total users harvested: {len(harvested_users)}"
            LOGGER.info(msg)
            index_event(ctx.obj.es, module=__name__, event_type="INFO", event=msg)
            click.echo(f"[*] {msg}")

            if click.confirm("[*] Do you want to print harvested user information?", default=True):
                for okta_user in harvested_users:
                    user = OktaUser(okta_user)
                    user.print_info()

            if click.confirm("[*] Do you want to save harvested user information to a file?", default=True):
                file_path = f"{ctx.obj.data_dir}/{ctx.obj.profile_id}_harvested_users"
                write_json_file(file_path, harvested_users)

        return harvested_users

    def get_groups(self, ctx):
        """Get all groups from the Okta environment"""

        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f"SSWS {self.api_token}",
        }

        params = {}
        payload = {}

        url = f"{self.base_url}/groups"

        next_page = 1
        harvested_groups = []

        while next_page:
            try:
                response = ctx.obj.session.get(url, headers=headers, params=params, data=payload, timeout=7)
            except Exception as e:
                LOGGER.error(e, exc_info=True)
                index_event(ctx.obj.es, module=__name__, event_type="ERROR", event=e)
                click.secho(f"[!] {URL_OR_API_TOKEN_ERROR}", fg="red")
                response = None

            if response.ok:
                msg = f"Retrieved information for {len(response.json())} groups"
                LOGGER.info(msg)
                index_event(ctx.obj.es, module=__name__, event_type="INFO", event=msg)
                click.secho(f"[*] {msg}", fg="green")
            else:
                msg = (
                    f"Error retrieving groups\n"
                    f"    Response Code: {response.status_code} | Response Reason: {response.reason}\n"
                    f'    Error Code: {response.json().get("errorCode")} | '
                    f'Error Summary: {response.json().get("errorSummary")}'
                )
                LOGGER.error(msg),
                index_event(ctx.obj.es, module=__name__, event_type="ERROR", event=msg)
                click.secho(f"[!] {msg}", fg="red")
                return

            groups = response.json()
            links = response.links

            harvested_groups.extend(groups)
            time.sleep(1)

            if links.get("next"):
                next_page = links["next"]["url"]
                url = next_page
            else:
                next_page = None
                click.echo("[*] No more groups found")

        if harvested_groups:
            msg = f"Total groups harvested: {len(harvested_groups)}"
            LOGGER.info(msg)
            index_event(ctx.obj.es, module=__name__, event_type="INFO", event=msg)
            click.echo(f"[*] {msg}")

            if click.confirm("[*] Do you want to print harvested group information?", default=True):
                for okta_group in harvested_groups:
                    group = OktaGroup(okta_group)
                    group.print_info()

            if click.confirm("[*] Do you want to save harvested group information to a file?", default=True):
                file_path = f"{ctx.obj.data_dir}/{ctx.obj.profile_id}_harvested_groups"
                write_json_file(file_path, harvested_groups)

        return harvested_groups

    def get_policies_by_type(self, ctx, policy_type):
        """Get all policies from the Okta environment by type"""

        msg = f"Attempting to get policies with policy type, {policy_type}"
        LOGGER.info(msg)
        index_event(ctx.obj.es, module=__name__, event_type="INFO", event=msg)
        click.echo(f"[*] {msg}")

        harvested_policies = []

        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f"SSWS {self.api_token}",
        }

        params = {"type": policy_type}
        payload = {}

        url = f"{self.base_url}/policies"

        try:
            response = ctx.obj.session.get(url, headers=headers, params=params, data=payload, timeout=7)
        except Exception as e:
            LOGGER.error(e, exc_info=True)
            index_event(ctx.obj.es, module=__name__, event_type="ERROR", event=e)
            click.secho(f"[!] {URL_OR_API_TOKEN_ERROR}", fg="red")
            response = None

        if response.ok:
            msg = f"Retrieved {len(response.json())} policies with policy type, {policy_type}"
            LOGGER.info(msg)
            index_event(ctx.obj.es, module=__name__, event_type="INFO", event=msg)
            click.secho(f"[*] {msg}", fg="green")

            for policy in response.json():
                harvested_policies.append(policy)

        else:
            msg = (
                f"Error retrieving policies for policy type, {policy_type}\n"
                f"    Response Code: {response.status_code} | Response Reason: {response.reason}\n"
                f'    Error Code: {response.json().get("errorCode")} | '
                f'Error Summary: {response.json().get("errorSummary")}'
            )
            LOGGER.error(msg)
            index_event(ctx.obj.es, module=__name__, event_type="ERROR", event=msg)
            click.secho(f"[!] {msg}", fg="red")

            return

        if not harvested_policies:
            msg = "No policies found"
            LOGGER.info(msg)
            index_event(ctx.obj.es, module=__name__, event_type="INFO", event=msg)
            click.echo(f"[*] {msg}")

        return harvested_policies

    def get_policy(self, ctx, policy_id, rules=False):
        """Get a policy object and optionally, its rules"""

        if rules:
            msg = f"Attempting to get policy and policy rules for policy {policy_id}"
            LOGGER.info(msg)
            index_event(ctx.obj.es, module=__name__, event_type="INFO", event=msg)
            click.echo(f"[*] {msg}")
        else:
            msg = f"Attempting to get policy {policy_id}"
            LOGGER.info(msg)
            index_event(ctx.obj.es, module=__name__, event_type="INFO", event=msg)
            click.echo(f"[*] {msg}")

        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f"SSWS {self.api_token}",
        }

        """
        The expand=rules query parameter returns up to twenty Rules for the specified Policy. If the Policy has more
        than 20 Rules, this request returns an error.

        Reference: https://developer.okta.com/docs/reference/api/policy/#get-a-policy-with-rules
        """
        if rules:
            params = {"expand": "rules"}
        else:
            params = {}

        payload = {}
        url = f"{self.base_url}/policies/{policy_id}"

        try:
            response = ctx.obj.session.get(url, headers=headers, params=params, data=payload, timeout=7)
        except Exception as e:
            LOGGER.error(e, exc_info=True)
            index_event(ctx.obj.es, module=__name__, event_type="ERROR", event=e)
            click.secho(f"[!] {URL_OR_API_TOKEN_ERROR}", fg="red")
            response = None

        if response.ok:
            policy = response.json()

            if rules:
                msg = (
                    f'Retrieved policy ID {policy_id} ({policy["name"]}) with {len(policy["_embedded"]["rules"])} rules'
                )
            else:
                msg = f'Retrieved policy ID {policy_id} ({policy["name"]})'
            LOGGER.info(msg)
            index_event(ctx.obj.es, module=__name__, event_type="INFO", event=msg)
            click.secho(f"[*] {msg}", fg="green")

            return policy

        else:
            msg = (
                f"Error retrieving policy {policy_id})\n"
                f"    Response Code: {response.status_code} | Response Reason: {response.reason}\n"
                f'    Error Code: {response.json().get("errorCode")} | '
                f'Error Summary: {response.json().get("errorSummary")}'
            )
            LOGGER.error(msg)
            index_event(ctx.obj.es, module=__name__, event_type="ERROR", event=msg)
            click.secho(f"[!] {msg}", fg="red")
            click.secho(
                "[!] The policy might have more than the maximum (20) number of rules that can be retrieved", fg="red"
            )

    def get_policy_rule(self, ctx, policy_id, rule_id):
        """Get a policy rule object using the policy ID and rule ID"""

        msg = f"Attempting to get policy rule {rule_id} from policy {policy_id}"
        LOGGER.info(msg)
        index_event(ctx.obj.es, module=__name__, event_type="INFO", event=msg)
        click.echo(f"[*] {msg}")

        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f"SSWS {self.api_token}",
        }

        params = {}
        payload = {}

        url = f"{self.base_url}/policies/{policy_id}/rules/{rule_id}"

        try:
            response = ctx.obj.session.get(url, headers=headers, params=params, data=payload, timeout=7)
        except Exception as e:
            LOGGER.error(e, exc_info=True)
            index_event(ctx.obj.es, module=__name__, event_type="ERROR", event=e)
            click.secho(f"[!] {URL_OR_API_TOKEN_ERROR}", fg="red")
            response = None

        if response.ok:
            msg = f"Retrieved policy rule {rule_id} from policy {policy_id}"
            LOGGER.info(msg)
            index_event(ctx.obj.es, module=__name__, event_type="INFO", event=msg)
            click.secho(f"[*] {msg}", fg="green")

            rule = response.json()

            OktaPolicyRule(rule).print_info()

            return rule

        else:
            msg = (
                f"Error retrieving rule, {policy_id}\n"
                f"    Response Code: {response.status_code} | Response Reason: {response.reason}\n"
                f'    Error Code: {response.json().get("errorCode")} | '
                f'Error Summary: {response.json().get("errorSummary")}'
            )
            LOGGER.error(msg)
            index_event(ctx.obj.es, module=__name__, event_type="ERROR", event=msg)
            click.secho(f"[!] {msg}", fg="red")

    def get_zones(self, ctx):
        """Get all network zones from the Okta environment"""

        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f"SSWS {self.api_token}",
        }

        params = {}
        payload = {}

        url = f"{self.base_url}/zones"

        next_page = 1
        harvested_zones = []

        while next_page:
            try:
                response = ctx.obj.session.get(url, headers=headers, params=params, data=payload, timeout=7)
            except Exception as e:
                LOGGER.error(e, exc_info=True)
                index_event(ctx.obj.es, module=__name__, event_type="ERROR", event=e)
                click.secho(f"[!] {URL_OR_API_TOKEN_ERROR}", fg="red")
                response = None

            if response.ok:
                msg = f"Retrieved information for {len(response.json())} zones"
                LOGGER.info(msg)
                index_event(ctx.obj.es, module=__name__, event_type="INFO", event=msg)
                click.secho(f"[*] {msg}", fg="green")
            else:
                msg = (
                    f"Error retrieving zones\n"
                    f"    Response Code: {response.status_code} | Response Reason: {response.reason}\n"
                    f'    Error Code: {response.json().get("errorCode")} | '
                    f'Error Summary: {response.json().get("errorSummary")}'
                )
                LOGGER.error(msg)
                index_event(ctx.obj.es, module=__name__, event_type="ERROR", event=msg)
                click.secho(f"[!] {msg}", fg="red")
                return

            zones = response.json()
            links = response.links

            harvested_zones.extend(zones)
            time.sleep(1)

            if links.get("next"):
                next_page = links["next"]["url"]
                url = next_page
            else:
                next_page = None
                click.echo("[*] No more zones found")

        if harvested_zones:
            msg = f"Total zones harvested: {len(harvested_zones)}"
            LOGGER.info(msg)
            index_event(ctx.obj.es, module=__name__, event_type="INFO", event=msg)
            click.secho(f"[*] {msg}", fg="green")

            file_path = f"{ctx.obj.data_dir}/{ctx.obj.profile_id}_harvested_zones"

            if click.confirm("[*] Do you want to print harvested network zone information?", default=True):
                for okta_zone in harvested_zones:
                    zone = OktaZone(okta_zone)
                    zone.print_info()

            if click.confirm("[*] Do you want to save harvested network zone information to a file?", default=True):
                write_json_file(file_path, harvested_zones)

        return harvested_zones

    def get_zone(self, ctx, zone_id):
        """Get a network zone from the Okta environment"""

        msg = f"Attempting to get network zone {zone_id}"
        LOGGER.info(msg)
        index_event(ctx.obj.es, module=__name__, event_type="INFO", event=msg)
        click.echo(f"[*] {msg}")

        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f"SSWS {self.api_token}",
        }

        params = {}
        payload = {}

        url = f"{self.base_url}/zones/{zone_id}"

        try:
            response = ctx.obj.session.get(url, headers=headers, params=params, data=payload, timeout=7)
        except Exception as e:
            LOGGER.error(e, exc_info=True)
            index_event(ctx.obj.es, module=__name__, event_type="ERROR", event=e)
            click.secho(f"[!] {URL_OR_API_TOKEN_ERROR}", fg="red")
            response = None

        if response.ok:
            msg = f"Retrieved zone {zone_id}"
            LOGGER.info(msg)
            index_event(ctx.obj.es, module=__name__, event_type="INFO", event=msg)
            click.secho(f"[*] {msg}", fg="green")

            zone = OktaZone(response.json())

            zone.print_info()

            return zone

        else:
            msg = (
                f"Error retrieving zone {zone_id}\n"
                f"    Response Code: {response.status_code} | Response Reason: {response.reason}\n"
                f'    Error Code: {response.json().get("errorCode")} | '
                f'Error Summary: {response.json().get("errorSummary")}'
            )
            LOGGER.error(msg)
            index_event(ctx.obj.es, module=__name__, event_type="ERROR", event=msg)
            click.secho(f"[!] {msg}", fg="red")

    def get_apps(self, ctx):
        """Get all applications from the Okta environment"""

        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f"SSWS {self.api_token}",
        }

        params = {}
        payload = {}

        url = f"{self.base_url}/apps"

        next_page = 1
        harvested_apps = []

        while next_page:
            try:
                response = ctx.obj.session.get(url, headers=headers, params=params, data=payload, timeout=7)
            except Exception as e:
                LOGGER.error(e, exc_info=True)
                index_event(ctx.obj.es, module=__name__, event_type="ERROR", event=e)
                click.secho(f"[!] {URL_OR_API_TOKEN_ERROR}", fg="red")
                response = None

            if response.ok:
                msg = f"Retrieved information for {len(response.json())} applications"
                LOGGER.info(msg)
                index_event(ctx.obj.es, module=__name__, event_type="INFO", event=msg)
                click.secho(f"[*] {msg}", fg="green")
            else:
                msg = (
                    f"Error retrieving applications\n"
                    f"    Response Code: {response.status_code} | Response Reason: {response.reason}\n"
                    f'    Error Code: {response.json().get("errorCode")} | '
                    f'Error Summary: {response.json().get("errorSummary")}'
                )
                LOGGER.error(msg)
                index_event(ctx.obj.es, module=__name__, event_type="ERROR", event=msg)
                click.secho(f"[!] {msg}", fg="red")
                return

            apps = response.json()
            links = response.links

            harvested_apps.extend(apps)
            time.sleep(1)

            if links.get("next"):
                next_page = links["next"]["url"]
                url = next_page
            else:
                next_page = None
                click.echo("[*] No more applications found")

        if harvested_apps:
            msg = f"Total applications harvested: {len(harvested_apps)}"
            LOGGER.info(msg)
            index_event(ctx.obj.es, module=__name__, event_type="INFO", event=msg)
            click.secho(f"[*] {msg}", fg="green")

            if click.confirm("[*] Do you want to print harvested application info?", default=True):
                for okta_app in harvested_apps:
                    app = OktaApp(okta_app)
                    app.print_info()

            if click.confirm("[*] Do you want to save harvested applications information to a file?", default=True):
                file_path = f"{ctx.obj.data_dir}/{ctx.obj.profile_id}_harvested_apps"
                write_json_file(file_path, harvested_apps)

        return harvested_apps

    def get_app(self, ctx, app_id):
        """Get an Okta application object from the Okta environment using its unique ID"""

        msg = f"Attempting to get application {app_id}"
        LOGGER.info(msg)
        index_event(ctx.obj.es, module=__name__, event_type="INFO", event=msg)
        click.echo(f"[*] {msg}")

        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f"SSWS {self.api_token}",
        }

        params = {}
        payload = {}

        url = f"{self.base_url}/apps/{app_id}"

        try:
            response = ctx.obj.session.get(url, headers=headers, params=params, data=payload, timeout=7)
        except Exception as e:
            LOGGER.error(e, exc_info=True)
            index_event(ctx.obj.es, module=__name__, event_type="ERROR", event=e)
            click.secho(f"[!] {URL_OR_API_TOKEN_ERROR}", fg="red")
            response = None

        if response.ok:
            msg = f"Retrieved application {app_id}"
            LOGGER.info(msg)
            index_event(ctx.obj.es, module=__name__, event_type="INFO", event=msg)
            click.secho(f"[*] {msg}", fg="green")

            app = OktaApp(response.json())

            app.print_info()

            return app

        else:
            msg = (
                f"Error retrieving app {app_id}\n"
                f"    Response Code: {response.status_code} | Response Reason: {response.reason}\n"
                f'    Error Code: {response.json().get("errorCode")} | '
                f'Error Summary: {response.json().get("errorSummary")}'
            )
            LOGGER.error(msg)
            index_event(ctx.obj.es, module=__name__, event_type="ERROR", event=msg)
            click.secho(f"[!] {msg}", fg="red")


@dataclass
class OktaUser:
    """Data class for an Okta user"""

    obj: dict

    def print_info(self):
        """Print basic info for the Okta user"""

        click.echo(f'[*] User information for ID {self.obj.get("id")}, login {self.obj["profile"].get("login")}:')
        click.echo(
            f'    ID: {self.obj.get("id", "unknown")}\n'
            f'    Status: {self.obj.get("status", "unknown")}\n'
            f'    Login: {self.obj["profile"].get("login", "unknown")}\n'
            f'    Last login: {self.obj.get("lastLogin", "unknown")}\n'
            f'    Last password change: {self.obj.get("passwordChanged", "unknown")}'
        )

    def get_groups(self, ctx):
        """Get the user's group memberships"""

        payload = {}
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f"SSWS {ctx.obj.api_token}",
        }

        url = f"{ctx.obj.base_url}/users/{self.obj['id']}/groups"

        msg = f"Attempting to get group memberships for user ID {self.obj['id']}"
        LOGGER.info(msg)
        index_event(ctx.obj.es, module=__name__, event_type="INFO", event=msg)
        click.echo(f"[*] {msg}")

        try:
            response = ctx.obj.session.get(url, headers=headers, data=payload, timeout=7)
        except Exception as e:
            LOGGER.error(e, exc_info=True)
            index_event(ctx.obj.es, module=__name__, event_type="ERROR", event=msg)
            click.secho(f"[!] {URL_OR_API_TOKEN_ERROR}", fg="red")
            response = None

        if not response.ok:
            msg = (
                f"""Error retrieving user's group memberships\n"""
                f"    Response Code: {response.status_code} | Response Reason: {response.reason}\n"
                f'    Error Code: {response.json().get("errorCode")} | Error Summary: {response.json().get("errorSummary")}'
            )
            LOGGER.error(msg)
            index_event(ctx.obj.es, module=__name__, event_type="ERROR", event=msg)
            click.secho(f"[!] {msg}", fg="red")
            return

        groups = []

        if response.ok:
            groups = response.json()

        if groups:
            click.echo(f"[*] Group memberships for user ID {self.obj['id']}:")
            for okta_group in groups:
                group = OktaGroup(okta_group)
                group.print_info()

        return groups

    def list_roles(self, ctx, mute=False):
        """List the admin roles assigned to the user"""
        assigned_roles, error = list_assigned_roles(ctx, self.obj["id"], object_type="user", mute=mute)
        return assigned_roles, error

    def assign_admin_role(self, ctx, role_type):
        """Assign an admin role to the user"""
        assign_admin_role(ctx, self.obj["id"], role_type, target="user")

    def execute_lifecycle_operation(self, ctx, operation):
        """Execute a lifecycle operation on the user object to change its state"""

        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f"SSWS {ctx.obj.api_token}",
        }

        # Set sendEmail to False. The default value for sendEmail is True, which will send the one-time token to the
        # target user
        if click.confirm("[*] Do you want to send an email notification to the user/administrator?", default=False):
            params = {}
        else:
            params = {"sendEmail": "False"}
        payload = {}

        try:
            if operation == "DELETE":
                url = f'{ctx.obj.base_url}/users/{self.obj["id"]}'
                response = ctx.obj.session.delete(url, headers=headers, params=params, json=payload, timeout=7)
            else:
                url = f'{ctx.obj.base_url}/users/{self.obj["id"]}/lifecycle/{operation.lower()}'
                response = ctx.obj.session.post(url, headers=headers, params=params, json=payload, timeout=7)
        except Exception as e:
            LOGGER.error(e, exc_info=True)
            index_event(ctx.obj.es, module=__name__, event_type="ERROR", event=e)
            click.secho(f"[!] {URL_OR_API_TOKEN_ERROR}", fg="red")
            response = None

        if response.ok:
            msg = f'Operation {operation} executed on user ID {self.obj["id"]}'
            LOGGER.info(msg)
            index_event(ctx.obj.es, module=__name__, event_type="INFO", event=msg)
            click.secho(f"[*] {msg}", fg="green")

            ctx.obj.okta.get_user(ctx, self.obj["id"])

        else:
            msg = (
                f'Error executing {operation} on user ID {self.obj["id"]}\n'
                f"    Response Code: {response.status_code} | Response Reason: {response.reason}\n"
                f'    Error Code: {response.json().get("errorCode")} | Error Summary: {response.json().get("errorSummary")}'
            )
            LOGGER.error(msg)
            index_event(ctx.obj.es, module=__name__, event_type="ERROR", event=msg)
            click.secho(f"[!] {msg}", fg="red")

            ctx.obj.okta.get_user(ctx, self.obj["id"])

            return

    def list_enrolled_factors(self, ctx, mute=False):
        """List the user's enrolled MFA factors"""

        payload = {}
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f"SSWS {ctx.obj.api_token}",
        }

        url = f'{ctx.obj.base_url}/users/{self.obj["id"]}/factors'

        msg = f'Attempting to get enrolled MFA factors for user {self.obj["id"]}'
        LOGGER.info(msg)
        index_event(ctx.obj.es, module=__name__, event_type="INFO", event=msg)
        if not mute:
            click.echo(f"[*] {msg}")

        enrolled_factors = []
        error = False

        try:
            response = ctx.obj.session.get(url, headers=headers, data=payload, timeout=7)
        except Exception as e:
            LOGGER.error(e, exc_info=True)
            index_event(ctx.obj.es, module=__name__, event_type="ERROR", event=e)
            click.secho(f"[!] {URL_OR_API_TOKEN_ERROR}", fg="red")
            response = None

        if not response.ok:
            msg = (
                f'Error retrieving enrolled MFA factors for user {self.obj["id"]}\n'
                f"    Response Code: {response.status_code} | Response Reason: {response.reason}\n"
                f'    Error Code: {response.json().get("errorCode")} | Error Summary: {response.json().get("errorSummary")}'
            )
            LOGGER.error(msg)
            index_event(ctx.obj.es, module=__name__, event_type="ERROR", event=msg)
            click.secho(f"[!] {msg}", fg="red")
            error = True
            return enrolled_factors, error

        if response.ok:
            enrolled_factors = response.json()

        return enrolled_factors, error

    def reset_factor(self, ctx, factor_id):
        """Delete an enrolled MFA factor for the user"""

        payload = {}
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f"SSWS {ctx.obj.api_token}",
        }

        url = f'{ctx.obj.base_url}/users/{self.obj["id"]}/factors/{factor_id}'

        msg = f'Attempting to delete enrolled MFA factor {factor_id} for user {self.obj["id"]}'
        LOGGER.info(msg)
        index_event(ctx.obj.es, module=__name__, event_type="INFO", event=msg)
        click.echo(f"[*] {msg}")

        try:
            response = ctx.obj.session.delete(url, headers=headers, data=payload, timeout=7)
        except Exception as e:
            LOGGER.error(e, exc_info=True)
            index_event(ctx.obj.es, module=__name__, event_type="ERROR", event=e)
            click.secho(f"[!] {URL_OR_API_TOKEN_ERROR}", fg="red")
            response = None

        if not response.ok:
            msg = (
                f'Error deleting MFA factor {factor_id} for user {self.obj["id"]}\n'
                f"    Response Code: {response.status_code} | Response Reason: {response.reason}\n"
                f'    Error Code: {response.json().get("errorCode")} | Error Summary: {response.json().get("errorSummary")}'
            )
            LOGGER.error(msg)
            index_event(ctx.obj.es, module=__name__, event_type="ERROR", event=msg)
            click.secho(f"[!] {msg}", fg="red")
            return

        if response.ok:
            msg = f'MFA factor {factor_id} deleted for user {self.obj["id"]}'
            LOGGER.info(msg)
            index_event(ctx.obj.es, module=__name__, event_type="INFO", event=msg)
            click.secho(f"[*] {msg}", fg="green")


@dataclass
class OktaGroup:
    """Data class for an Okta group"""

    obj: dict

    def print_info(self):
        """Print basic info for the Okta group"""

        click.echo(
            f'    Group ID: {self.obj.get("id", "unknown")}\n'
            f'    Type: {self.obj.get("type", "unknown")}\n'
            f'    Name: {self.obj["profile"].get("name", "unknown")}\n'
            f'    Description: {self.obj["profile"].get("description", "unknown")}'
        )

    def list_roles(self, ctx, mute=False):
        """List the admin roles assigned to the group"""

        assigned_roles, error = list_assigned_roles(ctx, self.obj["id"], object_type="group", mute=mute)
        return assigned_roles, error

    def assign_admin_role(self, ctx, role_type):
        """Assign an admin role to the user"""

        assign_admin_role(ctx, self.obj["id"], role_type, target="group")


@dataclass
class OktaZone:
    """Data class for an Okta network zone"""

    obj: dict

    def print_info(self):
        """Print basic info for the Okta network zone"""

        click.echo(f'[*] Information for network zone ID {self.obj.get("id")} ({self.obj.get("name")}):')
        click.echo(
            f'    Status: {self.obj.get("status", "unknown")}\n'
            f'    Created: {self.obj.get("created", "unknown")}\n'
            f'    Last Updated: {self.obj.get("lastUpdated", "unknown")}'
        )

    def change_state(self, ctx, operation):
        """Activate or deactivate the Okta network"""

        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f"SSWS {ctx.obj.api_token}",
        }

        params = {}
        payload = {}

        url = f'{ctx.obj.base_url}/zones/{self.obj["id"]}/lifecycle/{operation.lower()}'

        try:
            response = ctx.obj.session.post(url, headers=headers, params=params, json=payload, timeout=7)
            time.sleep(1)
        except Exception as e:
            LOGGER.error(e, exc_info=True)
            index_event(ctx.obj.es, module=__name__, event_type="ERROR", event=e)
            click.secho(f"[!] {URL_OR_API_TOKEN_ERROR}", fg="red")
            response = None

        if response.ok:
            msg = f'Zone {self.obj["id"]} {operation.lower()}d'
            LOGGER.info(msg)
            index_event(ctx.obj.es, module=__name__, event_type="INFO", event=msg)
            click.secho(f"[*] {msg}", fg="green")

            ctx.obj.okta.get_zone(ctx, self.obj["id"])

        else:
            msg = (
                f'Error executing {operation} for zone {self.obj["id"]}\n'
                f"    Response Code: {response.status_code} | Response Reason: {response.reason}\n"
                f'    Error Code: {response.json().get("errorCode")} | Error Summary: {response.json().get("errorSummary")}'
            )
            LOGGER.error(msg)
            index_event(ctx.obj.es, module=__name__, event_type="ERROR", event=msg)
            click.secho(f"[!] {msg}", fg="red")

            ctx.obj.okta.get_zone(ctx, self.obj["id"])

            return


@dataclass
class OktaApp:
    """Data class for an Okta application"""

    obj: dict

    def print_info(self):
        """Print basic info for the Okta application"""

        click.echo(f'[*] Information for application {self.obj.get("id")} ({self.obj.get("name")}):')
        click.echo(
            f'    Status: {self.obj.get("status", "unknown")}\n'
            f'    Label: {self.obj.get("label", "unknown")}\n'
            f'    Created: {self.obj.get("created", "unknown")}\n'
            f'    Last Updated: {self.obj.get("lastUpdated", "unknown")}'
        )

    def change_state(self, ctx, operation):
        """Activate or deactivate the Okta application"""

        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f"SSWS {ctx.obj.api_token}",
        }

        params = {}
        payload = {}

        url = f'{ctx.obj.base_url}/apps/{self.obj["id"]}/lifecycle/{operation.lower()}'

        try:
            response = ctx.obj.session.post(url, headers=headers, params=params, json=payload, timeout=7)
            time.sleep(1)
        except Exception as e:
            LOGGER.error(e, exc_info=True)
            index_event(ctx.obj.es, module=__name__, event_type="ERROR", event=e)
            click.secho(f"[!] {URL_OR_API_TOKEN_ERROR}", fg="red")
            response = None

        if response.ok:
            msg = f'Application {self.obj["id"]} {operation.lower()}d'
            LOGGER.info(msg)
            index_event(ctx.obj.es, module=__name__, event_type="INFO", event=msg)
            click.secho(f"[*] {msg}", fg="green")

            ctx.obj.okta.get_app(ctx, self.obj["id"])

        else:
            msg = (
                f'Error executing {operation} for application {self.obj["id"]}\n'
                f"    Response Code: {response.status_code} | Response Reason: {response.reason}\n"
                f'    Error Code: {response.json().get("errorCode")} | Error Summary: {response.json().get("errorSummary")}'
            )
            LOGGER.error(msg)
            index_event(ctx.obj.es, module=__name__, event_type="ERROR", event=msg)
            click.secho(f"[!] {msg}", fg="red")

            ctx.obj.okta.get_app(ctx, self.obj["id"])

            return


@dataclass
class OktaPolicy:
    """Data class for an Okta policy"""

    obj: dict

    def print_info(self):
        """Print basic info for the Okta policy"""

        click.echo(f'[*] Information for policy ID {self.obj.get("id")} ({self.obj.get("name")}):')
        click.echo(
            f'    Status: {self.obj.get("status", "unknown")}\n'
            f'    Description: {self.obj.get("description", "unknown")}\n'
            f'    Created: {self.obj.get("created", "unknown")}\n'
            f'    Last Updated: {self.obj.get("lastUpdated", "unknown")}'
        )

    def change_state(self, ctx, operation):
        """Activate or deactivate the Okta policy"""

        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f"SSWS {ctx.obj.api_token}",
        }

        params = {}
        payload = {}

        url = f'{ctx.obj.base_url}/policies/{self.obj["id"]}/lifecycle/{operation.lower()}'

        try:
            response = ctx.obj.session.post(url, headers=headers, params=params, json=payload, timeout=7)
            time.sleep(1)
        except Exception as e:
            LOGGER.error(e, exc_info=True)
            index_event(ctx.obj.es, module=__name__, event_type="ERROR", event=e)
            click.secho(f"[!] {URL_OR_API_TOKEN_ERROR}", fg="red")
            response = None

        if response.ok:
            msg = f'Policy {self.obj["id"]} {operation.lower()}d'
            LOGGER.info(msg)
            index_event(ctx.obj.es, module=__name__, event_type="INFO", event=msg)
            click.secho(f"[*] {msg}", fg="green")

        else:
            msg = (
                f'Error executing {operation} for policy {self.obj["id"]}\n'
                f"    Response Code: {response.status_code} | Response Reason: {response.reason}\n"
                f'    Error Code: {response.json().get("errorCode")} | Error Summary: {response.json().get("errorSummary")}'
            )
            LOGGER.error(msg)
            index_event(ctx.obj.es, module=__name__, event_type="ERROR", event=msg)
            click.secho(f"[!] {msg}", fg="red")

            return


@dataclass
class OktaPolicyRule:
    """Data class for an Okta policy rule"""

    obj: dict

    def print_info(self):
        """Print basic info for the Okta policy rule"""

        click.echo(f'[*] Information for policy rule {self.obj.get("id")} ({self.obj.get("name")}):')
        click.echo(
            f'    Status: {self.obj.get("status", "unknown")}\n'
            f'    Created: {self.obj.get("created", "unknown")}\n'
            f'    Last Updated: {self.obj.get("lastUpdated", "unknown")}'
        )

    def change_state(self, ctx, policy_id, operation):
        """Activate or deactivate the Okta policy rule"""

        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f"SSWS {ctx.obj.api_token}",
        }

        params = {}
        payload = {}

        url = f'{ctx.obj.base_url}/policies/{policy_id}/rules/{self.obj["id"]}/lifecycle/{operation.lower()}'

        try:
            response = ctx.obj.session.post(url, headers=headers, params=params, json=payload, timeout=7)
            time.sleep(1)
        except Exception as e:
            LOGGER.error(e, exc_info=True)
            index_event(ctx.obj.es, module=__name__, event_type="ERROR", event=e)
            click.secho(f"[!] {URL_OR_API_TOKEN_ERROR}", fg="red")
            response = None

        if response.ok:
            msg = f'Policy rule {self.obj["id"]} in policy {policy_id} {operation.lower()}d'
            LOGGER.info(msg)
            index_event(ctx.obj.es, module=__name__, event_type="INFO", event=msg)
            click.secho(f"[*] {msg}", fg="green")

            ctx.obj.okta.get_policy_rule(ctx, policy_id, self.obj["id"])

        else:
            msg = (
                f'Error executing {operation} for rule {self.obj["id"]} in policy {policy_id}\n'
                f"    Response Code: {response.status_code} | Response Reason: {response.reason}\n"
                f'    Error Code: {response.json().get("errorCode")} | Error Summary: {response.json().get("errorSummary")}'
            )
            LOGGER.error(msg)
            index_event(ctx.obj.es, module=__name__, event_type="ERROR", event=msg)
            click.secho(f"[!] {msg}", fg="red")

            ctx.obj.okta.get_policy_rule(ctx, policy_id, self.obj["id"])

            return


def list_modules(obj):
    """List all of Dorothy's modules"""

    # Yield all .py files in modules directory and subdirectories
    modules_dir = obj.root_dir / "modules"
    files = list(modules_dir.rglob("*.py"))

    module_files = []
    # Filter the module names in this list
    exclude = ["__init__", "defense_evasion", "discovery", "persistence", "impact", "manage_config"]
    for index, file in enumerate(files):
        if file.stem not in exclude:
            module_files.append(file)

    modules = [("Discovery", "whoami", "Get info for user linked with current API token")]

    for module in module_files:
        description = getattr(
            import_module(f"dorothy.modules.{module.parent.name}.{module.stem}"), "MODULE_DESCRIPTION", "Missing"
        )
        tactics = getattr(import_module(f"dorothy.modules.{module.parent.name}.{module.stem}"), "TACTICS", "Missing")

        modules.append((str(tactics).strip("[]").replace("'", ""), module.stem.replace("_", "-"), description))

    modules.append(("-", "manage-config", "Manage Dorothy's configuration profiles"))

    # Print modules in table format
    headers = ["Tactics", "Module Name", "Description"]
    click.echo(tabulate(modules, headers=headers, tablefmt="pretty"))


def setup_session_instance(url):
    """Setup HTTPAdapter and session instance"""

    # Setup a Transport Adapter (HTTPAdapter) with max_retries set
    okta_adapter = HTTPAdapter(max_retries=3)
    # Setup session instance
    session = requests.Session()
    # Use okta_adapter for all requests to endpoints that start with the base URL
    session.mount(url, okta_adapter)

    return session


def whoami(ctx):
    """Get info for user linked with current API token"""

    msg = "Attempting to get user information associated with current API token"
    LOGGER.info(msg)
    index_event(ctx.obj.es, module=__name__, event_type="INFO", event=msg)
    click.echo(f"[*] {msg}")

    user = ctx.obj.okta.get_current_user(ctx)
    if user:
        user.list_roles(ctx, mute=False)
    else:
        msg = """Unable to list current user's assigned roles. No user object found"""
        LOGGER.error(msg)
        index_event(ctx.obj.es, module=__name__, event_type="ERROR", event=msg)
        click.secho(f"[!] {msg}", fg="red")

    if user:
        groups = user.get_groups(ctx)
        if groups:
            click.echo(f"[*] Group memberships for user ID {user.obj['id']}:")
            for okta_group in groups:
                group = OktaGroup(okta_group)
                group.print_info()
    else:
        msg = """Unable to list current user's group memberships. No user object found"""
        LOGGER.error(msg)
        index_event(ctx.obj.es, module=__name__, event_type="ERROR", event=msg)
        click.secho(f"[!] {msg}", fg="red")


def write_json_file(file_name: str, results: list) -> str:
    """Write data to json file"""

    now = datetime.now()
    timestamp = f"_{now.month}-{now.day}-{now.year}_{now.hour}-{now.minute}.json"

    file_path = file_name + timestamp

    click.secho(f"[*] Writing results to {file_path}", fg="green")
    with open(file_path, "w") as f:
        json.dump(results, f, indent=4)

    return file_path


def load_json_file(file_path: str) -> dict:
    """Load JSON file from local host"""

    with open(file_path, "r") as f:
        data = json.load(f)

    return data


def setup_logging(root_dir, config_dir, logs_dir):
    """Prepare location to write log files to"""

    # Load logging_config_template.yaml before customizing it and storing a new local config file
    logging_template = root_dir / "etc/logging_config_template.yaml"

    # Load config template
    with open(logging_template, "r") as f:
        config = yaml.safe_load(f.read())

    # Set path for logging.handlers.RotatingFileHandler
    config["handlers"]["file"]["filename"] = str(logs_dir.joinpath("dorothy.log"))

    # Write new config file
    new_config_file = f"{config_dir}/logging_config.yaml"
    with open(new_config_file, "w") as f:
        yaml.dump(config, f)

    return new_config_file


def setup_elasticsearch_client(okta_url):
    """Setup a connection in preparation of indexing Dorothy's logs in Elasticsearch"""

    if click.confirm("[*] Do you want to index Dorothy's logs in Elasticsearch?", default=False):
        es_url = click.prompt("[*] Enter your Elasticsearch URL")
        es_username = click.prompt("[*] Enter your Elasticsearch username")
        es_password = click.prompt(
            "[*] Enter your Elasticsearch password. The input for this value is hidden", hide_input=True
        )
        es_client = Elasticsearch([es_url], http_auth=(es_username, es_password), scheme="https")

        event = f"Dorothy started using URL {okta_url}"
        index_event(es_client, module=__name__, event_type="INFO", event=event)

        click.echo(
            "[*] Create an index pattern named, 'dorothy' to review log events in Kibana. For more information, "
            "visit https://www.elastic.co/guide/en/kibana/current/index-patterns.html"
        )
        return es_client
    else:
        return


def index_event(es, module, event_type, event):
    """Index event in Elasticsearch"""

    timestamp = datetime.utcnow()

    if es:
        try:
            es.index(
                index="dorothy",
                id=hashlib.md5((str(timestamp) + str(event)).encode()).hexdigest(),
                body={"timestamp": timestamp, "module": module, "event_type": event_type, "event": str(event)},
            )
        except Exception as e:
            LOGGER.error(e, exc_info=True)
            click.secho(
                f"[!] Error indexing event in Elasticsearch. Review dorothy.log for further information", fg="red"
            )


def list_assigned_roles(ctx, unique_id, object_type, mute=False):
    """List admin roles assigned to a user or group

    Only the SUPER_ADMIN role can view, assign, or remove admin roles

    Reference: https://help.okta.com/en/prod/Content/Topics/Security/administrators-admin-comparison.htm
    """

    payload = {}
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Authorization": f"SSWS {ctx.obj.api_token}",
    }

    if object_type == "user":
        url = f"{ctx.obj.base_url}/users/{unique_id}/roles"
    elif object_type == "group":
        url = f"{ctx.obj.base_url}/groups/{unique_id}/roles"
    else:
        msg = "Unexpected type. Type must be 'user' or 'group'"
        LOGGER.error(msg)
        index_event(ctx.obj.es, module=__name__, event_type="ERROR", event=msg)
        click.secho(f"[!] {msg}", fg="red")

        return

    if not mute:
        msg = f"Attempting to get roles for {object_type} ID {unique_id}"
        LOGGER.info(msg)
        index_event(ctx.obj.es, module=__name__, event_type="INFO", event=msg)
        click.echo(f"[*] {msg}")

    roles = []
    error = False

    try:
        response = ctx.obj.session.get(url, headers=headers, data=payload, timeout=7)
    except Exception as e:
        LOGGER.error(e, exc_info=True)
        index_event(ctx.obj.es, module=__name__, event_type="ERROR", event=e)
        click.secho(f"[!] {URL_OR_API_TOKEN_ERROR}", fg="red")
        response = None

    if not response.ok:
        msg = (
            f"""Error retrieving {object_type}'s assigned roles\n"""
            f"    Response Code: {response.status_code} | Response Reason: {response.reason}\n"
            f'    Error Code: {response.json().get("errorCode")} | Error Summary: {response.json().get("errorSummary")}'
        )
        LOGGER.error(msg)
        index_event(ctx.obj.es, module=__name__, event_type="ERROR", event=msg)
        click.secho(f"[!] {msg}", fg="red")
        click.secho(
            "[!] Only the SUPER_ADMIN role can view, assign, or remove admin roles. The user linked to the "
            "current API token might not have the SUPER_ADMIN role assigned",
            fg="red",
        )
        error = True
        return roles, error

    if response.ok:
        roles = response.json()

        if not mute:
            print_role_info(unique_id, roles, object_type=object_type)

    return roles, error


def print_role_info(unique_id, roles, object_type):
    """Print basic info on the admin roles assigned to a user or group"""
    click.echo(f"[*] Roles assigned to {object_type} ID {unique_id}:")

    for role in roles:
        click.echo(
            f'    ID: {role.get("id", "unknown")}\n'
            f'    Label: {role.get("label", "unknown")}\n'
            f'    Type: {role.get("type", "unknown")}\n'
            f'    Status: {role.get("status", "unknown")}\n'
            f'    Assignment type: {role.get("assignmentType", "unknown")}'
        )


def assign_admin_role(ctx, object_id, role_type, target):
    """Assign an admin role to a user or group"""

    if target == "user":
        url = f"{ctx.obj.base_url}/users/{object_id}/roles"
    elif target == "group":
        url = f"{ctx.obj.base_url}/groups/{object_id}/roles"
    else:
        click.secho('''[!] Invalid type. Must be "user" or "group"''', fg="red")
        return

    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Authorization": f"SSWS {ctx.obj.api_token}",
    }

    params = {}
    payload = {"type": role_type}

    try:
        response = ctx.obj.session.post(url, headers=headers, params=params, json=payload, timeout=7)
    except Exception as e:
        LOGGER.error(e, exc_info=True)
        index_event(ctx.obj.es, module=__name__, event_type="ERROR", event=e)
        click.secho(f"[!] {URL_OR_API_TOKEN_ERROR}", fg="red")
        response = None

    if response.ok:
        msg = f"Admin role, {role_type} assigned to {target} {object_id}"
        LOGGER.info(msg)
        index_event(ctx.obj.es, module=__name__, event_type="INFO", event=msg)
        click.secho(f"[*] {msg}", fg="green")

    else:
        msg = (
            f"Error assigning admin role to target\n"
            f"    Response Code: {response.status_code} | Response Reason: {response.reason}\n"
            f'    Error Code: {response.json().get("errorCode")} | Error Summary: {response.json().get("errorSummary")}'
        )
        LOGGER.error(msg)
        index_event(ctx.obj.es, module=__name__, event_type="ERROR", event=msg)
        click.secho(f"[!] {msg}", fg="red")
        click.secho(
            "[!] Only the SUPER_ADMIN role can view, assign, or remove admin roles. The user linked to the "
            "current API token might not have the SUPER_ADMIN role assigned",
            fg="red",
        )

        return
