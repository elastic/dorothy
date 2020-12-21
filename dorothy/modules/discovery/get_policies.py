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

# Harvest information on all Okta policies and policy rules

import logging.config

import click

from dorothy.core import OktaPolicy, write_json_file, index_event
from dorothy.modules.discovery.discovery import discovery

LOGGER = logging.getLogger(__name__)
MODULE_DESCRIPTION = "Harvest information on all Okta policies and policy rules"
TACTICS = ["Discovery"]


@discovery.subshell(name="get-policies")
@click.pass_context
def get_policies(ctx):
    """Harvest information on all Okta policies and policy rules"""


@get_policies.command()
@click.pass_context
def execute(ctx):
    """Execute this module with the configured options"""

    if click.confirm(
        "[*] Do you want to attempt to harvest information for all Okta policies and policy rules?", default=True
    ):

        harvested_policies = []

        policy_types = ctx.obj.policy_types

        # Get a list of all policies by policy type
        for policy_type in policy_types:
            policies = ctx.obj.okta.get_policies_by_type(ctx, policy_type)
            if policies:
                harvested_policies.extend(policies)

        policies_and_rules = []

        # Get all policies again including their rules
        if harvested_policies:
            for policy in harvested_policies:
                policy_and_rules = ctx.obj.okta.get_policy(ctx, policy["id"], rules=True)
                if not policy_and_rules:
                    msg = f'Issue retrieving policy {policy["id"]} ({policy["name"]}) with rules'
                    LOGGER.error(msg)
                    index_event(ctx.obj.es, module=__name__, event_type="ERROR", event=msg)
                    click.secho(f"[!] {msg}", fg="red")
                else:
                    policies_and_rules.append(policy_and_rules)

        if policies_and_rules:
            if click.confirm("[*] Do you want to print harvested policy information?", default=True):
                for okta_policy in policies_and_rules:
                    policy = OktaPolicy(okta_policy)
                    policy.print_info()

            if click.confirm(
                f"[*] Do you want to save {len(policies_and_rules)} harvested policies to a file?", default=True
            ):
                file_path = f"{ctx.obj.data_dir}/{ctx.obj.profile_id}_harvested_policies"
                write_json_file(file_path, policies_and_rules)
