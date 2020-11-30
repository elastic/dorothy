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

# Menu for impact modules

import click

from dorothy.main import dorothy_shell
from dorothy.modules.defense_evasion import (
    change_app_state,
    change_rule_state,
    change_zone_state,
    change_policy_state,
    modify_policy,
    modify_policy_rule,
    modify_zone,
)
from dorothy.modules.persistence import change_user_state


@dorothy_shell.subshell(name="impact")
@click.pass_context
def impact(ctx):
    """Modules to interrupt components of the Okta environment"""


# Reuse a few commands from defense_evasion
impact.add_command(change_user_state.change_user_state)
impact.add_command(change_app_state.change_app_state)
impact.add_command(change_rule_state.change_rule_state)
impact.add_command(change_zone_state.change_zone_state)
impact.add_command(change_policy_state.change_policy_state)
impact.add_command(modify_policy.modify_policy)
impact.add_command(modify_policy_rule.modify_policy_rule)
impact.add_command(modify_zone.modify_zone)
