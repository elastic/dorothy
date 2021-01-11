![Supported Python Versions](https://img.shields.io/badge/Supported%20Python%20Versions-3.7%2B-yellow)
[![Unit Tests](https://github.com/elastic/dorothy/workflows/Unit%20Tests/badge.svg)](https://github.com/elastic/dorothy/actions)
[![Chat](https://img.shields.io/badge/chat-%23security-blueviolet)](https://ela.st/slack)
[![PyPI](https://img.shields.io/pypi/v/dorothy?label=PyPI)](https://pypi.org/project/dorothy/)

![Dorothy](https://github.com/elastic/dorothy/blob/main/.github/images/github-header-dorothy-moo-1500x454.png?raw=true)

Created by David French ([@threatpunter](https://twitter.com/threatpunter)) at [Elastic Security](https://www.elastic.co/security)

Dorothy is a tool to help security teams test their monitoring and detection capabilities for their Okta environment. Dorothy has several modules to simulate actions that an attacker might take while operating in an Okta environment and actions that security teams should be able to audit. The modules are mapped to the relevant [MITRE ATT&CK®](https://attack.mitre.org/) tactics, such as persistence, defense evasion, and discovery.

Learn more about Dorothy and how to get started with it in [this blog post](https://www.elastic.co/blog/testing-okta-visibility-and-detection-dorothy) or [this presentation](https://youtu.be/IG76PVvQSHE).

[Elastic Security's](https://www.elastic.co/security) free detection rules for Okta can be found in our [detection-rules](https://github.com/elastic/detection-rules) repo. You can read [this blog post](https://www.elastic.co/blog/cloud-monitoring-and-detection-with-elastic-security) to learn more about how Elastic Security helps with cloud monitoring and detection.

Dorothy can change the configuration of your Okta environment. Consider using Dorothy in a test environment to avoid any risk of impacting your production environment.

![Dorothy](https://raw.githubusercontent.com/elastic/dorothy/main/.github/images/whoami.gif?raw=true)

## Table of Contents
- [Getting Started](#getting-started)
- [Questions? Problems? Suggestions?](#questions-problems-suggestions)
- [Contributors](#contributors)
- [Acknowledgements](#acknowledgements)
- [Disclaimer](#disclaimer)
- [How to Contribute](#how-to-contribute)
- [Fun Facts](#fun-facts)

## Getting Started

Head on over to the [wiki](https://github.com/elastic/dorothy/wiki) for help installing and running Dorothy.

## Questions? Problems? Suggestions?

Reach out in the **#security** channel in [Elastic's Community Slack workspace](https://ela.st/slack) or open an issue in this repo.

## Contributors

- [Justin Ibarra](https://twitter.com/br0k3ns0und)
- [Ross Wolf](https://twitter.com/rw_access)
- [Brent Murphy](https://twitter.com/brent_murphy)
- [Seth Goodwin](https://twitter.com/bluish_red_)

## Acknowledgements

[Justin Ibarra](https://github.com/brokensound77) and [Ross Wolf](https://github.com/rw-access) - The style and layout of this project is inspired by shell/CLI utilities that they've developed.

## Disclaimer

Obtain the proper authorization before using Dorothy in an environment that you do not own and administer. Users take full responsibility for the outcomes of using Dorothy.

Dorothy is licensed under the [Apache License Version 2.0](https://github.com/elastic/dorothy/blob/main/LICENSE.txt).

> Disclaimer of Warranty. Unless required by applicable law or agreed to in writing, Licensor provides the Work (and each Contributor provides its Contributions) on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied, including, without limitation, any warranties or conditions of TITLE, NON-INFRINGEMENT, MERCHANTABILITY, or FITNESS FOR A PARTICULAR PURPOSE. You are solely responsible for determining the appropriateness of using or redistributing the Work and assume any risks associated with Your exercise of permissions under this License.

> Limitation of Liability. In no event and under no legal theory, whether in tort (including negligence), contract, or otherwise, unless required by applicable law (such as deliberate and grossly negligent acts) or agreed to in writing, shall any Contributor be liable to You for damages, including any direct, indirect, special, incidental, or consequential damages of any character arising as a result of this License or out of the use or inability to use the Work (including but not limited to damages for loss of goodwill, work stoppage, computer failure or malfunction, or any and all other commercial damages or losses), even if such Contributor has been advised of the possibility of such damages.

## How to Contribute

Interested in contributing to Dorothy? Thanks for your interest. Please familiarize yourself with the [contribution guide](https://github.com/elastic/dorothy/blob/main/CONTRIBUTING.md).

## Fun Facts

- [Dorothy](https://www.noaa.gov/stories/noaa-tornado-scientists-inspired-twister-creators-20-years-ago) is a scientific tornado instrument used to analyze data and to radio back information to create an advanced warning system.
- [What is an Okta](https://en.wikipedia.org/wiki/Glossary_of_meteorology)? A unit of measurement used to describe the amount of cloud cover at a given location in terms of how many eighths of the sky are covered in clouds
