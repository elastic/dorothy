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

import logging.config
from pathlib import Path

import yaml

import dorothy.modules
from .core import setup_logging

__version__ = "0.3.2"

ROOT_DIR = Path(__file__).parent
DATA_DIR = Path.home() / "dorothy" / "data"
LOGS_DIR = Path.home() / "dorothy" / "logs"
CONFIG_DIR = Path.home() / "dorothy" / "config"

# Create directories if they don't exist
DATA_DIR.mkdir(parents=True, exist_ok=True)
LOGS_DIR.mkdir(parents=True, exist_ok=True)
CONFIG_DIR.mkdir(parents=True, exist_ok=True)

logging_config = setup_logging(ROOT_DIR, CONFIG_DIR, LOGS_DIR)

# Setup logger
with open(logging_config, "r") as f:
    config = yaml.safe_load(f.read())
    logging.config.dictConfig(config)
