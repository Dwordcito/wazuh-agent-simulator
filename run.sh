#!/bin/bash

# Activate virtual environment and run Wazuh Agent Controller
source venv/bin/activate
python wazuh_agent_controller.py "$@"
