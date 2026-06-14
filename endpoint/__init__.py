"""Optional endpoint agent for the Threat Intelligence Briefing Agent.

This package is installed *on a destination host* by an admin to collect a
local inventory (packages, services, listening ports, users, patches) and
report it back to the central app over HTTPS. It is dependency-free (Python 3
standard library only) so it runs on a bare host without pip installs.

Components:
  collector.py  - gathers the host inventory (cross-platform: Linux + Windows)
  agent.py      - loads config, collects, and checks in once or on a loop

Run `python -m endpoint.agent --help` for usage.
"""
__version__ = "0.1.0"
