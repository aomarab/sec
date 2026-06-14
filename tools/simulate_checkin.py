"""Simulate an endpoint agent check-in — posts a representative host inventory
to a running app's /agent/checkin so a host shows up under
Settings -> Endpoint agents, without installing anything on a real machine.

  python tools/simulate_checkin.py --server http://localhost:5000 --token <ENROLL_TOKEN>

Get <ENROLL_TOKEN> from Settings -> Endpoint agents -> Reveal. Run it a few
times with different --hostname values to populate the table.
"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
import uuid


def sample_inventory(hostname: str) -> dict:
    return {
        "schema": 1,
        "identity": {
            "hostname": hostname, "os": "Linux", "os_release": "6.1.0",
            "os_version": "#1 SMP", "architecture": "x86_64",
            "distro": "Ubuntu 22.04.4 LTS", "current_user": "root",
        },
        "ip_addresses": ["10.0.0.50", "192.168.1.50"],
        "listening_ports": [
            {"proto": "tcp", "local": "0.0.0.0:22", "port": "22"},
            {"proto": "tcp", "local": "0.0.0.0:443", "port": "443"},
            {"proto": "tcp", "local": "127.0.0.1:5432", "port": "5432"},
        ],
        "packages": [
            {"name": "openssl", "version": "3.0.2"},
            {"name": "openssh-server", "version": "8.9p1"},
            {"name": "nginx", "version": "1.18.0"},
            {"name": "python3", "version": "3.10.12"},
        ],
        "services": [
            {"name": "sshd.service", "display": "OpenSSH server"},
            {"name": "nginx.service", "display": "nginx web server"},
        ],
        "users": ["root", "deploy"],
        "patches": {"available_updates": 7},
        "summary": {"packages": 4, "services": 2, "listening_ports": 3},
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Simulate an endpoint agent check-in")
    ap.add_argument("--server", default="http://localhost:5000",
                    help="base URL of the running app")
    ap.add_argument("--token", required=True, help="enrollment token from the UI")
    ap.add_argument("--hostname", default="demo-web-01", help="host name to report")
    args = ap.parse_args()

    payload = {
        "agent_id": str(uuid.uuid5(uuid.NAMESPACE_DNS, args.hostname)),  # stable per host
        "agent_version": "simulator",
        "hostname": args.hostname,
        "tags": ["demo"],
        "inventory": sample_inventory(args.hostname),
    }
    req = urllib.request.Request(
        args.server.rstrip("/") + "/agent/checkin",
        data=json.dumps(payload).encode("utf-8"), method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("Authorization", "Bearer " + args.token)
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            print(f"HTTP {resp.status}: {resp.read().decode()}")
            print(f"Done. Open Settings -> Endpoint agents and you should see '{args.hostname}'.")
            return 0
    except urllib.error.HTTPError as err:
        print(f"HTTP {err.code}: {err.read().decode()}", file=sys.stderr)
        if err.code == 401:
            print("-> token rejected. Re-copy the enrollment token from the UI.", file=sys.stderr)
        return 1
    except Exception as err:
        print(f"Could not reach {args.server}: {err}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
