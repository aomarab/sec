"""Endpoint agent runner. Loads a small JSON config, collects the host
inventory, and checks in to the central app over HTTPS with a bearer token.

Modes:
  --once     collect and check in a single time (good for cron / testing)
  --loop     run forever, checking in every `interval_seconds` (service mode)
  --print    collect and print the inventory locally; never sends

Standard library only — no pip install required on the host.

  python -m endpoint.agent --config /etc/sec-endpoint/agent.config.json --loop
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import socket
import ssl
import sys
import time
import urllib.error
import urllib.request
import uuid

if __package__ in (None, ""):  # allow `python endpoint/agent.py` as well as -m
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import collector  # type: ignore
else:
    from . import collector

log = logging.getLogger("endpoint.agent")

DEFAULT_INTERVAL = 3600
_MIN_INTERVAL = 60


def load_config(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        cfg = json.load(fh)
    if not cfg.get("server_url"):
        raise SystemExit("config error: 'server_url' is required")
    if not cfg.get("token"):
        raise SystemExit("config error: 'token' (enrollment token) is required")
    return cfg


def _state_path(config_path: str) -> str:
    return os.path.join(os.path.dirname(os.path.abspath(config_path)), "agent_state.json")


def agent_id(config_path: str) -> str:
    """Stable per-install id so re-runs update the same record, not a new one."""
    sp = _state_path(config_path)
    try:
        with open(sp, encoding="utf-8") as fh:
            aid = json.load(fh).get("agent_id")
            if aid:
                return aid
    except Exception:
        pass
    aid = str(uuid.uuid4())
    try:
        with open(sp, "w", encoding="utf-8") as fh:
            json.dump({"agent_id": aid}, fh)
    except Exception as err:
        log.warning("could not persist agent id (%s); using ephemeral id", err)
    return aid


def _ssl_context(cfg: dict) -> ssl.SSLContext | None:
    if cfg.get("server_url", "").lower().startswith("http://"):
        return None  # plain http, no TLS context needed
    ca = cfg.get("ca_bundle")
    if cfg.get("verify_tls", True) is False:
        # Self-signed lab servers only — never use against production.
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    if ca:
        return ssl.create_default_context(cafile=ca)
    return ssl.create_default_context()


def check_in(cfg: dict, config_path: str) -> bool:
    inventory = collector.collect()
    body = json.dumps({
        "agent_id": agent_id(config_path),
        "agent_version": getattr(__import__("endpoint", fromlist=["__version__"]),
                                 "__version__", "0"),
        "hostname": socket.gethostname(),
        "tags": cfg.get("tags", []),
        "inventory": inventory,
    }).encode("utf-8")

    url = cfg["server_url"].rstrip("/") + "/agent/checkin"
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("Authorization", "Bearer " + cfg["token"])
    try:
        with urllib.request.urlopen(req, timeout=45, context=_ssl_context(cfg)) as resp:
            ok = 200 <= resp.status < 300
            log.info("check-in %s (%s packages, %s services, %s ports)",
                     "ok" if ok else f"failed [{resp.status}]",
                     inventory["summary"]["packages"], inventory["summary"]["services"],
                     inventory["summary"]["listening_ports"])
            return ok
    except urllib.error.HTTPError as err:
        log.error("check-in rejected by server: HTTP %s %s", err.code, err.reason)
    except Exception as err:
        log.error("check-in failed: %s", err)
    return False


def run_loop(cfg: dict, config_path: str) -> None:
    interval = max(int(cfg.get("interval_seconds", DEFAULT_INTERVAL)), _MIN_INTERVAL)
    log.info("endpoint agent started; reporting to %s every %ss", cfg["server_url"], interval)
    backoff = 0
    while True:
        ok = check_in(cfg, config_path)
        # On failure, retry sooner with capped exponential backoff.
        if ok:
            backoff = 0
            time.sleep(interval)
        else:
            backoff = min(backoff * 2 or 60, interval)
            time.sleep(backoff)


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Threat-intel endpoint agent")
    p.add_argument("--config", default=os.getenv("SEC_AGENT_CONFIG",
                   "/etc/sec-endpoint/agent.config.json"),
                   help="path to agent.config.json")
    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--once", action="store_true", help="check in a single time and exit")
    mode.add_argument("--loop", action="store_true", help="run forever (service mode)")
    mode.add_argument("--print", dest="print_only", action="store_true",
                      help="collect and print inventory locally; do not send")
    p.add_argument("--interval", type=int, help="override interval_seconds (loop mode)")
    p.add_argument("--insecure", action="store_true",
                   help="disable TLS verification (self-signed lab servers only)")
    args = p.parse_args(argv)

    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    if args.print_only:
        json.dump(collector.collect(), sys.stdout, indent=2, default=str)
        sys.stdout.write("\n")
        return 0

    cfg = load_config(args.config)
    if args.interval:
        cfg["interval_seconds"] = args.interval
    if args.insecure:
        cfg["verify_tls"] = False

    if args.loop:
        try:
            run_loop(cfg, args.config)
        except KeyboardInterrupt:
            log.info("stopped")
        return 0
    # default: --once
    return 0 if check_in(cfg, args.config) else 1


if __name__ == "__main__":
    raise SystemExit(main())
