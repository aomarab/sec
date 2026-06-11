"""Entrypoint. Runs the agent once, or on a cron schedule (like the MS agent's
trigger). Produces a briefing, saves it, and optionally emails it."""
from __future__ import annotations

import logging
import sys

from apscheduler.schedulers.blocking import BlockingScheduler
from apscheduler.triggers.cron import CronTrigger

from agent.loop import run_agent
from briefing import delivery, report
from config import CONFIG

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
log = logging.getLogger("main")


def run_once() -> None:
    log.info("Starting briefing run (region=%s industry=%s look_back=%dd insights=%d)",
             CONFIG.region, CONFIG.industry, CONFIG.look_back_days,
             CONFIG.insights_to_research)

    markdown = run_agent(CONFIG)
    if not markdown.strip():
        log.error("Agent returned an empty briefing.")
        return

    out = report.render(markdown)
    log.info("Briefing saved: %s / %s", out["markdown_path"], out["html_path"])

    delivery.send_email(
        CONFIG.email,
        subject=out["title"],
        html_body=out["html"],
        markdown_body=markdown,
    )


def main() -> None:
    if CONFIG.run_mode == "schedule":
        log.info("Schedule mode — cron '%s' (UTC). Waiting for trigger...",
                 CONFIG.schedule_cron)
        scheduler = BlockingScheduler(timezone="UTC")
        scheduler.add_job(run_once, CronTrigger.from_crontab(CONFIG.schedule_cron))
        try:
            run_once()  # run immediately on boot, then on schedule
            scheduler.start()
        except (KeyboardInterrupt, SystemExit):
            log.info("Shutting down scheduler.")
    else:
        run_once()


if __name__ == "__main__":
    try:
        main()
    except Exception as err:
        log.exception("Fatal error: %s", err)
        sys.exit(1)
