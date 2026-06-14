"""Windows service wrapper for the endpoint agent (requires pywin32).

  python win_service.py --startup auto install   # register the service
  python win_service.py start                     # start it
  python win_service.py stop | remove             # control / uninstall

Once installed it appears in services.msc as "Threat Intel Endpoint Agent".
A dependency-free alternative (Scheduled Task) is install-task.ps1.
"""
import os
import sys

import servicemanager
import win32event
import win32service
import win32serviceutil

# Make the 'endpoint' package importable whether this file runs from the repo
# tree (endpoint/packaging/windows/) or the installed location (next to endpoint/).
_here = os.path.dirname(os.path.abspath(__file__))
for _cand in (_here, os.path.dirname(_here), os.path.dirname(os.path.dirname(_here)),
              os.path.dirname(os.path.dirname(os.path.dirname(_here)))):
    if os.path.isfile(os.path.join(_cand, "endpoint", "agent.py")):
        sys.path.insert(0, _cand)
        break

from endpoint import agent  # noqa: E402


class SecEndpointAgent(win32serviceutil.ServiceFramework):
    _svc_name_ = "SecEndpointAgent"
    _svc_display_name_ = "Threat Intel Endpoint Agent"
    _svc_description_ = ("Collects a local host inventory and reports it to the "
                         "central Threat Intelligence Briefing Agent.")

    def __init__(self, args):
        super().__init__(args)
        self.stop_event = win32event.CreateEvent(None, 0, 0, None)
        self.running = True

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self.stop_event)
        self.running = False

    def SvcDoRun(self):
        servicemanager.LogMsg(servicemanager.EVENTLOG_INFORMATION_TYPE,
                              servicemanager.PYS_SERVICE_STARTED, (self._svc_name_, ""))
        cfg_path = os.environ.get(
            "SEC_AGENT_CONFIG", r"C:\ProgramData\sec-endpoint\agent.config.json")
        cfg = agent.load_config(cfg_path)
        interval = max(int(cfg.get("interval_seconds", agent.DEFAULT_INTERVAL)), 60)
        while self.running:
            try:
                agent.check_in(cfg, cfg_path)
            except Exception as err:  # never let one failure kill the service
                servicemanager.LogErrorMsg(f"check-in error: {err}")
            # Sleep until the interval elapses or a stop is requested.
            win32event.WaitForSingleObject(self.stop_event, interval * 1000)


if __name__ == "__main__":
    if len(sys.argv) == 1:
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(SecEndpointAgent)
        servicemanager.StartServiceCtrlDispatcher()
    else:
        win32serviceutil.HandleCommandLine(SecEndpointAgent)
