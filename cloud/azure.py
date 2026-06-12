"""Azure cloud security posture (CSPM) — read-only, agentless.

Authenticates a service principal via the OAuth2 client-credentials flow, then
uses Azure REST APIs (no Azure SDK required — just requests):
  • Azure Resource Graph        → asset inventory
  • Microsoft Defender for Cloud → secure score + security recommendations

The signed-in service principal needs **Reader** + **Security Reader** at the
subscription (or management-group) scope. Credentials are used for the request
only and are never stored."""
from __future__ import annotations

import datetime
import logging

import requests

from agent.llm import build_client

log = logging.getLogger("cloud.azure")

LOGIN = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
DEVICECODE = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/devicecode"
ARM = "https://management.azure.com"

# Microsoft's first-party Azure CLI public client — present in every tenant, so
# users can sign in interactively (device code) without registering an app.
CLI_CLIENT_ID = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"
DEVICE_SCOPE = "https://management.azure.com/.default offline_access"

_SYSTEM = """You are a cloud security advisor. You are given an Azure environment's
Microsoft Defender for Cloud secure score, a list of FAILING security
recommendations (with severities), and a resource-inventory summary. Write
GitHub-flavoured Markdown with exactly two sections:

## Summary
3-6 sentences: the overall cloud security posture, the most significant
exposures, and the business risk. Be factual; do not invent resources or findings.

## Priority Actions
A short, ranked list (max 6) of the most impactful remediations based strictly on
the findings — fix highest-severity Defender recommendations first, reduce public
exposure, enforce encryption/MFA, restrict over-permissive access, etc. One line
each, framed as a decision.

Do NOT list every recommendation or resource — those are in tables below."""

_SEV_ORDER = {"High": 0, "Medium": 1, "Low": 2}


# ── REST helpers ──────────────────────────────────────────────────────────────
def get_token(tenant: str, client_id: str, secret: str) -> str:
    r = requests.post(LOGIN.format(tenant=tenant),
                      data={"grant_type": "client_credentials", "client_id": client_id,
                            "client_secret": secret, "scope": ARM + "/.default"}, timeout=30)
    if r.status_code in (400, 401):
        raise RuntimeError("Azure sign-in failed — check the tenant ID, client ID, and secret.")
    r.raise_for_status()
    return r.json()["access_token"]


def start_device_code(tenant: str = "organizations") -> dict:
    """Begin the device-code flow (no app registration). Returns the user_code,
    verification_uri, device_code, interval, and expiry for the caller to display
    and poll."""
    tenant = (tenant or "organizations").strip() or "organizations"
    r = requests.post(DEVICECODE.format(tenant=tenant),
                      data={"client_id": CLI_CLIENT_ID, "scope": DEVICE_SCOPE}, timeout=30)
    r.raise_for_status()
    return r.json()


def poll_token(tenant: str, device_code: str) -> dict:
    """Poll once for the device-code token. Returns {status: ok|pending|expired|error}."""
    tenant = (tenant or "organizations").strip() or "organizations"
    r = requests.post(LOGIN.format(tenant=tenant),
                      data={"grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                            "client_id": CLI_CLIENT_ID, "device_code": device_code}, timeout=30)
    d = r.json()
    if r.status_code == 200:
        return {"status": "ok", "access_token": d["access_token"]}
    err = d.get("error", "")
    if err in ("authorization_pending", "slow_down"):
        return {"status": "pending"}
    if err in ("expired_token", "code_expired"):
        return {"status": "expired"}
    return {"status": "error", "message": d.get("error_description") or err or "Sign-in failed."}


class TokenTooLargeError(Exception):
    """Raised on HTTP 431 — the bearer token is too large for the endpoint's
    header limit (common with large delegated/user tokens on some Azure RPs)."""


def _get(token: str, url: str, params: dict | None = None) -> dict:
    r = requests.get(url, headers={"Authorization": "Bearer " + token}, params=params, timeout=45)
    if r.status_code == 431:
        raise TokenTooLargeError()
    r.raise_for_status()
    return r.json()


def list_subscriptions(token: str) -> list[dict]:
    data = _get(token, ARM + "/subscriptions", {"api-version": "2020-01-01"})
    return [{"id": s["subscriptionId"], "name": s.get("displayName", "")}
            for s in data.get("value", []) if s.get("subscriptionId")]


def list_tenants(token: str) -> list[str]:
    """Tenant IDs the signed-in account is associated with (to help when the
    subscription lives in a different tenant than the one signed in to)."""
    try:
        data = _get(token, ARM + "/tenants", {"api-version": "2020-01-01"})
        return [t.get("tenantId") for t in data.get("value", []) if t.get("tenantId")]
    except Exception:
        return []


def resource_graph(token: str, sub_ids: list[str], query: str, top: int = 1000) -> list[dict]:
    r = requests.post(ARM + "/providers/Microsoft.ResourceGraph/resources",
                      headers={"Authorization": "Bearer " + token},
                      params={"api-version": "2021-03-01"},
                      json={"subscriptions": sub_ids, "query": query, "options": {"$top": top}},
                      timeout=60)
    r.raise_for_status()
    return r.json().get("data", [])


def secure_score(token: str, sub: str) -> dict | None:
    try:
        d = _get(token, f"{ARM}/subscriptions/{sub}/providers/Microsoft.Security/secureScores/ascScore",
                 {"api-version": "2020-01-01"})
    except TokenTooLargeError:
        raise
    except Exception as err:
        log.info("secure score failed for %s: %s", sub, err)
        return None
    score = (d.get("properties", {}) or {}).get("score", {}) or {}
    pct = score.get("percentage")
    return {"percentage": round(100 * pct) if pct is not None else None,
            "current": score.get("current"), "max": score.get("max")}


def assessments(token: str, sub: str) -> list[dict]:
    """Failing (unhealthy) Defender for Cloud security recommendations."""
    try:
        d = _get(token, f"{ARM}/subscriptions/{sub}/providers/Microsoft.Security/assessments",
                 {"api-version": "2020-01-01"})
    except TokenTooLargeError:
        raise
    except Exception as err:
        log.info("assessments failed for %s: %s", sub, err)
        return []
    out = []
    for a in d.get("value", []):
        p = a.get("properties", {}) or {}
        status = ((p.get("status") or {}).get("code") or "")
        if status.lower() == "healthy":
            continue
        meta = p.get("metadata", {}) or {}
        sev = (meta.get("severity") or "").title() or "Unknown"
        out.append({"name": p.get("displayName") or a.get("name", ""),
                    "severity": sev, "status": status,
                    "resource": ((p.get("resourceDetails", {}) or {}).get("Id")
                                 or (p.get("resourceDetails", {}) or {}).get("id") or "")})
    return out


def _narrative(cfg, context: str) -> str:
    client, model = build_client(cfg.llm)
    if cfg.llm.provider == "anthropic":
        kwargs = dict(model=model, max_tokens=1800,
                      system=[{"type": "text", "text": _SYSTEM, "cache_control": {"type": "ephemeral"}}],
                      messages=[{"role": "user", "content": context}])
        if getattr(cfg.llm, "anthropic_thinking", False):
            kwargs["thinking"] = {"type": "adaptive"}
            kwargs["max_tokens"] = 5000
        resp = client.messages.create(**kwargs)
        return "".join(b.text for b in resp.content if b.type == "text")
    resp = client.chat.completions.create(
        model=model, temperature=0.2,
        messages=[{"role": "system", "content": _SYSTEM}, {"role": "user", "content": context}])
    return resp.choices[0].message.content or ""


def _risk_label(score_pct: int) -> tuple[int, str]:
    """Posture risk = inverse of secure score."""
    risk = max(0, 100 - score_pct)
    label = ("Critical" if risk >= 70 else "High" if risk >= 45
             else "Medium" if risk >= 20 else "Low")
    return risk, label


# ── orchestration ─────────────────────────────────────────────────────────────
def assess_azure(creds: dict, cfg=None, progress=None, token: str | None = None) -> dict:
    """Run the CSPM assessment. Either pass a service principal in `creds`
    (tenant/client_id/secret) or a pre-obtained delegated `token` (device-code
    sign-in)."""
    tenant = (creds.get("tenant") or "").strip()
    via_signin = token is not None
    if token:
        tenant_label = tenant or "signed-in account"
    else:
        client_id = (creds.get("client_id") or "").strip()
        secret = creds.get("secret") or ""
        if not (tenant and client_id and secret):
            raise ValueError("Tenant ID, client ID, and client secret are all required.")
        if progress:
            progress("Signing in to Azure…")
        token = get_token(tenant, client_id, secret)
        tenant_label = tenant

    subs = list_subscriptions(token)
    want = (creds.get("subscription") or "").strip()
    if want:
        subs = [s for s in subs if s["id"] == want or s["name"].lower() == want.lower()]
    if not subs:
        if via_signin:
            others = [t for t in list_tenants(token) if t.lower() != tenant.lower()]
            hint = (" Tenants your account can access: " + ", ".join(others) + ".") if others else ""
            raise RuntimeError(
                "Signed in successfully, but no subscriptions are visible in this tenant. "
                "Your subscription is likely in a different Microsoft Entra tenant — enter that "
                "tenant's Directory (tenant) ID in the form and sign in again." + hint)
        raise RuntimeError("No accessible subscriptions found "
                           "(the service principal needs Reader + Security Reader).")
    sub_ids = [s["id"] for s in subs]
    log.info("Azure CSPM across %d subscription(s)", len(subs))

    if progress:
        progress(f"Enumerating resources across {len(subs)} subscription(s)…")
    resources = resource_graph(
        token, sub_ids,
        "Resources | project name, type, location, resourceGroup | order by type asc", top=1000)
    public_ips = resource_graph(
        token, sub_ids,
        "Resources | where type =~ 'microsoft.network/publicipaddresses' "
        "| project name, ip = tostring(properties.ipAddress) | where isnotempty(ip)", top=500)

    if progress:
        progress("Reading Defender for Cloud secure score and recommendations…")
    scores, recs = [], []
    token_too_large = False
    for s in subs:
        try:
            sc = secure_score(token, s["id"])
            if sc:
                scores.append({**s, **sc})
            for r in assessments(token, s["id"]):
                recs.append({**r, "subscription": s["name"]})
        except TokenTooLargeError:
            token_too_large = True
            log.info("Defender for Cloud rejected the token (HTTP 431, token too large) for %s", s["id"])
    if token_too_large and progress:
        progress("Note: the signed-in token was too large for Defender for Cloud (HTTP 431) — "
                 "secure score/recommendations skipped. Use the service principal method for full posture.")

    # ── aggregate ──
    pcts = [s["percentage"] for s in scores if s.get("percentage") is not None]
    avg_score = round(sum(pcts) / len(pcts)) if pcts else 0
    risk, label = _risk_label(avg_score)
    sev_counts = {"High": 0, "Medium": 0, "Low": 0}
    for r in recs:
        sev_counts[r["severity"]] = sev_counts.get(r["severity"], 0) + 1
    type_counts: dict[str, int] = {}
    for row in resources:
        t = (row.get("type") or "").split("/")[-1] or row.get("type", "")
        type_counts[t] = type_counts.get(t, 0) + 1

    recs.sort(key=lambda r: (_SEV_ORDER.get(r["severity"], 9), r["name"]))

    # ── LLM narrative (optional) ──
    ctx = (f"Tenant: {tenant_label}\nSubscriptions: {len(subs)}\n"
           f"Average secure score: {avg_score}%\n"
           f"Failing recommendations: {len(recs)} "
           f"(High {sev_counts['High']}, Medium {sev_counts['Medium']}, Low {sev_counts['Low']})\n"
           f"Resources: {len(resources)} | public IPs: {len(public_ips)}\n\n"
           "Top failing recommendations:\n" +
           "\n".join(f"- [{r['severity']}] {r['name']}" for r in recs[:25]))
    narrative = ""
    if cfg is not None:
        try:
            narrative = _narrative(cfg, ctx).strip()
        except Exception as err:
            log.info("Azure narrative failed: %s", err)
            narrative = ("## Summary\nAutomated summary unavailable "
                         f"({err}). Review the score and recommendations below.\n\n"
                         "## Priority Actions\n- Remediate the highest-severity Defender "
                         "recommendations first.\n- Reduce public network exposure.")

    # ── markdown ──
    risk_line = (f"**Posture risk: {risk}/100 ({label})** · secure score {avg_score}% · "
                 f"{sev_counts['High']} high, {sev_counts['Medium']} medium, {sev_counts['Low']} low "
                 f"recommendations · {len(resources)} resources, {len(public_ips)} public IP(s)")
    parts = [f"# Azure Cloud Security Posture — {tenant_label}", "", risk_line, ""]
    if token_too_large:
        parts += ["> ⚠️ **Defender for Cloud data was skipped** — your signed-in token was too large "
                  "for the secure-score/recommendations endpoint (HTTP 431). Resource inventory below is "
                  "complete; for secure score and recommendations, re-run using the **Service principal** "
                  "method (its token is compact and avoids this limit).", ""]
    if narrative:
        parts += [narrative, ""]

    parts += ["## Secure Score by Subscription", "",
              "| Subscription | Secure score | Points |", "|---|---|---|"]
    if scores:
        for s in scores:
            pct = f"{s['percentage']}%" if s.get("percentage") is not None else "n/a"
            pts = (f"{s.get('current')}/{s.get('max')}"
                   if s.get("current") is not None and s.get("max") is not None else "—")
            parts.append(f"| {s['name'] or s['id']} | {pct} | {pts} |")
    else:
        parts.append("| _no secure-score data (is Defender for Cloud enabled?)_ | | |")

    parts += ["", "## Security Recommendations (failing)", ""]
    if recs:
        parts += ["| Severity | Recommendation | Subscription | Resource |",
                  "|---|---|---|---|"]
        for r in recs[:40]:
            res = (r.get("resource") or "").split("/")[-1] or "—"
            nm = r["name"].replace("|", "\\|")[:90]
            parts.append(f"| {r['severity']} | {nm} | {r['subscription']} | `{res}` |")
        if len(recs) > 40:
            parts.append(f"| … | _{len(recs) - 40} more_ | | |")
    else:
        parts.append("_No failing recommendations returned (or Defender for Cloud is not enabled)._")

    parts += ["", "## Resource Inventory", "",
              f"_{len(resources)} resource(s) across {len(subs)} subscription(s)._", "",
              "| Resource type | Count |", "|---|---|"]
    for t, n in sorted(type_counts.items(), key=lambda kv: kv[1], reverse=True)[:30]:
        parts.append(f"| {t} | {n} |")

    if public_ips:
        parts += ["", "## Public Exposure (public IP addresses)", "",
                  "| Name | IP |", "|---|---|"]
        for p in public_ips[:50]:
            parts.append(f"| {p.get('name', '')} | `{p.get('ip', '')}` |")

    parts += ["", "## Scope & Method", "",
              f"- Tenant: `{tenant_label}` · {len(subs)} subscription(s) assessed",
              "- Assets: Azure Resource Graph",
              "- Posture: Microsoft Defender for Cloud (secure score + assessments)",
              "- Read-only access (Reader + Security Reader); credentials/tokens not stored.",
              f"- Generated {datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}"]

    stats = {"provider": "Azure", "tenant": tenant_label, "subscriptions": len(subs),
             "resources": len(resources), "public_ips": len(public_ips),
             "secure_score": avg_score, "risk": risk, "label": label,
             "recommendations": len(recs), "counts": sev_counts}
    return {"markdown": "\n".join(parts), "stats": stats}
