"""Provider-level cloud vendor security assessment.

Distinct from the tenant CSPM check (which inspects *your* resources), this
evaluates the cloud provider/platform itself: security certifications,
compliance coverage, public security posture, shared-responsibility model,
native IAM / data-protection / threat-detection / network-security / vuln-mgmt
capabilities, and an AI-generated vendor risk score.

It is AI-compiled from well-established public information (the provider's trust
center and compliance documentation). Certifications and capabilities for the
major providers are stable public facts; recent-incident figures and the risk
score are estimates the reader should verify. No credentials are required."""
from __future__ import annotations

import logging

from intel.analyst import _complete

log = logging.getLogger("cloud.vendor")

PROVIDERS = {
    "azure": ("Microsoft Azure",
              ["https://www.microsoft.com/trust-center",
               "https://servicetrust.microsoft.com",
               "https://learn.microsoft.com/azure/compliance/"]),
    "aws": ("Amazon Web Services (AWS)",
            ["https://aws.amazon.com/compliance/",
             "https://aws.amazon.com/artifact/",
             "https://aws.amazon.com/security/"]),
    "gcp": ("Google Cloud Platform (GCP)",
            ["https://cloud.google.com/security/compliance",
             "https://cloud.google.com/security"]),
}

_INTRO = """You are a third-party cloud vendor risk analyst. Given a major cloud
provider, compile a vendor security assessment from well-established public
information. Write GitHub-flavoured Markdown containing ONLY the sections listed
below, with the exact headings given, in this order. Be factual and specific to
the named provider; name real services. Do not fabricate certifications — if
uncertain about a specific attestation, say "verify in the trust center"."""

# Selectable checks: key -> (label, heading, instruction).
SECTIONS = {
    "certifications": ("Security certifications", "Security Certifications",
        "A table | Certification | Status | of: ISO 27001, ISO 27017, ISO 27018, SOC 1, "
        "SOC 2, PCI DSS, HIPAA, FedRAMP, CSA STAR. Use ✓ for held/attested, or a short note "
        "(e.g. \"Eligible\", \"Authorized\") where that's more accurate."),
    "compliance": ("Compliance coverage", "Compliance Coverage",
        "A table | Framework | Supported | of: GDPR, CCPA, HIPAA, PCI DSS, NIS2, DORA, with a "
        "one-line note on how the provider supports each."),
    "posture": ("Public security posture", "Public Security Posture",
        "Bullet summary of security advisories, notable public incidents, data breaches, major "
        "service disruptions, and security-bulletin channels. Then a small table of risk factors: "
        "Critical Incidents (last 12 months), Security Transparency, Patch Response Speed. CLEARLY "
        "mark incident/recency claims as 'verify against current sources'."),
    "shared": ("Shared responsibility model", "Shared Responsibility Model",
        "Two short lists — what the vendor secures vs what the customer secures — for IaaS, with a "
        "one-line note on how it shifts for PaaS/SaaS."),
    "iam": ("Identity & access management", "Identity & Access Management",
        "Bullet IAM capabilities: MFA, Conditional Access, RBAC, PIM/PAM, SSO, SCIM provisioning — "
        "name the actual products (e.g. Microsoft Entra ID, AWS IAM/Identity Center, Google Cloud IAM)."),
    "data": ("Data protection", "Data Protection",
        "Bullets: encryption at rest, encryption in transit, customer-managed keys, key rotation, "
        "HSM support, backup & recovery — name the services."),
    "threat": ("Threat detection", "Threat Detection",
        "Bullets naming the native SIEM, XDR, IDS/IPS, security monitoring, and threat-intelligence services."),
    "network": ("Network security", "Network Security",
        "Bullets: DDoS protection, WAF, private networking, network segmentation, Zero Trust — name the services."),
    "vuln": ("Vulnerability management", "Vulnerability Management",
        "Bullets: patch-management process, security-update cadence, vulnerability disclosure program, bug bounty program."),
    "score": ("AI risk score", "Vendor Risk Score (AI estimate)",
        "A table | Category | Score (/100) | for the areas covered above (e.g. Identity Security, "
        "Compliance, Data Protection, Network Security, Incident History, Transparency). Then an "
        "**Overall score: NN/100** line and an **Overall risk: Low/Medium/High** line. State explicitly "
        "this is an AI-generated estimate for prioritisation, not an audited rating."),
}
_ORDER = list(SECTIONS)


def _build_system(keys: list[str]) -> str:
    parts, n = [_INTRO], 1
    for k in _ORDER:
        if k in keys:
            _, heading, instr = SECTIONS[k]
            parts.append(f"## {n}. {heading}\n{instr}")
            n += 1
    return "\n\n".join(parts)


def assess_vendor(provider: str, cfg, sections: list[str] | None = None) -> str:
    key = (provider or "").strip().lower()
    if key not in PROVIDERS:
        raise ValueError("Choose a supported provider: azure, aws, or gcp.")
    name, links = PROVIDERS[key]
    chosen = [k for k in _ORDER if k in sections] if sections else list(_ORDER)
    if not chosen:
        raise ValueError("Select at least one check to assess.")
    log.info("Vendor assessment for %s (%d section(s))", name, len(chosen))
    ctx = (f"Cloud provider to assess: {name}\n\n"
           "Produce the assessment with exactly the sections defined above — no others.")
    body = _complete(cfg, _build_system(chosen), ctx, max_tokens=3800).strip()
    note = ("> **Analyst note:** AI-compiled from public information. Certifications "
            "and capabilities are generally stable, but verify the current status — "
            "and any recent incident claims — in the provider's trust center. The "
            "risk score is an AI estimate for prioritisation, not an audited rating.")
    refs = ["## Sources & Verification", ""] + [f"- {u}" for u in links] + [
        "- Confirm certifications and compliance in the provider's official trust center before relying on this assessment."]
    return f"# {name} — Vendor Security Assessment\n\n{note}\n\n{body}\n\n" + "\n".join(refs)
