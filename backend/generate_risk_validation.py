"""
generate_risk_validation.py
===========================
Runs the three canonical SecureBank test scenarios through RiskEngine.calculate_risk()
and produces risk_engine_validation_report.json.

Expected output ordering:
  Official.score  < Plus.score  < Clone.score
  Official.verdict == SAFE
  Plus.verdict    == SUSPICIOUS
  Clone.verdict   == MALICIOUS
"""

import os
import sys
import json
import hashlib
from datetime import datetime

# Ensure backend package is importable when run from any cwd
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from risk_engine import RiskEngine  # noqa: E402

# ── Real SHA-256 fingerprints (derived from code bytes used in init_benchmark_dataset.py)
OFFICIAL_CERT_SHA256  = hashlib.sha256(b"secureBankAppCoreInit").hexdigest()
PLUS_CERT_SHA256      = hashlib.sha256(b"secureBankOverlayVerification").hexdigest()
CLONE_CERT_SHA256     = hashlib.sha256(b"secureBankRepackagedMaliciousCode").hexdigest()

OFFICIAL_PKG = "com.securebank.official"
PLUS_PKG     = "com.securebank.plus"
CLONE_PKG    = "com.securebank.official"  # Same package — repackaged official

# ── Scenario definitions ──────────────────────────────────────────────────────
SCENARIOS = {
    "official": {
        "label": "SecureBank Official",
        "package_name": OFFICIAL_PKG,
        "app_name":     "SecureBank Official",
        "permissions":  ["android.permission.INTERNET"],
        "certificates": [{"sha256": OFFICIAL_CERT_SHA256, "issuer": "CN=SecureBank Official, O=SecureBank, C=US"}],
        "has_services": False,
        "has_certs":    True,
        "dex_indicators": {},
        "activities":   [".MainActivity"],
    },
    "plus": {
        "label": "SecureBank Plus",
        "package_name": PLUS_PKG,
        "app_name":     "SecureBank Plus",
        "permissions":  ["android.permission.INTERNET", "android.permission.SYSTEM_ALERT_WINDOW"],
        "certificates": [{"sha256": PLUS_CERT_SHA256, "issuer": "CN=Android Debug, O=Android, C=US"}],
        "has_services": False,
        "has_certs":    True,
        "dex_indicators": {},
        "activities":   [".MainActivity"],
    },
    "clone": {
        "label": "SecureBank Clone",
        "package_name": CLONE_PKG,
        "app_name":     "SecureBank Clone",
        "permissions":  ["android.permission.INTERNET"],
        "certificates": [{"sha256": CLONE_CERT_SHA256, "issuer": "CN=Android Debug, O=Android, C=US"}],
        "has_services": False,
        "has_certs":    True,
        "dex_indicators": {},
        "activities":   [".MainActivity"],
    },
}


def score_breakdown(result: dict) -> dict:
    """Extract per-category scores from triggered_rules."""
    permission_score = 0
    dex_score        = 0
    certificate_score = 0
    clone_score      = 0

    dex_rules  = {"DexClassLoader", "DEX_SMS", "Reflection", "RuntimeExec", "WebviewBridge", "SuspiciousUrl"}
    cert_rules = {"UnknownCertificate"}
    clone_rules = {"PackageImpersonation", "SamePkgForgery"}
    perm_rules = {"ACCESSIBILITY", "READ_SMS", "SYSTEM_ALERT_WINDOW"}

    for rule in result.get("triggered_rules", []):
        name = rule.get("permission", "")
        w    = rule.get("weight", 0)
        if name in perm_rules:
            permission_score += w
        elif name in dex_rules:
            dex_score += w
        elif name in cert_rules:
            certificate_score += w
        elif name in clone_rules:
            clone_score += w

    return {
        "permission_score":   permission_score,
        "dex_score":          dex_score,
        "certificate_score":  certificate_score,
        "clone_score":        clone_score,
        "final_score":        result.get("score", 0),
        "verdict":            result.get("verdict"),
        "severity":           result.get("severity"),
        "confidence":         result.get("confidence"),
        "clone_findings":     result.get("clone_findings", {}),
        "cert_findings":      result.get("cert_findings", {}),
        "triggered_rules":    result.get("triggered_rules", []),
    }


def main():
    report = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "engine_version": "3.2.0",
        "fingerprints": {
            "official": OFFICIAL_CERT_SHA256,
            "plus":     PLUS_CERT_SHA256,
            "clone":    CLONE_CERT_SHA256,
        },
        "official": {},
        "plus":     {},
        "clone":    {},
        "ordering_check": {},
        "verdict_check":  {},
    }

    results = {}
    for key, scenario in SCENARIOS.items():
        raw = RiskEngine.calculate_risk(
            permissions=scenario["permissions"],
            has_services=scenario["has_services"],
            has_certs=scenario["has_certs"],
            dex_indicators=scenario["dex_indicators"],
            package_name=scenario["package_name"],
            certificates=scenario["certificates"],
            app_name=scenario["app_name"],
            activities=scenario["activities"],
        )
        breakdown = score_breakdown(raw)
        report[key] = breakdown
        results[key] = breakdown
        print(f"\n{'='*60}")
        print(f"  {scenario['label']}")
        print(f"  Package:      {scenario['package_name']}")
        print(f"  Perm score:   {breakdown['permission_score']}")
        print(f"  DEX score:    {breakdown['dex_score']}")
        print(f"  Cert score:   {breakdown['certificate_score']}")
        print(f"  Clone score:  {breakdown['clone_score']}")
        print(f"  FINAL SCORE:  {breakdown['final_score']}")
        print(f"  VERDICT:      {breakdown['verdict']}")
        print(f"  Clone risk:   {breakdown['clone_findings'].get('clone_risk')}")
        print(f"  Cert trusted: {breakdown['cert_findings'].get('is_trusted')}")

    # ── Ordering + verdict validation ──────────────────────────────────────────
    off_score   = results["official"]["final_score"]
    plus_score  = results["plus"]["final_score"]
    clone_score = results["clone"]["final_score"]

    ordering_ok = off_score < plus_score < clone_score
    report["ordering_check"] = {
        "official_score":  off_score,
        "plus_score":      plus_score,
        "clone_score":     clone_score,
        "pass":            ordering_ok,
        "expected":        "official < plus < clone",
    }

    verdict_ok = (
        results["official"]["verdict"] == "SAFE"
        and results["plus"]["verdict"] in ("SUSPICIOUS", "MALICIOUS")
        and results["clone"]["verdict"] == "MALICIOUS"
    )
    report["verdict_check"] = {
        "official_verdict":  results["official"]["verdict"],
        "plus_verdict":      results["plus"]["verdict"],
        "clone_verdict":     results["clone"]["verdict"],
        "pass":              verdict_ok,
        "expected": {"official": "SAFE", "plus": "SUSPICIOUS|MALICIOUS", "clone": "MALICIOUS"},
    }

    print(f"\n{'='*60}")
    print(f"  ORDERING CHECK : {'PASS' if ordering_ok else 'FAIL'}")
    print(f"  VERDICT CHECK  : {'PASS' if verdict_ok else 'FAIL'}")

    # Write report
    out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "risk_engine_validation_report.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    print(f"\n  Report saved: {out_path}")

    if not ordering_ok or not verdict_ok:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
