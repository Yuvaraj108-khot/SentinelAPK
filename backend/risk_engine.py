import os
import json
import difflib
from datetime import datetime, timezone
from typing import Dict, Any, List


class RiskEngine:

    @staticmethod
    def _normalize_sha256(raw: str) -> str:
        """
        Normalize a SHA256 fingerprint to a plain lowercase 64-char hex string
        for consistent comparison regardless of input format.

        Handles:
          - "SHA256:7A:B3:C2:..."        (colon-separated hex, prefixed)
          - "7a:b3:c2:..."               (colon-separated hex, no prefix)
          - "7ab3c2..."                  (raw 64-char hex)
          - "SHA256:7B:A9:E2" (stub — returned as-is lowercased for partial match)
        """
        s = raw.strip()
        # Remove "SHA256:" or "SHA1:" prefix
        for prefix in ("SHA256:", "SHA1:", "sha256:", "sha1:"):
            if s.startswith(prefix):
                s = s[len(prefix):]
                break
        # Remove colons and spaces
        s = s.replace(":", "").replace(" ", "").lower()
        return s

    @staticmethod
    def load_dynamic_weights() -> Dict[str, Any]:
        try:
            weights_path = os.path.join(os.path.dirname(__file__), "adaptive_weights.json")
            if os.path.exists(weights_path):
                with open(weights_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                return {k: v["value"] for k, v in data.items()}
        except Exception:
            pass
        # Fallbacks — used only if adaptive_weights.json is missing
        return {
            "READ_SMS": 20,
            "ACCESSIBILITY": 25,
            "SYSTEM_ALERT_WINDOW": 20,
            "DexClassLoader": 15,
            "DEX_SMS": 12,
            "Reflection": 10,
            "UnknownCertificate": 10,
            "PackageImpersonation": 20,
            "SamePkgForgery": 60,
            "RuntimeExec": 8,
            "WebviewBridge": 8,
            "SuspiciousUrl": 5,
        }

    @staticmethod
    def calculate_risk(
        permissions: List[str],
        has_services: bool,
        has_certs: bool,
        dex_indicators: Dict[str, Any] = None,
        package_name: str = "Unknown",
        certificates: List[Dict[str, Any]] = None,
        app_name: str = "Unknown",
        activities: List[str] = None
    ) -> Dict[str, Any]:
        """
        Calculates risk score using adaptive weights, Clone Detection,
        and Certificate Reputation check. Enforces strict NO EVIDENCE = NO DETECTION.
        """
        weights = RiskEngine.load_dynamic_weights()
        score = 0
        triggered_rules = []
        evidence_validation = {
            "sms": {"status": "UNKNOWN", "reason": "NO_EVIDENCE_AVAILABLE"},
            "accessibility": {"status": "UNKNOWN", "reason": "NO_EVIDENCE_AVAILABLE"},
            "overlay": {"status": "UNKNOWN", "reason": "NO_EVIDENCE_AVAILABLE"},
            "runtime_exec": {"status": "UNKNOWN", "reason": "NO_EVIDENCE_AVAILABLE"},
            "dynamic_loading": {"status": "UNKNOWN", "reason": "NO_EVIDENCE_AVAILABLE"},
            "clone_detection": {"status": "UNKNOWN", "reason": "NO_EVIDENCE_AVAILABLE"},
            "certificate_validation": {"status": "UNKNOWN", "reason": "NO_EVIDENCE_AVAILABLE"}
        }

        # Load weights
        acc_w     = weights.get("ACCESSIBILITY", 25)
        sms_w     = weights.get("READ_SMS", 20)
        overlay_w = weights.get("SYSTEM_ALERT_WINDOW", 20)
        dex_w     = weights.get("DexClassLoader", 15)
        dex_sms_w = weights.get("DEX_SMS", 12)
        refl_w    = weights.get("Reflection", 10)
        cert_w    = weights.get("UnknownCertificate", 10)
        imp_w     = weights.get("PackageImpersonation", 20)
        forgery_w = weights.get("SamePkgForgery", 45)
        rtexec_w  = weights.get("RuntimeExec", 8)
        webview_w = weights.get("WebviewBridge", 8)
        url_w     = weights.get("SuspiciousUrl", 5)

        # ── 1. Clone Detection & Brand Similarity ──────────────────────────────
        clone_findings = {
            "is_clone": False,
            "official_target": None,
            "brand_similarity": 0,
            "package_similarity": 0,
            "certificate_match": False,
            "clone_risk": "LOW"
        }

        banks_path    = os.path.join(os.path.dirname(__file__), "data", "official_banks.json")
        keywords_path = os.path.join(os.path.dirname(__file__), "data", "bank_keywords.json")

        banks = []
        if os.path.exists(banks_path):
            try:
                with open(banks_path, "r", encoding="utf-8") as f:
                    banks = json.load(f)
            except Exception:
                pass

        keywords = {}
        if os.path.exists(keywords_path):
            try:
                with open(keywords_path, "r", encoding="utf-8") as f:
                    keywords = json.load(f)
            except Exception:
                pass

        matched_bank = None
        for bank_id, kw_list in keywords.items():
            match_found = False
            if any(kw in app_name.lower() for kw in kw_list):
                match_found = True
            if any(kw in package_name.lower() for kw in kw_list):
                match_found = True
            if activities:
                for act in activities:
                    if any(kw in act.lower() for kw in kw_list):
                        match_found = True
                        break
            if match_found:
                matched_bank = bank_id
                break

        def is_official_app(package: str, certs: List[Dict[str, Any]], bank_detail: Dict[str, Any]) -> bool:
            if not bank_detail or not package or package == "Unknown":
                return False
            if package != bank_detail.get("package_name"):
                return False
            tc_hashes = [
                RiskEngine._normalize_sha256(h)
                for h in bank_detail.get("official_certificates", [])
            ]
            if "certificate_sha256" in bank_detail:
                tc_hashes.append(
                    RiskEngine._normalize_sha256(bank_detail["certificate_sha256"])
                )
            if not certs:
                return False
            for c in certs:
                c_norm = RiskEngine._normalize_sha256(c.get("sha256", ""))
                for tc_norm in tc_hashes:
                    if c_norm and tc_norm and (
                        c_norm == tc_norm
                        or (len(tc_norm) >= 8 and tc_norm in c_norm)
                        or (len(c_norm) >= 8 and c_norm in tc_norm)
                    ):
                        return True
            return False

        if matched_bank or (package_name and package_name != "Unknown"):
            matching_bank_detail = None

            # Exact package name match first
            for b in banks:
                if b["package_name"] == package_name:
                    matching_bank_detail = b
                    break

            # Keyword → bank name fallback
            if not matching_bank_detail and matched_bank:
                mapped_name = {
                    "SBI": "State Bank of India",
                    "ICICI": "ICICI Bank",
                    "HDFC": "HDFC Bank",
                    "SecureBank": "SecureBank Official",
                }.get(matched_bank, matched_bank)

                for b in banks:
                    b_name = b["bank_name"].lower()
                    if mapped_name.lower() in b_name or b_name in mapped_name.lower():
                        matching_bank_detail = b
                        break

            if matching_bank_detail:
                tgt_pkg   = matching_bank_detail["package_name"]
                tgt_label = matching_bank_detail["bank_name"]

                pkg_sim = difflib.SequenceMatcher(None, package_name, tgt_pkg).ratio()
                lbl_sim = difflib.SequenceMatcher(None, app_name.lower(), tgt_label.lower()).ratio()

                # Centralized official app verification
                official_verified = is_official_app(package_name, certificates, matching_bank_detail)

                clone_findings["official_target"]    = tgt_label
                clone_findings["brand_similarity"]   = round(lbl_sim * 100)
                clone_findings["package_similarity"] = round(pkg_sim * 100)
                clone_findings["certificate_match"]  = official_verified

                if official_verified:
                    clone_findings["clone_risk"] = "LOW"
                    clone_findings["is_clone"]   = False
                    evidence_validation["clone_detection"] = {
                        "status": "UNKNOWN",
                        "matched_string": "Verified Legitimate Official Application",
                        "source_file": "AndroidManifest.xml",
                        "offset": 0,
                        "extraction_method": "is_official_app_check",
                        "confidence": 1.0
                    }
                else:
                    if package_name == tgt_pkg:
                        clone_findings["clone_risk"] = "HIGH"
                        clone_findings["is_clone"]   = True
                    elif (pkg_sim >= 0.55 or lbl_sim >= 0.55):
                        clone_findings["is_clone"] = True
                        if pkg_sim >= 0.75 or lbl_sim >= 0.75:
                            clone_findings["clone_risk"] = "HIGH"
                        else:
                            clone_findings["clone_risk"] = "MEDIUM"

                # Score clone detection only if clone findings evidence exists and is_clone is True
                if clone_findings["is_clone"] and clone_findings["clone_risk"] in ["HIGH", "MEDIUM"]:
                    evidence_validation["clone_detection"] = {
                        "status": "FOUND",
                        "matched_string": f"Impersonates {tgt_label} (brand_sim={clone_findings['brand_similarity']}%, pkg_sim={clone_findings['package_similarity']}%)",
                        "source_file": "AndroidManifest.xml",
                        "offset": 0,
                        "extraction_method": "manifest_similarity_comparison",
                        "confidence": 0.85
                    }
                    if package_name == tgt_pkg:
                        penalty = forgery_w
                        rule_label = "SamePkgForgery"
                        rule_desc = (
                            f"Same-Package Forgery: Exact package '{package_name}' with "
                            f"mismatched certificate (risk: HIGH)"
                        )
                    else:
                        penalty = imp_w
                        rule_label = "PackageImpersonation"
                        rule_desc = (
                            f"Banking Clone: Impersonates {tgt_label} "
                            f"(brand: {clone_findings['brand_similarity']}%, "
                            f"pkg: {clone_findings['package_similarity']}%, "
                            f"risk: {clone_findings['clone_risk']})"
                        )
                    score += penalty
                    triggered_rules.append({
                        "permission": rule_label,
                        "weight": penalty,
                        "description": rule_desc
                    })

        # ── 2. Certificate Reputation ──────────────────────────────────────────
        cert_findings = {"is_trusted": True, "reputation_issue": None, "status": "UNKNOWN"}
        trusted_path  = os.path.join(os.path.dirname(__file__), "data", "trusted_certificates.json")

        if not has_certs or not certificates:
            cert_findings["is_trusted"]     = False
            cert_findings["reputation_issue"] = "Certificate missing or extraction failed"
            cert_findings["status"]         = "UNTRUSTED"
            score += cert_w
            triggered_rules.append({
                "permission": "UnknownCertificate",
                "weight": cert_w,
                "description": "Certificate missing, malformed, or extraction failed"
            })
            evidence_validation["certificate_validation"] = {
                "status": "UNTRUSTED",
                "matched_string": "Certificate missing or extraction failed",
                "source_file": "META-INF/*",
                "offset": 0,
                "extraction_method": "signature_scan",
                "confidence": 1.0
            }
        elif os.path.exists(trusted_path):
            try:
                with open(trusted_path, "r", encoding="utf-8") as f:
                    trusted_certs = json.load(f)

                trusted_norms = [
                    RiskEngine._normalize_sha256(tc.get("sha256", ""))
                    for tc in trusted_certs
                ]

                # Check if official app verified earlier
                if clone_findings.get("certificate_match") == True:
                    cert_findings["status"] = "TRUSTED"
                    evidence_validation["certificate_validation"] = {
                        "status": "TRUSTED",
                        "matched_string": "Trusted Official Certificate (Verified)",
                        "source_file": "META-INF/CERT.RSA",
                        "offset": 0,
                        "extraction_method": "signature_scan_comparison",
                        "confidence": 1.0
                    }
                else:
                    cert_penalty_fired = False
                    for c in certificates:
                        if cert_penalty_fired:
                            break
                        c_norm = RiskEngine._normalize_sha256(c.get("sha256", ""))
                        issuer_val = c.get("issuer", "")
                        
                        # Validate if certificate was successfully parsed
                        if not c_norm or len(c_norm) != 64:
                            cert_findings["is_trusted"]     = False
                            cert_findings["reputation_issue"] = "Certificate malformed or fingerprint invalid"
                            cert_findings["status"]         = "UNTRUSTED"
                            score += cert_w
                            triggered_rules.append({
                                "permission": "UnknownCertificate",
                                "weight": cert_w,
                                "description": "Certificate malformed or fingerprint invalid"
                            })
                            evidence_validation["certificate_validation"] = {
                                "status": "UNTRUSTED",
                                "matched_string": f"Invalid fingerprint: {c_norm}",
                                "source_file": "META-INF/CERT.RSA",
                                "offset": 0,
                                "extraction_method": "signature_scan",
                                "confidence": 1.0
                            }
                            cert_penalty_fired = True
                            continue

                        match_found = any(
                            c_norm and tc_norm and (
                                c_norm == tc_norm
                                or (len(tc_norm) >= 8 and tc_norm in c_norm)
                                or (len(c_norm) >= 8 and c_norm in tc_norm)
                            )
                            for tc_norm in trusted_norms
                        )

                        if match_found:
                            cert_findings["status"] = "TRUSTED"
                            evidence_validation["certificate_validation"] = {
                                "status": "TRUSTED",
                                "matched_string": f"Trusted signature: sha256={c_norm}",
                                "source_file": "META-INF/CERT.RSA",
                                "offset": 0,
                                "extraction_method": "signature_scan_comparison",
                                "confidence": 1.0
                            }
                            cert_penalty_fired = True
                        else:
                            cert_findings["is_trusted"]     = False
                            cert_findings["reputation_issue"] = "Unknown / Self-signed certificate"
                            cert_findings["status"]         = "UNKNOWN"
                            # UNKNOWN = 0 penalty
                            triggered_rules.append({
                                "permission": "UnknownCertificate",
                                "weight": 0,
                                "description": f"Unknown certificate: issuer '{issuer_val}'"
                            })
                            evidence_validation["certificate_validation"] = {
                                "status": "UNKNOWN",
                                "matched_string": f"Unknown certificate: sha256={c_norm}",
                                "source_file": "META-INF/CERT.RSA",
                                "offset": 0,
                                "extraction_method": "signature_scan_comparison",
                                "confidence": 0.95
                            }
                            cert_penalty_fired = True
            except Exception:
                cert_findings["status"] = "UNKNOWN"
        else:
            cert_findings["status"] = "UNKNOWN"

        # ── 2.5 Security Vendor Recognition ───────────────────────────────────
        security_vendor_verified = False
        security_vendors_path = os.path.join(os.path.dirname(__file__), "data", "security_vendors.json")
        if os.path.exists(security_vendors_path) and cert_findings.get("status") == "TRUSTED":
            try:
                with open(security_vendors_path, "r", encoding="utf-8") as f:
                    vendors = json.load(f)
                for v in vendors:
                    if v.get("package_name") == package_name:
                        v_norm = RiskEngine._normalize_sha256(v.get("certificate_sha256", ""))
                        if certificates:
                            for c in certificates:
                                c_norm = RiskEngine._normalize_sha256(c.get("sha256", ""))
                                if c_norm == v_norm:
                                    security_vendor_verified = True
                                    break
                    if security_vendor_verified:
                        break
            except Exception:
                pass

        # ── 3. Permission Checks ───────────────────────────────────────────────
        if "android.permission.BIND_ACCESSIBILITY_SERVICE" in permissions:
            act_acc_w = 5 if security_vendor_verified else acc_w
            score += act_acc_w
            triggered_rules.append({
                "permission": "ACCESSIBILITY",
                "weight": act_acc_w,
                "description": "Requests high-risk Accessibility Service permission (verified security vendor: reduced risk)" if security_vendor_verified else "Requests high-risk Accessibility Service permission"
            })
            evidence_validation["accessibility"] = {
                "status": "FOUND",
                "matched_string": "android.permission.BIND_ACCESSIBILITY_SERVICE",
                "source_file": "AndroidManifest.xml",
                "offset": 0,
                "extraction_method": "manifest_permission_tag",
                "confidence": 1.0
            }

        has_sms_perm = any(
            p in permissions for p in [
                "android.permission.READ_SMS",
                "android.permission.RECEIVE_SMS",
                "android.permission.SEND_SMS"
            ]
        )
        if has_sms_perm:
            score += sms_w
            triggered_rules.append({
                "permission": "READ_SMS",
                "weight": sms_w,
                "description": "Requests SMS OTP interception permissions"
            })
            matched_perms = [p for p in permissions if p in ["android.permission.READ_SMS", "android.permission.RECEIVE_SMS", "android.permission.SEND_SMS"]]
            evidence_validation["sms"] = {
                "status": "FOUND",
                "matched_string": ", ".join(matched_perms),
                "source_file": "AndroidManifest.xml",
                "offset": 0,
                "extraction_method": "manifest_permission_tag",
                "confidence": 1.0
            }

        if "android.permission.SYSTEM_ALERT_WINDOW" in permissions:
            act_overlay_w = 5 if security_vendor_verified else overlay_w
            score += act_overlay_w
            triggered_rules.append({
                "permission": "SYSTEM_ALERT_WINDOW",
                "weight": act_overlay_w,
                "description": "Requests System Alert overlay window (verified security vendor: reduced risk)" if security_vendor_verified else "Requests System Alert overlay window"
            })
            evidence_validation["overlay"] = {
                "status": "FOUND",
                "matched_string": "android.permission.SYSTEM_ALERT_WINDOW",
                "source_file": "AndroidManifest.xml",
                "offset": 0,
                "extraction_method": "manifest_permission_tag",
                "confidence": 1.0
            }

        # ── 4. DEX Bytecode Checks ─────────────────────────────────────────────
        if dex_indicators:
            dex_evidence = dex_indicators.get("evidence", {})
            
            # DEX SMS checks
            if dex_indicators.get("sms_send") or dex_indicators.get("sms_manager"):
                ev = dex_evidence.get("sms_send") or dex_evidence.get("sms_manager")
                if ev:
                    score += dex_sms_w
                    triggered_rules.append({
                        "permission": "DEX_SMS",
                        "weight": dex_sms_w,
                        "description": "DEX: Contains SMS sending bytecode"
                    })
                    evidence_validation["sms"] = {
                        "status": "FOUND",
                        "matched_string": ev.get("matched_string", "SMS_DEX"),
                        "source_file": ev.get("source_file", "classes.dex"),
                        "offset": ev.get("offset", 0),
                        "extraction_method": ev.get("extraction_method", "dex_find_bytes"),
                        "confidence": ev.get("confidence", 0.9)
                    }

            # Reflection / Accessibility
            if dex_indicators.get("accessibility_callback") or dex_indicators.get("accessibility_service"):
                ev = dex_evidence.get("accessibility_callback") or dex_evidence.get("accessibility_service")
                if ev:
                    score += refl_w
                    triggered_rules.append({
                        "permission": "Reflection",
                        "weight": refl_w,
                        "description": "DEX: Contains Accessibility service callbacks"
                    })
                    evidence_validation["accessibility"] = {
                        "status": "FOUND",
                        "matched_string": ev.get("matched_string", "onAccessibilityEvent"),
                        "source_file": ev.get("source_file", "classes.dex"),
                        "offset": ev.get("offset", 0),
                        "extraction_method": ev.get("extraction_method", "dex_find_bytes"),
                        "confidence": ev.get("confidence", 0.85)
                    }

            # DexClassLoader
            if dex_indicators.get("dex_class_loader"):
                ev = dex_evidence.get("dex_class_loader")
                if ev:
                    score += dex_w
                    triggered_rules.append({
                        "permission": "DexClassLoader",
                        "weight": dex_w,
                        "description": "DEX: Dynamic class loading (DexClassLoader)"
                    })
                    evidence_validation["dynamic_loading"] = {
                        "status": "FOUND",
                        "matched_string": ev.get("matched_string", "Ldalvik/system/DexClassLoader;"),
                        "source_file": ev.get("source_file", "classes.dex"),
                        "offset": ev.get("offset", 0),
                        "extraction_method": ev.get("extraction_method", "dex_find_bytes"),
                        "confidence": ev.get("confidence", 0.95)
                    }

            # Runtime.exec
            if dex_indicators.get("runtime_exec"):
                ev = dex_evidence.get("runtime_exec")
                if ev:
                    score += rtexec_w
                    triggered_rules.append({
                        "permission": "RuntimeExec",
                        "weight": rtexec_w,
                        "description": "DEX: Spawns shell commands via Runtime.exec"
                    })
                    evidence_validation["runtime_exec"] = {
                        "status": "FOUND",
                        "matched_string": ev.get("matched_string", "Ljava/lang/Runtime;->exec"),
                        "source_file": ev.get("source_file", "classes.dex"),
                        "offset": ev.get("offset", 0),
                        "extraction_method": ev.get("extraction_method", "dex_find_bytes"),
                        "confidence": ev.get("confidence", 0.95)
                    }

            # WebviewBridge
            if dex_indicators.get("webview_js_interface"):
                ev = dex_evidence.get("webview_js_interface")
                if ev:
                    score += webview_w
                    triggered_rules.append({
                        "permission": "WebviewBridge",
                        "weight": webview_w,
                        "description": "DEX: Exposes native bridge via addJavascriptInterface"
                    })

            # Suspicious URL
            if dex_indicators.get("suspicious_urls"):
                ev_list = dex_evidence.get("suspicious_urls", [])
                if ev_list:
                    score += url_w
                    triggered_rules.append({
                        "permission": "SuspiciousUrl",
                        "weight": url_w,
                        "description": f"DEX: Suspicious URL found: {dex_indicators.get('suspicious_urls')[0]}"
                    })

        # ── 5. Hard Clamp ──────────────────────────────────────────────────────
        score = min(score, 100)

        # ── 6. Memory Retrieval: top-3 multi-signal lessons ─────────────────────────────
        retrieved_lessons: List[Dict[str, Any]] = []
        score_before_retrieval = score
        initial_verdict = "MALICIOUS" if score >= 70 else ("SUSPICIOUS" if score >= 35 else "SAFE")
        learning_influenced = False

        memory_path = os.path.join(os.path.dirname(__file__), "data", "learning_memory.json")

        if os.path.exists(memory_path):
            try:
                with open(memory_path, "r", encoding="utf-8") as f:
                    memory = json.load(f)

                if memory:
                    current_dex_set: set = set()
                    if dex_indicators and isinstance(dex_indicators, dict):
                        current_dex_set = {
                            k for k, v in dex_indicators.items()
                            if v and k not in ("suspicious_urls", "evidence")
                        }
                    elif dex_indicators and isinstance(dex_indicators, list):
                        current_dex_set = set(dex_indicators)

                    current_perms_set = set(permissions)

                    scored_entries: list = []
                    for entry in memory:
                        if (
                            entry.get("package_name") == package_name
                            and package_name not in ("Unknown", "")
                        ):
                            sim = 1.0
                        else:
                            ep = set(entry.get("permissions", []))
                            union_p = current_perms_set | ep
                            j_perms = len(current_perms_set & ep) / len(union_p) if union_p else 0.0

                            if j_perms < 0.15:
                                continue

                            ed = set(entry.get("dex_indicators", []))
                            union_d = current_dex_set | ed
                            j_dex = len(current_dex_set & ed) / len(union_d) if union_d else 0.0

                            sim = 0.70 * j_perms + 0.30 * j_dex

                        if sim >= 0.45:
                            scored_entries.append((sim, entry))

                    top3 = sorted(scored_entries, key=lambda x: -x[0])[:3]
                    MAX_DELTA_PER_LESSON = 15
                    cumulative_delta = 0.0

                    for sim, entry in top3:
                        error_type  = entry.get("error_type", "")
                        gt          = entry.get("ground_truth", "")
                        lesson_text = entry.get("lesson", "")

                        if error_type == "FALSE_NEGATIVE":
                            delta      = sim * MAX_DELTA_PER_LESSON
                            direction  = "escalated"
                        elif error_type == "FALSE_POSITIVE":
                            delta      = -(sim * MAX_DELTA_PER_LESSON)
                            direction  = "de-escalated"
                        else:
                            delta      = 0.0
                            direction  = "neutral"

                        cumulative_delta += delta
                        retrieved_lessons.append({
                            "similarity":    round(sim, 3),
                            "error_type":    error_type,
                            "ground_truth":  gt,
                            "lesson":        lesson_text,
                            "score_delta":   round(delta, 2),
                            "direction":     direction,
                        })

                    if retrieved_lessons and cumulative_delta != 0.0:
                        raw_after = score + cumulative_delta
                        score_after = int(min(100, max(0, round(raw_after))))
                        if score_after != score:
                            score = score_after
                            learning_influenced = True

            except Exception as mem_err:
                import logging as _log
                _log.getLogger("sentinel.risk_engine").warning(
                    f"Memory retrieval failed: {mem_err}"
                )

        # ── Write learning trace report ───────────────────────────────────────────────
        try:
            trace_path = os.path.join(
                os.path.dirname(__file__), "data", "learning_trace_report.json"
            )
            def _verdict_from_score(s: int) -> str:
                return "MALICIOUS" if s >= 70 else ("SUSPICIOUS" if s >= 35 else "SAFE")

            verdict_before = _verdict_from_score(score_before_retrieval)
            verdict_after  = _verdict_from_score(score) if learning_influenced else verdict_before

            trace_report = {
                "timestamp":        datetime.now(timezone.utc).isoformat(),
                "apk": {
                    "package_name":  package_name,
                    "app_name":      app_name,
                },
                "retrieved_lessons": retrieved_lessons,
                "score_before_retrieval": score_before_retrieval,
                "verdict_before_retrieval": verdict_before,
                "score_after_retrieval":  score if learning_influenced else score_before_retrieval,
                "verdict_after_retrieval": verdict_after,
                "cumulative_delta":  round(
                    sum(l["score_delta"] for l in retrieved_lessons), 2
                ),
                "learning_influenced": learning_influenced,
                "influence_note": (
                    f"Retrieved {len(retrieved_lessons)} lesson(s); "
                    f"score shifted {score_before_retrieval} -> {score}."
                    if learning_influenced
                    else "no learning influence detected"
                ),
            }
            with open(trace_path, "w", encoding="utf-8") as tf:
                json.dump(trace_report, tf, indent=2)
        except Exception:
            pass

        # ── 7. Final Verdict ───────────────────────────────────────────────────
        if score >= 70:
            verdict  = "MALICIOUS"
            severity = "Critical"
        elif score >= 35:
            verdict  = "SUSPICIOUS"
            severity = "Medium"
        else:
            verdict  = "SAFE"
            severity = "Low"

        confidence = min(50 + score, 98)

        # ── 8. Attack Chain ────────────────────────────────────────────────────
        attack_chain = []
        if evidence_validation["accessibility"].get("status") != "UNKNOWN":
            attack_chain.append({
                "step": "Accessibility Enabled",
                "desc": "Logs screen telemetry and intercepts UI events."
            })
        if evidence_validation["sms"].get("status") != "UNKNOWN":
            attack_chain.append({
                "step": "SMS OTP Steal",
                "desc": "Intercepts and suppresses incoming OTP messages."
            })
        if clone_findings.get("is_clone"):
            attack_chain.append({
                "step": "UI Impersonation",
                "desc": f"Mimics {clone_findings.get('official_target', 'official app')} to harvest credentials."
            })
        if not attack_chain:
            attack_chain = [{"step": "Safe Execution", "desc": "No hazardous indicator chains detected."}]

        # ── 7. Evidence-driven MITRE Mappings ─────────────────────────────
        mitre_techs = []
        if evidence_validation["sms"].get("status") != "UNKNOWN":
            mitre_techs.append({
                "id": "T1647",
                "name": "SMS Collection",
                "description": f"Accessing messages to steal OTPs. Evidence: {evidence_validation['sms']['matched_string']}"
            })
        if evidence_validation["overlay"].get("status") != "UNKNOWN":
            mitre_techs.append({
                "id": "T1418",
                "name": "Input Capture / Overlay Capability",
                "description": f"Overlay capability detected which could be used to capture credentials. Evidence: {evidence_validation['overlay']['matched_string']}"
            })
        if evidence_validation["dynamic_loading"].get("status") != "UNKNOWN":
            mitre_techs.append({
                "id": "T1407",
                "name": "Dynamic Code Loading",
                "description": f"Loading execution payloads dynamically. Evidence: {evidence_validation['dynamic_loading']['matched_string']}"
            })
        if evidence_validation["runtime_exec"].get("status") != "UNKNOWN":
            mitre_techs.append({
                "id": "T1406",
                "name": "Command Execution",
                "description": f"Executing system shell commands. Evidence: {evidence_validation['runtime_exec']['matched_string']}"
            })
        if evidence_validation["accessibility"].get("status") != "UNKNOWN":
            mitre_techs.append({
                "id": "T1430",
                "name": "Input Capture / Accessibility Capability",
                "description": f"Accessibility capability detected which could be used to capture keystrokes, read screen contents, and click buttons. Evidence: {evidence_validation['accessibility']['matched_string']}"
            })
        if evidence_validation["clone_detection"].get("status") != "UNKNOWN":
            mitre_techs.append({
                "id": "T1474",
                "name": "Masquerading / Brand Impersonation",
                "description": f"Spoofing legitimate applications to harvest bank logins. Evidence: {evidence_validation['clone_detection']['matched_string']}"
            })
        if evidence_validation["certificate_validation"].get("status") != "UNKNOWN":
            mitre_techs.append({
                "id": "T1473",
                "name": "Signature Theft / Untrusted Signing",
                "description": f"Using invalid or unknown signatures to bypass device verification. Evidence: {evidence_validation['certificate_validation']['matched_string']}"
            })

        # --- V2 Integration ---
        try:
            from behavior_correlation_engine import BehaviorCorrelationEngine
            from attack_chain_engine import AttackChainEngine
    
            metadata = {"permissions": permissions}
            behavioral_threats = BehaviorCorrelationEngine.evaluate(
                metadata=metadata, 
                evidence_validation=evidence_validation, 
                clone_findings=clone_findings, 
                cert_findings=cert_findings
            )
            
            attack_chain_result = AttackChainEngine.build_chains(
                correlated_threats=behavioral_threats, 
                evidence_validation=evidence_validation
            )
            attack_chains = attack_chain_result.get("attack_chains", [])
        except Exception:
            behavioral_threats = []
            attack_chains = []
        # ----------------------

        return {
            "score":            score,
            "verdict":          verdict,
            "severity":         severity,
            "confidence":       confidence,
            "top_reasons":      [r["description"] for r in triggered_rules[:4]] or ["No risk indicators triggered."],
            "triggered_rules":  triggered_rules,
            "mitre_techniques": mitre_techs,
            "attack_chain":     attack_chain,
            "clone_findings":   clone_findings,
            "cert_findings":    cert_findings,
            "initial_verdict":  initial_verdict,
            "retrieved_lessons": retrieved_lessons,
            "evidence_validation": evidence_validation,
            "behavioral_threats": behavioral_threats,
            "attack_chains": attack_chains,
            "analysis_version": "V2"
        }

    def evaluate(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """
        Instance helper method called during benchmark execution.
        """
        permissions    = features.get("permissions", [])
        has_services   = len(features.get("services", [])) > 0
        has_certs      = len(features.get("certificates", [])) > 0
        dex_indicators = features.get("dex_indicators", {})

        if isinstance(dex_indicators, list):
            dex_indicators_dict = {}
            for item in dex_indicators:
                if "SmsManager" in item or "sendTextMessage" in item:
                    dex_indicators_dict["sms_send"] = True
                if "AccessibilityService" in item or "onAccessibilityEvent" in item:
                    dex_indicators_dict["accessibility_callback"] = True
                if "DexClassLoader" in item:
                    dex_indicators_dict["dex_class_loader"] = True
                if "Runtime.exec" in item or "exec" in item:
                    dex_indicators_dict["runtime_exec"] = True
            dex_indicators = dex_indicators_dict

        return self.calculate_risk(
            permissions,
            has_services,
            has_certs,
            dex_indicators,
            features.get("package_name", "Unknown"),
            features.get("certificates", []),
            features.get("app_name", "Unknown"),
            features.get("activities", []),
        )
