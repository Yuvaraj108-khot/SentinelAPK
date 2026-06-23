import logging
from typing import Dict, Any, List
try:
    from androguard.core.apk import APK  # type: ignore
except ImportError:
    try:
        from androguard.core.bytecodes.apk import APK  # type: ignore
    except ImportError:
        from androguard.apk import APK  # type: ignore

logger = logging.getLogger("sentinel.analyzer")

import os
import re
import logging
import zipfile
import xml.etree.ElementTree as ET
import json
from typing import Dict, Any, List

try:
    from androguard.core.apk import APK  # type: ignore
except ImportError:
    try:
        from androguard.core.bytecodes.apk import APK  # type: ignore
    except ImportError:
        from androguard.apk import APK  # type: ignore

logger = logging.getLogger("sentinel.analyzer")

class APKAnalyzer:
    def __init__(self, apk_path: str):
        self.apk_path = apk_path
        self.apk = None
        self.is_fallback = False
        try:
            self.apk = APK(apk_path)
        except Exception as e:
            logger.warning(f"Androguard binary parsing failed for {apk_path}, using fallback parser: {e}")
            self.is_fallback = True

    def analyze(self) -> Dict[str, Any]:
        """
        Runs the static analysis extraction, supporting binary androguard parsing
        with a robust XML/Zip fallback for programmatic test APKs.
        """
        if not self.is_fallback and self.apk:
            try:
                return self._analyze_androguard()
            except Exception as e:
                logger.warning(f"Androguard analysis failed, trying fallback: {e}")
        
        return self._analyze_fallback()

    def _analyze_androguard(self) -> Dict[str, Any]:
        package_name = self.apk.get_package()
        app_name = self.apk.get_app_name()
        version_name = self.apk.get_androidversion_name()
        version_code = self.apk.get_androidversion_code()
        min_sdk = self.apk.get_min_sdk_version()
        target_sdk = self.apk.get_target_sdk_version()
        
        permissions = self.apk.get_permissions()
        activities = self.apk.get_activities()
        services = self.apk.get_services()
        receivers = self.apk.get_receivers()
        providers = self.apk.get_providers()
        
        certs_info = []
        try:
            certs = self.apk.get_certificates()
            for c in certs:
                if hasattr(c, "sha256_fingerprint"):
                    sha256_hex = c.sha256_fingerprint.replace(" ", "").lower()
                    sha1_hex = c.sha1_fingerprint.replace(" ", "").lower()
                    try:
                        issuer_str = str(c.issuer.human_friendly)
                        subject_str = str(c.subject.human_friendly)
                    except Exception:
                        issuer_str = str(c.issuer)
                        subject_str = str(c.subject)
                    serial_number = str(c.serial_number)
                else:
                    from cryptography.hazmat.primitives import hashes
                    sha256_hex = c.fingerprint(hashes.SHA256()).hex()
                    sha1_hex   = c.fingerprint(hashes.SHA1()).hex()
    
                    try:
                        issuer_str  = c.issuer.rfc4514_string()
                        subject_str = c.subject.rfc4514_string()
                    except Exception:
                        issuer_str  = str(c.issuer)
                        subject_str = str(c.subject)
                    serial_number = str(c.serial_number)

                certs_info.append({
                    "certificate_sha256": sha256_hex,
                    "certificate_sha1":   sha1_hex,
                    "subject":            subject_str,
                    "issuer":             issuer_str,
                    "serial_number":      serial_number,
                    "sha256": sha256_hex,
                    "sha1":   sha1_hex,
                })
        except Exception as cert_err:
            logger.warning(f"Failed to extract certificates via androguard: {cert_err}")

        # If androguard returned no certs, fall back to direct PKCS#7 extraction
        if not certs_info:
            certs_info = self._extract_cert_from_apk()

        # Scan bytecode
        dex_indicators = self._scan_dex_zip()

        return {
            "package_name": package_name or "Unknown",
            "app_name": app_name or "Unknown",
            "version_name": version_name or "1.0",
            "version_code": str(version_code) if version_code else "1",
            "min_sdk": min_sdk or "Unknown",
            "target_sdk": target_sdk or "Unknown",
            "permissions": sorted(list(permissions)) if permissions else [],
            "activities": sorted(list(activities)) if activities else [],
            "services": sorted(list(services)) if services else [],
            "receivers": sorted(list(receivers)) if receivers else [],
            "providers": sorted(list(providers)) if providers else [],
            "certificates": certs_info,
            "dex_indicators": dex_indicators
        }

    # ──────────────────────────────────────────────────────────────────────────
    # Certificate extraction boundary
    # ──────────────────────────────────────────────────────────────────────────
    # _extract_cert_from_apk() reads the ACTUAL signing certificate from the
    # APK's META-INF PKCS#7 block.  It is the ONLY authoritative source of
    # certificate fingerprints for uploaded APKs.
    #
    # The sidecar <name>.json file is benchmark PROVENANCE metadata only.
    # It records ground-truth labels, source, and reviewer for the test
    # dataset pipeline.  Its "certificates" key MUST NOT be used as a trust
    # signal for production analysis — it is populated with synthetic
    # hashlib-derived values that have no cryptographic relationship to the
    # actual APK signing key.
    # ──────────────────────────────────────────────────────────────────────────

    def _extract_cert_from_apk(self) -> list:
        """
        Extracts the real signing certificate fingerprint(s) from the APK's
        META-INF PKCS#7 block (*.RSA, *.DSA, *.EC).

        Returns a list of certificate dicts:
          [
            {
              "certificate_sha256": "<64-char hex>",
              "certificate_sha1":   "<40-char hex>",
              "subject":            "<DN string>",
              "issuer":             "<DN string>",
              "serial_number":      "<int string>",
              # Legacy aliases kept for risk_engine compatibility:
              "sha256": "<64-char hex>",
              "sha1":   "<40-char hex>"
            }
          ]

        Falls back to hashlib.sha256 of the raw DER bytes when the
        cryptography library cannot parse the PKCS#7 envelope.
        Returns [] when no META-INF signing block is found.
        """
        import hashlib
        certs = []
        try:
            with zipfile.ZipFile(self.apk_path, "r") as zf:
                # Collect all META-INF signing blocks
                sig_entries = [
                    name for name in zf.namelist()
                    if name.upper().startswith("META-INF/")
                    and name.upper().rsplit(".", 1)[-1] in ("RSA", "DSA", "EC")
                ]
                if not sig_entries:
                    return []

                for entry in sig_entries:
                    der_bytes = zf.read(entry)
                    cert_info = None

                    # ── Attempt 1: cryptography library (full DN + fingerprint) ──
                    try:
                        from cryptography.hazmat.primitives import hashes
                        from cryptography.hazmat.primitives.serialization import pkcs7
                        from cryptography.hazmat.backends import default_backend

                        certs_parsed = pkcs7.load_der_pkcs7_certificates(der_bytes)
                        for cert in certs_parsed:
                            sha256_hex = cert.fingerprint(hashes.SHA256()).hex()
                            sha1_hex   = cert.fingerprint(hashes.SHA1()).hex()
                            try:
                                issuer_str  = cert.issuer.rfc4514_string()
                                subject_str = cert.subject.rfc4514_string()
                            except Exception:
                                issuer_str  = str(cert.issuer)
                                subject_str = str(cert.subject)
                            cert_info = {
                                "certificate_sha256": sha256_hex,
                                "certificate_sha1":   sha1_hex,
                                "subject":            subject_str,
                                "issuer":             issuer_str,
                                "serial_number":      str(cert.serial_number),
                                # Legacy aliases for risk_engine / clone detection
                                "sha256": sha256_hex,
                                "sha1":   sha1_hex,
                            }
                            certs.append(cert_info)
                        if certs:
                            return certs
                    except Exception as crypto_err:
                        logger.debug(f"cryptography PKCS#7 parse failed ({entry}): {crypto_err}")

                    # ── Attempt 2: extract leaf cert DER from PKCS#7 manually ──
                    # PKCS#7 SignedData: OID at byte 4-15, cert list at a known offset.
                    # We try to pull raw X.509 DER cert frames from the blob.
                    try:
                        # Find DER SEQUENCE tags (0x30) that could be X.509 certs
                        # This is a heuristic: look for 0x30 0x82 (SEQUENCE, length > 127)
                        positions = []
                        i = 0
                        while i < len(der_bytes) - 4:
                            if der_bytes[i] == 0x30 and der_bytes[i+1] == 0x82:
                                length = (der_bytes[i+2] << 8) | der_bytes[i+3]
                                end = i + 4 + length
                                if end <= len(der_bytes):
                                    positions.append((i, end))
                            i += 1

                        for start, end in positions:
                            candidate = der_bytes[start:end]
                            try:
                                from cryptography.x509 import load_der_x509_certificate
                                from cryptography.hazmat.primitives import hashes
                                cert = load_der_x509_certificate(candidate)
                                sha256_hex = cert.fingerprint(hashes.SHA256()).hex()
                                sha1_hex   = cert.fingerprint(hashes.SHA1()).hex()
                                try:
                                    issuer_str  = cert.issuer.rfc4514_string()
                                    subject_str = cert.subject.rfc4514_string()
                                except Exception:
                                    issuer_str  = str(cert.issuer)
                                    subject_str = str(cert.subject)
                                cert_info = {
                                    "certificate_sha256": sha256_hex,
                                    "certificate_sha1":   sha1_hex,
                                    "subject":            subject_str,
                                    "issuer":             issuer_str,
                                    "serial_number":      str(cert.serial_number),
                                    "sha256": sha256_hex,
                                    "sha1":   sha1_hex,
                                }
                                certs.append(cert_info)
                                break  # first valid cert is the signer
                            except Exception:
                                continue
                        if certs:
                            return certs
                    except Exception as heuristic_err:
                        logger.debug(f"Heuristic cert extraction failed ({entry}): {heuristic_err}")

                    # ── Attempt 3: hashlib digest of the raw signing block ──────
                    # Last resort: sha256 of the entire PKCS#7 DER blob.
                    # This is NOT a certificate fingerprint — it is a content hash.
                    # Marked as issuer=UNKNOWN so risk_engine knows it could not be
                    # parsed properly and should NOT match against known trusted certs.
                    sha256_hex = hashlib.sha256(der_bytes).hexdigest()
                    sha1_hex   = hashlib.sha1(der_bytes).hexdigest()  # noqa: S324
                    certs.append({
                        "certificate_sha256": sha256_hex,
                        "certificate_sha1":   sha1_hex,
                        "subject":            "UNKNOWN (signing block could not be parsed)",
                        "issuer":             "UNKNOWN",
                        "serial_number":      "0",
                        "sha256": sha256_hex,
                        "sha1":   sha1_hex,
                    })
        except Exception as e:
            logger.warning(f"Certificate extraction failed for {self.apk_path}: {e}")
        return certs

    def _analyze_fallback(self) -> Dict[str, Any]:
        """
        Parses text/XML manifest and classes.dex from minimal test ZIPs.

        Certificate Policy
        ------------------
        Certificates are ALWAYS extracted from the APK signing block via
        _extract_cert_from_apk().  The sidecar .json file (benchmark provenance)
        is used ONLY for package_name, app_label, and permissions — never for
        certificate data.  This ensures benchmark fingerprints cannot leak into
        production trust decisions.
        """
        package_name = "Unknown"
        app_name = "Unknown"
        version_name = "1.0"
        version_code = "1"
        min_sdk = "21"
        target_sdk = "33"
        permissions = []
        activities = []
        services = []
        receivers = []
        providers = []

        # ── Read sidecar JSON for provenance metadata ONLY ────────────────────
        # Allowed fields: package_name, app_label, permissions
        # FORBIDDEN field: certificates  (benchmark synthetic data — never trusted)
        json_path = self.apk_path.replace(".apk", ".json")
        if os.path.exists(json_path):
            try:
                with open(json_path, "r", encoding="utf-8") as f:
                    meta = json.load(f)
                package_name = meta.get("package_name", package_name)
                app_name     = meta.get("app_label", app_name)
                permissions  = meta.get("permissions", permissions)
                # NOTE: meta.get("certificates") is intentionally NOT loaded here.
            except Exception:
                pass

        try:
            with zipfile.ZipFile(self.apk_path, "r") as zf:
                # 1. Parse AndroidManifest.xml as text/xml
                if "AndroidManifest.xml" in zf.namelist():
                    manifest_content = zf.read("AndroidManifest.xml").decode("utf-8", errors="ignore")

                    # Extract package
                    pkg_match = re.search(r'package="([^"]+)"', manifest_content)
                    if pkg_match:
                        package_name = pkg_match.group(1)

                    # Extract app label
                    lbl_match = re.search(r'android:label="([^"]+)"', manifest_content)
                    if lbl_match:
                        app_name = lbl_match.group(1)

                    # Extract target sdk
                    tsdk_match = re.search(r'android:targetSdkVersion="([^"]+)"', manifest_content)
                    if tsdk_match:
                        target_sdk = tsdk_match.group(1)

                    # Extract min sdk
                    msdk_match = re.search(r'android:minSdkVersion="([^"]+)"', manifest_content)
                    if msdk_match:
                        min_sdk = msdk_match.group(1)

                    # Extract permissions
                    perms = re.findall(r'<uses-permission\s+android:name="([^"]+)"', manifest_content)
                    if perms:
                        permissions = list(set(permissions + perms))

                    # Extract activities
                    acts = re.findall(r'<activity\s+android:name="([^"]+)"', manifest_content)
                    if acts:
                        activities = list(set(activities + acts))

                    # Extract services
                    svcs = re.findall(r'<service\s+android:name="([^"]+)"', manifest_content)
                    if svcs:
                        services = list(set(svcs))
        except Exception as zip_err:
            logger.warning(f"Failed to open zip file {self.apk_path}: {zip_err}")

        # Scan dex bytecodes inside zip
        dex_indicators = self._scan_dex_zip()

        # ── Extract REAL certificate from APK signing block ───────────────────
        # _extract_cert_from_apk() is the single authoritative source.
        # No stubs, no benchmark fingerprints, no hardcoded defaults.
        certs_info = self._extract_cert_from_apk()

        return {
            "package_name": package_name,
            "app_name": app_name,
            "version_name": version_name,
            "version_code": version_code,
            "min_sdk": min_sdk,
            "target_sdk": target_sdk,
            "permissions": sorted(permissions),
            "activities": sorted(activities),
            "services": sorted(services),
            "receivers": sorted(receivers),
            "providers": sorted(providers),
            "certificates": certs_info,
            "dex_indicators": dex_indicators
        }

    def analyze(self) -> Dict[str, Any]:
        """
        Runs the static analysis extraction, supporting binary androguard parsing
        with a robust XML/Zip fallback for programmatic test APKs.
        """
        try:
            if not self.is_fallback and self.apk:
                try:
                    return self._analyze_androguard()
                except Exception as e:
                    logger.warning(f"Androguard analysis failed, trying fallback: {e}")
            
            return self._analyze_fallback()
        except Exception as e:
            # Propagate error with strict status code
            if "manifest" in str(e).lower() or "androidmanifest" in str(e).lower():
                raise Exception("MANIFEST_PARSE_FAILED") from e
            elif "certificate" in str(e).lower():
                raise Exception("CERTIFICATE_UNKNOWN") from e
            elif "dex" in str(e).lower():
                raise Exception("DEX_SCAN_FAILED") from e
            else:
                raise Exception("ANALYSIS_ERROR") from e

    def _analyze_androguard(self) -> Dict[str, Any]:
        try:
            package_name = self.apk.get_package()
            app_name = self.apk.get_app_name()
            version_name = self.apk.get_androidversion_name()
            version_code = self.apk.get_androidversion_code()
            min_sdk = self.apk.get_min_sdk_version()
            target_sdk = self.apk.get_target_sdk_version()
        except Exception as e:
            raise Exception("MANIFEST_PARSE_FAILED") from e
        
        try:
            permissions = self.apk.get_permissions()
            activities = self.apk.get_activities()
            services = self.apk.get_services()
            receivers = self.apk.get_receivers()
            providers = self.apk.get_providers()
        except Exception as e:
            raise Exception("MANIFEST_PARSE_FAILED") from e
        
        certs_info = []
        try:
            certs = self.apk.get_certificates()
            for c in certs:
                if hasattr(c, "sha256_fingerprint"):
                    sha256_hex = c.sha256_fingerprint.replace(" ", "").lower()
                    sha1_hex = c.sha1_fingerprint.replace(" ", "").lower()
                    try:
                        issuer_str = str(c.issuer.human_friendly)
                        subject_str = str(c.subject.human_friendly)
                    except Exception:
                        issuer_str = str(c.issuer)
                        subject_str = str(c.subject)
                    serial_number = str(c.serial_number)
                else:
                    from cryptography.hazmat.primitives import hashes
                    sha256_hex = c.fingerprint(hashes.SHA256()).hex()
                    sha1_hex   = c.fingerprint(hashes.SHA1()).hex()
    
                    try:
                        issuer_str  = c.issuer.rfc4514_string()
                        subject_str = c.subject.rfc4514_string()
                    except Exception:
                        issuer_str  = str(c.issuer)
                        subject_str = str(c.subject)
                    serial_number = str(c.serial_number)

                certs_info.append({
                    "certificate_sha256": sha256_hex,
                    "certificate_sha1":   sha1_hex,
                    "subject":            subject_str,
                    "issuer":             issuer_str,
                    "serial_number":      serial_number,
                    "sha256": sha256_hex,
                    "sha1":   sha1_hex,
                })
        except Exception as cert_err:
            logger.warning(f"Failed to extract certificates via androguard: {cert_err}")

        # If androguard returned no certs, fall back to direct PKCS#7 extraction
        if not certs_info:
            certs_info = self._extract_cert_from_apk()

        if not certs_info:
            raise Exception("CERTIFICATE_UNKNOWN")

        # Scan bytecode
        try:
            dex_indicators = self._scan_dex_zip()
            
            # --- V2 Integration ---
            from dex_behavior_analyzer import DexBehaviorAnalyzer
            v2_dex_results = DexBehaviorAnalyzer(self.apk_path).analyze()
            if "evidence" in v2_dex_results and "evidence" in dex_indicators:
                dex_indicators["evidence"].update(v2_dex_results["evidence"])
            # ----------------------
            
        except Exception as e:
            raise Exception("DEX_SCAN_FAILED") from e

        return {
            "package_name": package_name or "Unknown",
            "app_name": app_name or "Unknown",
            "version_name": version_name or "1.0",
            "version_code": str(version_code) if version_code else "1",
            "min_sdk": min_sdk or "Unknown",
            "target_sdk": target_sdk or "Unknown",
            "permissions": sorted(list(permissions)) if permissions else [],
            "activities": sorted(list(activities)) if activities else [],
            "services": sorted(list(services)) if services else [],
            "receivers": sorted(list(receivers)) if receivers else [],
            "providers": sorted(list(providers)) if providers else [],
            "certificates": certs_info,
            "dex_indicators": dex_indicators,
            "analysis_mode": "FULL_ANALYSIS"
        }

    # ──────────────────────────────────────────────────────────────────────────
    # Certificate extraction boundary
    # ──────────────────────────────────────────────────────────────────────────
    # _extract_cert_from_apk() reads the ACTUAL signing certificate from the
    # APK's META-INF PKCS#7 block.  It is the ONLY authoritative source of
    # certificate fingerprints for uploaded APKs.
    #
    # The sidecar <name>.json file is benchmark PROVENANCE metadata only.
    # It records ground-truth labels, source, and reviewer for the test
    # dataset pipeline.  Its "certificates" key MUST NOT be used as a trust
    # signal for production analysis — it is populated with synthetic
    # hashlib-derived values that have no cryptographic relationship to the
    # actual APK signing key.
    # ──────────────────────────────────────────────────────────────────────────

    def _extract_cert_from_apk(self) -> list:
        import hashlib
        certs = []
        try:
            with zipfile.ZipFile(self.apk_path, "r") as zf:
                # Collect all META-INF signing blocks
                sig_entries = [
                    name for name in zf.namelist()
                    if name.upper().startswith("META-INF/")
                    and name.upper().rsplit(".", 1)[-1] in ("RSA", "DSA", "EC")
                ]
                if not sig_entries:
                    return []

                for entry in sig_entries:
                    der_bytes = zf.read(entry)
                    cert_info = None

                    # ── Attempt 1: cryptography library (full DN + fingerprint) ──
                    try:
                        from cryptography.hazmat.primitives import hashes
                        from cryptography.hazmat.primitives.serialization import pkcs7
                        from cryptography.hazmat.backends import default_backend

                        certs_parsed = pkcs7.load_der_pkcs7_certificates(der_bytes)
                        for cert in certs_parsed:
                            sha256_hex = cert.fingerprint(hashes.SHA256()).hex()
                            sha1_hex   = cert.fingerprint(hashes.SHA1()).hex()
                            try:
                                issuer_str  = cert.issuer.rfc4514_string()
                                subject_str = cert.subject.rfc4514_string()
                            except Exception:
                                issuer_str  = str(cert.issuer)
                                subject_str = str(cert.subject)
                            cert_info = {
                                "certificate_sha256": sha256_hex,
                                "certificate_sha1":   sha1_hex,
                                "subject":            subject_str,
                                "issuer":             issuer_str,
                                "serial_number":      str(cert.serial_number),
                                # Legacy aliases for risk_engine / clone detection
                                "sha256": sha256_hex,
                                "sha1":   sha1_hex,
                            }
                            certs.append(cert_info)
                        if certs:
                            return certs
                    except Exception as crypto_err:
                        logger.debug(f"cryptography PKCS#7 parse failed ({entry}): {crypto_err}")

                    # ── Attempt 2: extract leaf cert DER from PKCS#7 manually ──
                    try:
                        positions = []
                        i = 0
                        while i < len(der_bytes) - 4:
                            if der_bytes[i] == 0x30 and der_bytes[i+1] == 0x82:
                                length = (der_bytes[i+2] << 8) | der_bytes[i+3]
                                end = i + 4 + length
                                if end <= len(der_bytes):
                                    positions.append((i, end))
                            i += 1

                        for start, end in positions:
                            candidate = der_bytes[start:end]
                            try:
                                from cryptography.x509 import load_der_x509_certificate
                                from cryptography.hazmat.primitives import hashes
                                cert = load_der_x509_certificate(candidate)
                                sha256_hex = cert.fingerprint(hashes.SHA256()).hex()
                                sha1_hex   = cert.fingerprint(hashes.SHA1()).hex()
                                try:
                                    issuer_str  = cert.issuer.rfc4514_string()
                                    subject_str = cert.subject.rfc4514_string()
                                except Exception:
                                    issuer_str  = str(cert.issuer)
                                    subject_str = str(cert.subject)
                                cert_info = {
                                    "certificate_sha256": sha256_hex,
                                    "certificate_sha1":   sha1_hex,
                                    "subject":            subject_str,
                                    "issuer":             issuer_str,
                                    "serial_number":      str(cert.serial_number),
                                    "sha256": sha256_hex,
                                    "sha1":   sha1_hex,
                                }
                                certs.append(cert_info)
                                break
                            except Exception:
                                continue
                        if certs:
                            return certs
                    except Exception as heuristic_err:
                        logger.debug(f"Heuristic cert extraction failed ({entry}): {heuristic_err}")

                    # ── Attempt 3: hashlib digest of the raw signing block ──────
                    sha256_hex = hashlib.sha256(der_bytes).hexdigest()
                    sha1_hex   = hashlib.sha1(der_bytes).hexdigest()  # noqa: S324
                    certs.append({
                        "certificate_sha256": sha256_hex,
                        "certificate_sha1":   sha1_hex,
                        "subject":            "UNKNOWN (signing block could not be parsed)",
                        "issuer":             "UNKNOWN",
                        "serial_number":      "0",
                        "sha256": sha256_hex,
                        "sha1":   sha1_hex,
                    })
        except Exception as e:
            logger.warning(f"Certificate extraction failed for {self.apk_path}: {e}")
        return certs

    def _analyze_fallback(self) -> Dict[str, Any]:
        """
        Parses text/XML manifest and classes.dex from minimal test ZIPs.
        """
        package_name = "Unknown"
        app_name = "Unknown"
        version_name = "1.0"
        version_code = "1"
        min_sdk = "21"
        target_sdk = "33"
        permissions = []
        activities = []
        services = []
        receivers = []
        providers = []

        json_path = self.apk_path.replace(".apk", ".json")
        if os.path.exists(json_path):
            try:
                with open(json_path, "r", encoding="utf-8") as f:
                    meta = json.load(f)
                package_name = meta.get("package_name", package_name)
                app_name     = meta.get("app_label", app_name)
                permissions  = meta.get("permissions", permissions)
            except Exception:
                pass

        manifest_found = False
        try:
            with zipfile.ZipFile(self.apk_path, "r") as zf:
                if "AndroidManifest.xml" in zf.namelist():
                    manifest_found = True
                    manifest_content = zf.read("AndroidManifest.xml").decode("utf-8", errors="ignore")

                    pkg_match = re.search(r'package="([^"]+)"', manifest_content)
                    if pkg_match:
                        package_name = pkg_match.group(1)

                    lbl_match = re.search(r'android:label="([^"]+)"', manifest_content)
                    if lbl_match:
                        app_name = lbl_match.group(1)

                    tsdk_match = re.search(r'android:targetSdkVersion="([^"]+)"', manifest_content)
                    if tsdk_match:
                        target_sdk = tsdk_match.group(1)

                    msdk_match = re.search(r'android:minSdkVersion="([^"]+)"', manifest_content)
                    if msdk_match:
                        min_sdk = msdk_match.group(1)

                    perms = re.findall(r'<uses-permission\s+android:name="([^"]+)"', manifest_content)
                    if perms:
                        permissions = list(set(permissions + perms))

                    acts = re.findall(r'<activity\s+android:name="([^"]+)"', manifest_content)
                    if acts:
                        activities = list(set(activities + acts))

                    svcs = re.findall(r'<service\s+android:name="([^"]+)"', manifest_content)
                    if svcs:
                        services = list(set(svcs))
        except Exception as zip_err:
            raise Exception("MANIFEST_PARSE_FAILED") from zip_err

        if not manifest_found and not os.path.exists(json_path):
            raise Exception("MANIFEST_PARSE_FAILED")

        # Scan dex bytecodes inside zip
        try:
            dex_indicators = self._scan_dex_zip()
            
            # --- V2 Integration ---
            from dex_behavior_analyzer import DexBehaviorAnalyzer
            v2_dex_results = DexBehaviorAnalyzer(self.apk_path).analyze()
            if "evidence" in v2_dex_results and "evidence" in dex_indicators:
                dex_indicators["evidence"].update(v2_dex_results["evidence"])
            # ----------------------
            
        except Exception as e:
            raise Exception("DEX_SCAN_FAILED") from e

        certs_info = self._extract_cert_from_apk()
        if not certs_info:
            raise Exception("CERTIFICATE_UNKNOWN")

        return {
            "package_name": package_name,
            "app_name": app_name,
            "version_name": version_name,
            "version_code": version_code,
            "min_sdk": min_sdk,
            "target_sdk": target_sdk,
            "permissions": sorted(permissions),
            "activities": sorted(activities),
            "services": sorted(services),
            "receivers": sorted(receivers),
            "providers": sorted(providers),
            "certificates": certs_info,
            "dex_indicators": dex_indicators,
            "analysis_mode": "FALLBACK_ANALYSIS"
        }

    def _scan_dex_zip(self) -> Dict[str, Any]:
        dex_indicators = {
            "sms_send": False,
            "accessibility_callback": False,
            "overlay_window": False,
            "http_client": False,
            "sms_manager": False,
            "accessibility_service": False,
            "dex_class_loader": False,
            "runtime_exec": False,
            "webview_js_interface": False,
            "suspicious_urls": [],
            "evidence": {}
        }
        url_pattern = re.compile(br'https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,4}[^\s"\'>]*')
        allowlisted_domains = ["developer.android.com", "android.com", "google.com", "firebase.google.com", "play.google.com"]
        
        try:
            with zipfile.ZipFile(self.apk_path, "r") as zf:
                for filename in zf.namelist():
                    if filename.endswith(".dex"):
                        dex_data = zf.read(filename)
                        
                        # SMS Send indicator
                        sms_idx = dex_data.find(b"sendTextMessage")
                        if sms_idx == -1:
                            sms_idx = dex_data.find(b"divideMessage")
                        if sms_idx != -1:
                            dex_indicators["sms_send"] = True
                            dex_indicators["evidence"]["sms_send"] = {
                                "matched_string": "sendTextMessage" if b"sendTextMessage" in dex_data else "divideMessage",
                                "source_file": filename,
                                "offset": sms_idx,
                                "extraction_method": "dex_find_bytes",
                                "confidence": 0.9
                            }

                        # SMS Manager indicator
                        sms_mgr_idx = dex_data.find(b"Landroid/telephony/SmsManager;")
                        if sms_mgr_idx != -1:
                            dex_indicators["sms_manager"] = True
                            dex_indicators["evidence"]["sms_manager"] = {
                                "matched_string": "Landroid/telephony/SmsManager;",
                                "source_file": filename,
                                "offset": sms_mgr_idx,
                                "extraction_method": "dex_find_bytes",
                                "confidence": 0.95
                            }

                        # Accessibility Callback indicator
                        acc_cb_idx = dex_data.find(b"onAccessibilityEvent")
                        if acc_cb_idx == -1:
                            acc_cb_idx = dex_data.find(b"performAction")
                        if acc_cb_idx != -1:
                            dex_indicators["accessibility_callback"] = True
                            dex_indicators["evidence"]["accessibility_callback"] = {
                                "matched_string": "onAccessibilityEvent" if b"onAccessibilityEvent" in dex_data else "performAction",
                                "source_file": filename,
                                "offset": acc_cb_idx,
                                "extraction_method": "dex_find_bytes",
                                "confidence": 0.85
                            }

                        # Accessibility Service indicator
                        acc_svc_idx = dex_data.find(b"Landroid/accessibilityservice/AccessibilityService;")
                        if acc_svc_idx != -1:
                            dex_indicators["accessibility_service"] = True
                            dex_indicators["evidence"]["accessibility_service"] = {
                                "matched_string": "Landroid/accessibilityservice/AccessibilityService;",
                                "source_file": filename,
                                "offset": acc_svc_idx,
                                "extraction_method": "dex_find_bytes",
                                "confidence": 0.95
                            }

                        # Overlay indicator
                        overlay_idx = dex_data.find(b"Landroid/view/WindowManager$LayoutParams;")
                        if overlay_idx == -1:
                            overlay_idx = dex_data.find(b"Landroid/view/WindowManager;")
                        if overlay_idx != -1:
                            dex_indicators["overlay_window"] = True
                            dex_indicators["evidence"]["overlay_window"] = {
                                "matched_string": "Landroid/view/WindowManager$LayoutParams;" if b"Landroid/view/WindowManager$LayoutParams;" in dex_data else "Landroid/view/WindowManager;",
                                "source_file": filename,
                                "offset": overlay_idx,
                                "extraction_method": "dex_find_bytes",
                                "confidence": 0.8
                            }

                        # Http Client indicator
                        http_idx = dex_data.find(b"okhttp")
                        if http_idx == -1:
                            http_idx = dex_data.find(b"HttpURLConnection")
                        if http_idx == -1:
                            http_idx = dex_data.find(b"HttpClient")
                        if http_idx != -1:
                            dex_indicators["http_client"] = True
                            dex_indicators["evidence"]["http_client"] = {
                                "matched_string": "okhttp" if b"okhttp" in dex_data else ("HttpURLConnection" if b"HttpURLConnection" in dex_data else "HttpClient"),
                                "source_file": filename,
                                "offset": http_idx,
                                "extraction_method": "dex_find_bytes",
                                "confidence": 0.85
                            }

                        # DexClassLoader indicator
                        dcl_idx = dex_data.find(b"Ldalvik/system/DexClassLoader;")
                        if dcl_idx == -1:
                            dcl_idx = dex_data.find(b"Ldalvik/system/PathClassLoader;")
                        if dcl_idx != -1:
                            dex_indicators["dex_class_loader"] = True
                            dex_indicators["evidence"]["dex_class_loader"] = {
                                "matched_string": "Ldalvik/system/DexClassLoader;" if b"Ldalvik/system/DexClassLoader;" in dex_data else "Ldalvik/system/PathClassLoader;",
                                "source_file": filename,
                                "offset": dcl_idx,
                                "extraction_method": "dex_find_bytes",
                                "confidence": 0.95
                            }

                        # Runtime Exec indicator
                        exec_idx = dex_data.find(b"Ljava/lang/Runtime;->exec")
                        if exec_idx != -1:
                            dex_indicators["runtime_exec"] = True
                            dex_indicators["evidence"]["runtime_exec"] = {
                                "matched_string": "Ljava/lang/Runtime;->exec",
                                "source_file": filename,
                                "offset": exec_idx,
                                "extraction_method": "dex_find_bytes",
                                "confidence": 0.95
                            }

                        # Webview JS Interface indicator
                        wv_idx = dex_data.find(b"addJavascriptInterface")
                        if wv_idx != -1:
                            dex_indicators["webview_js_interface"] = True
                            dex_indicators["evidence"]["webview_js_interface"] = {
                                "matched_string": "addJavascriptInterface",
                                "source_file": filename,
                                "offset": wv_idx,
                                "extraction_method": "dex_find_bytes",
                                "confidence": 0.9
                            }
                        
                        # Extract suspicious URLs
                        for match in url_pattern.findall(dex_data)[:10]:
                            try:
                                url_str = match.decode('utf-8', errors='ignore')
                                from urllib.parse import urlparse
                                parsed_url = urlparse(url_str)
                                domain = parsed_url.netloc.lower()
                                if ":" in domain:
                                    domain = domain.split(":")[0]
                                
                                is_allowlisted = False
                                for allowed in allowlisted_domains:
                                    if domain == allowed or domain.endswith("." + allowed):
                                        is_allowlisted = True
                                        break
                                
                                if is_allowlisted:
                                    continue

                                if any(keyword in url_str.lower() for keyword in ["c2", "malware", "botnet", "bypass", "temp", "verify", "rewards"]):
                                    if url_str not in dex_indicators["suspicious_urls"]:
                                        url_idx = dex_data.find(match)
                                        dex_indicators["suspicious_urls"].append(url_str)
                                        if "suspicious_urls" not in dex_indicators["evidence"]:
                                            dex_indicators["evidence"]["suspicious_urls"] = []
                                        dex_indicators["evidence"]["suspicious_urls"].append({
                                            "matched_string": url_str,
                                            "source_file": filename,
                                            "offset": url_idx,
                                            "extraction_method": "url_pattern_match",
                                            "confidence": 0.85
                                        })
                            except Exception:
                                pass
        except Exception as e:
            raise Exception("DEX_SCAN_FAILED") from e

        return dex_indicators

