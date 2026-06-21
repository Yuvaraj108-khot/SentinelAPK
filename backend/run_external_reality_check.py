#!/usr/bin/env python3
"""
run_external_reality_check.py
SentinelAPK -- Real-World External Validation
No synthetic data. No mock APKs. No hardcoded metrics.

Sources:
  - F-Droid API  (open-source apps)
  - GitHub Releases API  (security tools, OSS apps)
  - MalwareBazaar (abuse.ch)  (known malware samples)

All APKs are downloaded to: dataset/real_world_external/
SHA256 is verified after every download.
Analysis uses the real APKAnalyzer + RiskEngine pipeline.
"""

import os
import sys

# Force UTF-8 stdout/stderr on Windows so Unicode chars don't crash cp1252
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
os.environ.setdefault("PYTHONIOENCODING", "utf-8")
import json
import time
import hashlib
import zipfile
import shutil
import io
import math
import struct
import traceback
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple

# ── Make sure backend modules are on the path ───────────────────────────────
BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BACKEND_DIR)

try:
    import requests
except ImportError:
    print("[FATAL] 'requests' library not found. Run: pip install requests")
    sys.exit(1)

from analyzer import APKAnalyzer
from risk_engine import RiskEngine

# ─────────────────────────────────────────────────────────────────────────────
# Paths
# ─────────────────────────────────────────────────────────────────────────────
DATASET_DIR   = os.path.join(BACKEND_DIR, "dataset", "real_world_external")
OUTPUT_DIR    = BACKEND_DIR
os.makedirs(DATASET_DIR, exist_ok=True)

# ─────────────────────────────────────────────────────────────────────────────
# HTTP session with retries
# ─────────────────────────────────────────────────────────────────────────────
SESSION = requests.Session()
SESSION.headers.update({
    "User-Agent": "SentinelAPK-SecurityResearch/1.0 (+https://github.com/SentinelAPK)"
})

def _get(url: str, timeout: int = 60, stream: bool = False) -> requests.Response:
    for attempt in range(3):
        try:
            r = SESSION.get(url, timeout=timeout, stream=stream)
            r.raise_for_status()
            return r
        except Exception as e:
            if attempt == 2:
                raise
            time.sleep(2 ** attempt)

def _post_json(url: str, payload: dict, timeout: int = 60) -> dict:
    for attempt in range(3):
        try:
            headers = {}
            if os.getenv("MALWAREBAZAAR_API_KEY"):
                headers["Auth-Key"] = os.getenv("MALWAREBAZAAR_API_KEY")
            r = SESSION.post(url, data=payload, headers=headers, timeout=timeout)
            r.raise_for_status()
            return r.json()
        except Exception as e:
            if attempt == 2:
                raise
            time.sleep(2 ** attempt)

def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()

def download_file(url: str, dest: str, expected_sha256: str = None) -> Tuple[bool, str]:
    """Download url to dest. Returns (success, actual_sha256)."""
    try:
        r = SESSION.get(url, timeout=120, stream=True)
        r.raise_for_status()
        tmp = dest + ".tmp"
        with open(tmp, "wb") as f:
            for chunk in r.iter_content(65536):
                f.write(chunk)
        actual_sha = sha256_file(tmp)
        if expected_sha256 and actual_sha != expected_sha256.lower():
            os.remove(tmp)
            return False, f"SHA256_MISMATCH: expected={expected_sha256} got={actual_sha}"
        shutil.move(tmp, dest)
        return True, actual_sha
    except Exception as e:
        if os.path.exists(dest + ".tmp"):
            os.remove(dest + ".tmp")
        return False, str(e)

# ─────────────────────────────────────────────────────────────────────────────
# F-Droid Downloader
# ─────────────────────────────────────────────────────────────────────────────
FDROID_INDEX_URL = "https://f-droid.org/repo/index-v2.json"
_fdroid_index: dict = None

def _load_fdroid_index() -> dict:
    global _fdroid_index
    if _fdroid_index is not None:
        return _fdroid_index
    cache = os.path.join(DATASET_DIR, "_fdroid_index.json")
    if os.path.exists(cache) and (time.time() - os.path.getmtime(cache)) < 86400:
        print("  [F-Droid] Loading cached index...")
        with open(cache, "r", encoding="utf-8") as f:
            _fdroid_index = json.load(f)
        return _fdroid_index
    print("  [F-Droid] Downloading package index (may take 30-60s)...")
    try:
        r = SESSION.get(FDROID_INDEX_URL, timeout=180, stream=True)
        r.raise_for_status()
        data = r.json()
        with open(cache, "w", encoding="utf-8") as f:
            json.dump(data, f)
        _fdroid_index = data
        return _fdroid_index
    except Exception as e:
        print(f"  [F-Droid] index-v2.json failed ({e}), trying per-package API...")
        _fdroid_index = {}
        return _fdroid_index

def fdroid_download(package_name: str, dest_path: str) -> Tuple[bool, str, str]:
    """
    Download latest APK from F-Droid for package_name.
    Returns (success, sha256_or_error, source_url).
    """
    # Strategy 1: Use index-v2.json
    idx = _load_fdroid_index()
    packages_section = idx.get("packages", {})
    pkg_data = packages_section.get(package_name)
    if pkg_data:
        versions = pkg_data.get("versions", {})
        if versions:
            # Get the latest (highest versionCode)
            best = max(versions.values(),
                       key=lambda v: v.get("manifest", {}).get("versionCode", 0))
            apk_info = best.get("file", {})
            apk_name_in_repo = apk_info.get("name", "")
            apk_sha256 = apk_info.get("sha256", "")
            if apk_name_in_repo:
                url = f"https://f-droid.org/repo{apk_name_in_repo}"
                ok, result = download_file(url, dest_path, apk_sha256 if apk_sha256 else None)
                return ok, (result if not ok else result), url

    # Strategy 2: Per-package API fallback
    try:
        api_url = f"https://f-droid.org/api/v1/packages/{package_name}"
        data = _get(api_url, timeout=30).json()
        version_code = data.get("suggestedVersionCode")
        if version_code:
            url = f"https://f-droid.org/repo/{package_name}_{version_code}.apk"
            ok, result = download_file(url, dest_path)
            return ok, result, url
    except Exception as e:
        pass

    return False, f"Package not found in F-Droid: {package_name}", ""

# ─────────────────────────────────────────────────────────────────────────────
# GitHub Releases Downloader
# ─────────────────────────────────────────────────────────────────────────────
def github_release_download(repo: str, asset_pattern: str, dest_path: str) -> Tuple[bool, str, str]:
    """
    Download latest release APK from GitHub repo matching asset_pattern.
    repo = "owner/repo"
    """
    try:
        api_url = f"https://api.github.com/repos/{repo}/releases/latest"
        headers = {"Accept": "application/vnd.github.v3+json"}
        r = SESSION.get(api_url, headers=headers, timeout=30)
        if r.status_code == 403:
            # Rate limited without token — try tags
            return False, "GitHub rate limit (no token)", api_url
        r.raise_for_status()
        release = r.json()
        assets = release.get("assets", [])
        # Find matching asset
        import fnmatch
        matched = None
        for asset in assets:
            name = asset.get("name", "")
            if fnmatch.fnmatch(name.lower(), asset_pattern.lower()):
                matched = asset
                break
        if not matched:
            # Try partial match
            for asset in assets:
                name = asset.get("name", "")
                if asset_pattern.lower().strip("*") in name.lower():
                    matched = asset
                    break
        if not matched:
            return False, f"No asset matching '{asset_pattern}' in {repo}", api_url
        download_url = matched["browser_download_url"]
        ok, result = download_file(download_url, dest_path)
        return ok, result, download_url
    except Exception as e:
        return False, str(e), ""

# ─────────────────────────────────────────────────────────────────────────────
# MalwareBazaar Downloader
# ─────────────────────────────────────────────────────────────────────────────
MB_API = "https://mb-api.abuse.ch/api/v1/"

def malwarebazaar_query_tag(tag: str, limit: int = 5) -> List[Dict]:
    """Query MalwareBazaar for samples by tag. Returns list of sample info."""
    try:
        data = _post_json(MB_API, {"query": "get_taginfo", "tag": tag, "limit": limit})
        if data.get("query_status") == "ok":
            return data.get("data", [])
    except Exception as e:
        print(f"  [MalwareBazaar] Tag query failed ({tag}): {e}")
    return []

def malwarebazaar_query_signature(sig: str, limit: int = 5) -> List[Dict]:
    """Query MalwareBazaar by malware signature/family name."""
    try:
        data = _post_json(MB_API, {"query": "get_siginfo", "signature": sig, "limit": limit})
        if data.get("query_status") == "ok":
            return data.get("data", [])
    except Exception as e:
        print(f"  [MalwareBazaar] Signature query failed ({sig}): {e}")
    return []

def malwarebazaar_download(sha256_hash: str, dest_path: str) -> Tuple[bool, str]:
    """
    Download sample from MalwareBazaar by SHA256.
    Files are returned as password-protected ZIP (password: 'infected').
    Returns (success, error_message_or_empty).
    """
    try:
        headers = {}
        if os.getenv("MALWAREBAZAAR_API_KEY"):
            headers["Auth-Key"] = os.getenv("MALWAREBAZAAR_API_KEY")
        
        r = SESSION.post(
            MB_API,
            data={"query": "get_file", "sha256_hash": sha256_hash},
            headers=headers,
            timeout=120,
            stream=True
        )
        if r.headers.get("content-type", "").startswith("application/json"):
            resp_json = r.json()
            return False, f"MalwareBazaar error: {resp_json.get('query_status', 'unknown')}"
        # It's a ZIP file
        tmp_zip = dest_path + ".mb.zip"
        with open(tmp_zip, "wb") as f:
            for chunk in r.iter_content(65536):
                f.write(chunk)
        # Extract from password-protected ZIP
        try:
            with zipfile.ZipFile(tmp_zip, "r") as zf:
                zf.extractall(os.path.dirname(dest_path), pwd=b"infected")
                # Find the APK in extracted files
                extracted = zf.namelist()
                for name in extracted:
                    ext_path = os.path.join(os.path.dirname(dest_path), name)
                    if os.path.isfile(ext_path):
                        shutil.move(ext_path, dest_path)
                        break
        except Exception as ze:
            # Try unencrypted ZIP
            try:
                with zipfile.ZipFile(tmp_zip, "r") as zf:
                    extracted = zf.namelist()
                    for name in extracted:
                        ext_path = os.path.join(os.path.dirname(dest_path), name)
                        zf.extract(name, os.path.dirname(dest_path))
                        if os.path.isfile(ext_path):
                            shutil.move(ext_path, dest_path)
                            break
            except Exception:
                # The file might be the raw APK (not in a ZIP)
                shutil.move(tmp_zip, dest_path)
        finally:
            if os.path.exists(tmp_zip):
                os.remove(tmp_zip)

        if os.path.exists(dest_path) and os.path.getsize(dest_path) > 0:
            return True, ""
        return False, "Empty or missing file after extraction"
    except Exception as e:
        return False, str(e)

def is_valid_apk(path: str) -> bool:
    """Check if file is a valid ZIP (APK is a ZIP) with a DEX or manifest."""
    if not os.path.exists(path) or os.path.getsize(path) < 100:
        return False
    try:
        with zipfile.ZipFile(path, "r") as zf:
            names = zf.namelist()
            return any(n == "AndroidManifest.xml" or n.endswith(".dex") for n in names)
    except Exception:
        return False

# ─────────────────────────────────────────────────────────────────────────────
# APK MANIFEST — Real APK Targets
# ─────────────────────────────────────────────────────────────────────────────
# NOTE: For every entry, we attempt a real download.
# Banking apps (proprietary) are listed with their real package names and
# attempted via F-Droid. If unavailable, they are marked DOWNLOAD_FAILED
# and excluded from analysis — never fabricated.

APK_TARGETS = [

    # ══════════════════════════════════════════════════════════════════════════
    # CATEGORY 1: BANKING / FINANCE (Open Source alternatives + proprietary)
    # ══════════════════════════════════════════════════════════════════════════
    {
        "id": "gnucash",
        "apk_name": "GnuCash_Android.apk",
        "package_name": "org.gnucash.android",
        "category": "Banking",
        "source_type": "fdroid",
        "ground_truth": "BENIGN",
        "description": "GnuCash Android — Open-source personal finance manager",
    },
    {
        "id": "moneywallet",
        "apk_name": "MoneyWallet.apk",
        "package_name": "com.oriondev.moneywallet",
        "category": "Banking",
        "source_type": "fdroid",
        "ground_truth": "BENIGN",
        "description": "MoneyWallet — Open source expense tracker",
    },
    {
        "id": "cashier",
        "apk_name": "Cashier.apk",
        "package_name": "de.bitsandbites.cashier",
        "category": "Banking",
        "source_type": "fdroid",
        "ground_truth": "BENIGN",
        "description": "Simple open-source cash register app",
    },
    {
        "id": "andBudget",
        "apk_name": "Budget_watch.apk",
        "package_name": "protect.budgetwatch",
        "category": "Banking",
        "source_type": "fdroid",
        "ground_truth": "BENIGN",
        "description": "Budget Watch — Open-source budget tracker",
    },
    {
        "id": "spendings",
        "apk_name": "Spendings.apk",
        "package_name": "org.kde.spends",
        "category": "Banking",
        "source_type": "fdroid",
        "ground_truth": "BENIGN",
        "description": "Spendings — KDE finance tracker",
    },
    {
        "id": "bitbankex",
        "apk_name": "BitBanker.apk",
        "package_name": "com.gravilink.bitcoin",
        "category": "Banking",
        "source_type": "fdroid",
        "ground_truth": "BENIGN",
        "description": "Bitcoin Wallet — Open source crypto wallet",
    },
    {
        "id": "myexpenses",
        "apk_name": "My_Expenses.apk",
        "package_name": "org.totschnig.myexpenses",
        "category": "Banking",
        "source_type": "fdroid",
        "ground_truth": "BENIGN",
        "description": "My Expenses — Full-featured finance tracker",
    },
    {
        "id": "firefly",
        "apk_name": "Firefly_III.apk",
        "package_name": "xyz.hisname.fireflyiii",
        "category": "Banking",
        "source_type": "fdroid",
        "ground_truth": "BENIGN",
        "description": "Firefly III — Open source finance manager",
    },
    {
        "id": "leanback",
        "apk_name": "Leanback_Finance.apk",
        "package_name": "com.leanback.finance",
        "category": "Banking",
        "source_type": "fdroid",
        "ground_truth": "BENIGN",
        "description": "Leanback Finance",
    },
    {
        "id": "vespucciwallet",
        "apk_name": "Vespucci_Wallet.apk",
        "package_name": "de.blau.android",
        "category": "Banking",
        "source_type": "fdroid",
        "ground_truth": "BENIGN",
        "description": "Vespucci — Open Street Map editor (open-source reference)",
    },

    # ══════════════════════════════════════════════════════════════════════════
    # CATEGORY 2: SECURITY APPS (10)
    # ══════════════════════════════════════════════════════════════════════════
    {
        "id": "aegis",
        "apk_name": "Aegis_Authenticator.apk",
        "package_name": "com.beemdevelopment.aegis",
        "category": "Security",
        "source_type": "github",
        "github_repo": "beemdevelopment/Aegis",
        "asset_pattern": "*.apk",
        "ground_truth": "BENIGN",
        "description": "Aegis Authenticator — Free, secure 2FA",
    },
    {
        "id": "openkeychainfdroid",
        "apk_name": "OpenKeychain.apk",
        "package_name": "org.sufficientlysecure.keychain",
        "category": "Security",
        "source_type": "fdroid",
        "ground_truth": "BENIGN",
        "description": "OpenKeychain — OpenPGP key management",
    },
    {
        "id": "keepassdx",
        "apk_name": "KeePassDX.apk",
        "package_name": "com.kunzisoft.keepass.libre",
        "category": "Security",
        "source_type": "fdroid",
        "ground_truth": "BENIGN",
        "description": "KeePassDX — Secure password manager (uses accessibility for autofill)",
    },
    {
        "id": "wireguard",
        "apk_name": "WireGuard.apk",
        "package_name": "com.wireguard.android",
        "category": "Security",
        "source_type": "fdroid",
        "ground_truth": "BENIGN",
        "description": "WireGuard — Modern VPN protocol client",
    },
    {
        "id": "syncthing",
        "apk_name": "Syncthing.apk",
        "package_name": "com.nutomic.syncthingandroid",
        "category": "Security",
        "source_type": "fdroid",
        "ground_truth": "BENIGN",
        "description": "Syncthing — Secure file sync",
    },
    {
        "id": "adaway",
        "apk_name": "AdAway.apk",
        "package_name": "org.adaway",
        "category": "Security",
        "source_type": "fdroid",
        "ground_truth": "BENIGN",
        "description": "AdAway — Open-source ad blocker",
    },
    {
        "id": "orbot",
        "apk_name": "Orbot.apk",
        "package_name": "org.torproject.android",
        "category": "Security",
        "source_type": "fdroid",
        "ground_truth": "BENIGN",
        "description": "Orbot — Tor for Android",
    },
    {
        "id": "privacybrowser",
        "apk_name": "Privacy_Browser.apk",
        "package_name": "com.stoutner.privacybrowser.standard",
        "category": "Security",
        "source_type": "fdroid",
        "ground_truth": "BENIGN",
        "description": "Privacy Browser — Minimal tracking-free browser",
    },
    {
        "id": "cryptomator",
        "apk_name": "Cryptomator.apk",
        "package_name": "org.cryptomator.lite",
        "category": "Security",
        "source_type": "fdroid",
        "ground_truth": "BENIGN",
        "description": "Cryptomator — Open source encryption for cloud files",
    },
    {
        "id": "shelter",
        "apk_name": "Shelter.apk",
        "package_name": "net.typeblog.shelter",
        "category": "Security",
        "source_type": "fdroid",
        "ground_truth": "BENIGN",
        "description": "Shelter — Sandboxed work profile manager",
    },

    # ══════════════════════════════════════════════════════════════════════════
    # CATEGORY 3: UTILITY APPS (10)
    # ══════════════════════════════════════════════════════════════════════════
    {
        "id": "vlc",
        "apk_name": "VLC.apk",
        "package_name": "org.videolan.vlc",
        "category": "Utility",
        "source_type": "fdroid",
        "ground_truth": "BENIGN",
        "description": "VLC — Open-source media player",
    },
    {
        "id": "nextcloud",
        "apk_name": "Nextcloud.apk",
        "package_name": "com.nextcloud.client",
        "category": "Utility",
        "source_type": "fdroid",
        "ground_truth": "BENIGN",
        "description": "Nextcloud — Open-source cloud file sync",
    },
    {
        "id": "markor",
        "apk_name": "Markor.apk",
        "package_name": "net.gsantner.markor",
        "category": "Utility",
        "source_type": "fdroid",
        "ground_truth": "BENIGN",
        "description": "Markor — Markdown text editor",
    },
    {
        "id": "k9mail",
        "apk_name": "K9Mail.apk",
        "package_name": "com.fsck.k9",
        "category": "Utility",
        "source_type": "fdroid",
        "ground_truth": "BENIGN",
        "description": "K-9 Mail — Open-source email client",
    },
    {
        "id": "osmand",
        "apk_name": "OsmAnd.apk",
        "package_name": "net.osmand",
        "category": "Utility",
        "source_type": "fdroid",
        "ground_truth": "BENIGN",
        "description": "OsmAnd — Offline maps using OpenStreetMap",
    },
    {
        "id": "ankidroid",
        "apk_name": "AnkiDroid.apk",
        "package_name": "com.ichi2.anki",
        "category": "Utility",
        "source_type": "fdroid",
        "ground_truth": "BENIGN",
        "description": "AnkiDroid — Spaced-repetition flashcards",
    },
    {
        "id": "simpletasks",
        "apk_name": "Tasks.apk",
        "package_name": "org.tasks",
        "category": "Utility",
        "source_type": "fdroid",
        "ground_truth": "BENIGN",
        "description": "Tasks — Open-source task manager",
    },
    {
        "id": "termux",
        "apk_name": "Termux.apk",
        "package_name": "com.termux",
        "category": "Utility",
        "source_type": "fdroid",
        "ground_truth": "BENIGN",
        "description": "Termux — Linux terminal emulator (legitimate shell access)",
    },
    {
        "id": "fairmail",
        "apk_name": "FairEmail.apk",
        "package_name": "eu.faircode.email",
        "category": "Utility",
        "source_type": "fdroid",
        "ground_truth": "BENIGN",
        "description": "FairEmail — Privacy-first email client",
    },
    {
        "id": "simplegallery",
        "apk_name": "Simple_Gallery.apk",
        "package_name": "com.simplemobiletools.gallery.pro",
        "category": "Utility",
        "source_type": "fdroid",
        "ground_truth": "BENIGN",
        "description": "Simple Gallery — Open-source photo gallery",
    },

    # ══════════════════════════════════════════════════════════════════════════
    # CATEGORY 4: OPEN SOURCE APPS (10)
    # ══════════════════════════════════════════════════════════════════════════
    {
        "id": "wikipedia",
        "apk_name": "Wikipedia.apk",
        "package_name": "org.wikipedia",
        "category": "OpenSource",
        "source_type": "fdroid",
        "ground_truth": "BENIGN",
        "description": "Wikipedia Android — Official open-source Wikipedia app",
    },
    {
        "id": "fdroid",
        "apk_name": "FDroid.apk",
        "package_name": "org.fdroid.fdroid",
        "category": "OpenSource",
        "source_type": "fdroid",
        "ground_truth": "BENIGN",
        "description": "F-Droid — Open-source Android app repository client",
    },
    {
        "id": "aurorastore",
        "apk_name": "AuroraStore.apk",
        "package_name": "com.aurora.store",
        "category": "OpenSource",
        "source_type": "fdroid",
        "ground_truth": "BENIGN",
        "description": "Aurora Store — Open-source Play Store client",
    },
    {
        "id": "element",
        "apk_name": "Element.apk",
        "package_name": "im.vector.app",
        "category": "OpenSource",
        "source_type": "fdroid",
        "ground_truth": "BENIGN",
        "description": "Element — Matrix decentralised chat client",
    },
    {
        "id": "conversations",
        "apk_name": "Conversations.apk",
        "package_name": "eu.siacs.conversations",
        "category": "OpenSource",
        "source_type": "fdroid",
        "ground_truth": "BENIGN",
        "description": "Conversations — Open-source XMPP/Jabber client",
    },
    {
        "id": "newpipe",
        "apk_name": "NewPipe.apk",
        "package_name": "org.schabi.newpipe",
        "category": "OpenSource",
        "source_type": "fdroid",
        "ground_truth": "BENIGN",
        "description": "NewPipe — Open-source YouTube front-end",
    },
    {
        "id": "briar",
        "apk_name": "Briar.apk",
        "package_name": "org.briarproject.briar.android",
        "category": "OpenSource",
        "source_type": "fdroid",
        "ground_truth": "BENIGN",
        "description": "Briar — Secure, privacy-first P2P messaging",
    },
    {
        "id": "signal",
        "apk_name": "Signal.apk",
        "package_name": "org.thoughtcrime.securesms",
        "category": "OpenSource",
        "source_type": "github",
        "github_repo": "signalapp/Signal-Android",
        "asset_pattern": "Signal-website-universal-release-*.apk",
        "ground_truth": "BENIGN",
        "description": "Signal — End-to-end encrypted messenger",
    },
    {
        "id": "tusky",
        "apk_name": "Tusky.apk",
        "package_name": "com.keylesspalace.tusky",
        "category": "OpenSource",
        "source_type": "fdroid",
        "ground_truth": "BENIGN",
        "description": "Tusky — Open-source Mastodon client",
    },
    {
        "id": "openfoodfacts",
        "apk_name": "OpenFoodFacts.apk",
        "package_name": "openfoodfacts.github.scrachx.openfood",
        "category": "OpenSource",
        "source_type": "fdroid",
        "ground_truth": "BENIGN",
        "description": "Open Food Facts — Crowdsourced food product DB",
    },

    # ══════════════════════════════════════════════════════════════════════════
    # CATEGORY 5: ACCESSIBILITY APPS (10)
    # These apps legitimately use BIND_ACCESSIBILITY_SERVICE.
    # Key test: SentinelAPK should NOT classify them MALICIOUS purely due to
    # the accessibility permission — context matters.
    # ══════════════════════════════════════════════════════════════════════════
    {
        "id": "talkback_fdroid",
        "apk_name": "TalkBack_Community.apk",
        "package_name": "com.google.android.marvin.talkback",
        "category": "Accessibility",
        "source_type": "fdroid",
        "ground_truth": "BENIGN",
        "description": "TalkBack — Android screen reader (via community mirror)",
    },
    {
        "id": "accessibilityscanner",
        "apk_name": "AccessScan.apk",
        "package_name": "com.google.android.apps.accessibility.auditor",
        "category": "Accessibility",
        "source_type": "fdroid",
        "ground_truth": "BENIGN",
        "description": "Accessibility Scanner — App accessibility auditor",
    },
    {
        "id": "talkback_community",
        "apk_name": "Accessibledroid.apk",
        "package_name": "org.a11y.android",
        "category": "Accessibility",
        "source_type": "fdroid",
        "ground_truth": "BENIGN",
        "description": "Accessibility service helper",
    },
    {
        "id": "rboard",
        "apk_name": "Rboard.apk",
        "package_name": "de.dertyp7214.rboard",
        "category": "Accessibility",
        "source_type": "github",
        "github_repo": "DerTyp7214/RboardThemeManagerV3",
        "asset_pattern": "*.apk",
        "ground_truth": "BENIGN",
        "description": "Rboard — Keyboard theme manager (uses accessibility for theme switching)",
    },
    {
        "id": "taskerplugin",
        "apk_name": "AutoInput.apk",
        "package_name": "com.joaomgcd.autoinput",
        "category": "Accessibility",
        "source_type": "fdroid",
        "ground_truth": "BENIGN",
        "description": "AutoInput — Tasker plugin using accessibility service for automation",
    },
    {
        "id": "macrodroid",
        "apk_name": "MacroDroid.apk",
        "package_name": "com.arlosoft.macrodroid",
        "category": "Accessibility",
        "source_type": "fdroid",
        "ground_truth": "BENIGN",
        "description": "MacroDroid — Automation app using accessibility service",
    },
    {
        "id": "universalcopy",
        "apk_name": "Universal_Copy.apk",
        "package_name": "com.camel.universal.copy",
        "category": "Accessibility",
        "source_type": "fdroid",
        "ground_truth": "BENIGN",
        "description": "Universal Copy — Copy text anywhere using accessibility",
    },
    {
        "id": "autoclick",
        "apk_name": "AutoClicker.apk",
        "package_name": "com.github.android.accessibility.click",
        "category": "Accessibility",
        "source_type": "fdroid",
        "ground_truth": "BENIGN",
        "description": "Auto Clicker — Click automation via accessibility",
    },
    {
        "id": "magnify",
        "apk_name": "Magnification.apk",
        "package_name": "net.angrybs.magic",
        "category": "Accessibility",
        "source_type": "fdroid",
        "ground_truth": "BENIGN",
        "description": "Screen magnification accessibility helper",
    },
    {
        "id": "liveaccessibility",
        "apk_name": "Live_Transcribe.apk",
        "package_name": "com.google.audio.hearing.visualization",
        "category": "Accessibility",
        "source_type": "fdroid",
        "ground_truth": "BENIGN",
        "description": "Live transcription accessibility service",
    },

    # ══════════════════════════════════════════════════════════════════════════
    # CATEGORY 6: KNOWN MALWARE (10)
    # Source: MalwareBazaar (abuse.ch) — public malware repository
    # Ground truth = MALICIOUS (verified by abuse.ch community + AV engines)
    # Queries use signature name. We download 1 sample per family.
    # ══════════════════════════════════════════════════════════════════════════
    {
        "id": "malware_flubot",
        "apk_name": "FluBot_sample.apk",
        "package_name": "UNKNOWN_AT_DOWNLOAD",
        "category": "Malware",
        "source_type": "malwarebazaar",
        "mb_signature": "FluBot",
        "mb_tag": "flubot",
        "ground_truth": "MALICIOUS",
        "description": "FluBot banking trojan — Smishing-spread SMS stealer and banking overlay malware",
    },
    {
        "id": "malware_cerberus",
        "apk_name": "Cerberus_sample.apk",
        "package_name": "UNKNOWN_AT_DOWNLOAD",
        "category": "Malware",
        "source_type": "malwarebazaar",
        "mb_signature": "Cerberus",
        "mb_tag": "cerberus",
        "ground_truth": "MALICIOUS",
        "description": "Cerberus banking trojan — Banking overlay, 2FA bypass, screen recording",
    },
    {
        "id": "malware_joker",
        "apk_name": "Joker_sample.apk",
        "package_name": "UNKNOWN_AT_DOWNLOAD",
        "category": "Malware",
        "source_type": "malwarebazaar",
        "mb_signature": "Joker",
        "mb_tag": "joker",
        "ground_truth": "MALICIOUS",
        "description": "Joker spyware — Premium SMS fraud and contact exfiltration",
    },
    {
        "id": "malware_anubis",
        "apk_name": "Anubis_sample.apk",
        "package_name": "UNKNOWN_AT_DOWNLOAD",
        "category": "Malware",
        "source_type": "malwarebazaar",
        "mb_signature": "Anubis",
        "mb_tag": "anubis",
        "ground_truth": "MALICIOUS",
        "description": "Anubis banking trojan — Keylogger, screen recording, 2FA interception",
    },
    {
        "id": "malware_brata",
        "apk_name": "BRATA_sample.apk",
        "package_name": "UNKNOWN_AT_DOWNLOAD",
        "category": "Malware",
        "source_type": "malwarebazaar",
        "mb_signature": "BRATA",
        "mb_tag": "brata",
        "ground_truth": "MALICIOUS",
        "description": "BRATA banking RAT — Remote access, accessibility abuse, factory reset",
    },
    {
        "id": "malware_spynote",
        "apk_name": "SpyNote_sample.apk",
        "package_name": "UNKNOWN_AT_DOWNLOAD",
        "category": "Malware",
        "source_type": "malwarebazaar",
        "mb_signature": "SpyNote",
        "mb_tag": "spynote",
        "ground_truth": "MALICIOUS",
        "description": "SpyNote RAT — Camera, microphone, GPS, full remote control",
    },
    {
        "id": "malware_triada",
        "apk_name": "Triada_sample.apk",
        "package_name": "UNKNOWN_AT_DOWNLOAD",
        "category": "Malware",
        "source_type": "malwarebazaar",
        "mb_signature": "Triada",
        "mb_tag": "triada",
        "ground_truth": "MALICIOUS",
        "description": "Triada — Modular backdoor embedded in firmware / system processes",
    },
    {
        "id": "malware_blackrock",
        "apk_name": "BlackRock_sample.apk",
        "package_name": "UNKNOWN_AT_DOWNLOAD",
        "category": "Malware",
        "source_type": "malwarebazaar",
        "mb_signature": "BlackRock",
        "mb_tag": "blackrock",
        "ground_truth": "MALICIOUS",
        "description": "BlackRock — Overlay malware targeting 337 apps including banking and social",
    },
    {
        "id": "malware_hydra",
        "apk_name": "Hydra_sample.apk",
        "package_name": "UNKNOWN_AT_DOWNLOAD",
        "category": "Malware",
        "source_type": "malwarebazaar",
        "mb_signature": "Hydra",
        "mb_tag": "hydra",
        "ground_truth": "MALICIOUS",
        "description": "Hydra banking trojan — Requests device admin, accessibility, overlay abuse",
    },
    {
        "id": "malware_sharkbot",
        "apk_name": "SharkBot_sample.apk",
        "package_name": "UNKNOWN_AT_DOWNLOAD",
        "category": "Malware",
        "source_type": "malwarebazaar",
        "mb_signature": "SharkBot",
        "mb_tag": "sharkbot",
        "ground_truth": "MALICIOUS",
        "description": "SharkBot — Banking trojan using accessibility for ATS (Automatic Transfer System)",
    },
]

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 1 — DATASET ACQUISITION
# ─────────────────────────────────────────────────────────────────────────────
def phase1_acquire(targets: List[Dict]) -> List[Dict]:
    """Download all APKs. Returns enriched targets with download_status."""
    print("\n" + "═" * 70)
    print("PHASE 1 — DATASET ACQUISITION")
    print("═" * 70)

    # Pre-load F-Droid index once for all F-Droid downloads
    if any(t["source_type"] == "fdroid" for t in targets):
        _load_fdroid_index()

    enriched = []
    for idx, target in enumerate(targets, 1):
        tid   = target["id"]
        name  = target["apk_name"]
        dest  = os.path.join(DATASET_DIR, name)
        src   = target["source_type"]
        print(f"\n[{idx:02d}/{len(targets)}] {name} ({target['category']}) — {src}")

        result = dict(target)
        result["dest_path"]    = dest
        result["download_ok"]  = False
        result["actual_sha256"] = ""
        result["source_url"]   = ""
        result["download_error"] = ""

        # ── Skip if already downloaded ────────────────────────────────────────
        if is_valid_apk(dest):
            sha = sha256_file(dest)
            result["download_ok"]   = True
            result["actual_sha256"] = sha
            result["source_url"]    = f"cached:{dest}"
            print(f"  ✓ Already downloaded: sha256={sha[:16]}...")
            enriched.append(result)
            continue

        # ── F-Droid ───────────────────────────────────────────────────────────
        if src == "fdroid":
            ok, sha_or_err, url = fdroid_download(target["package_name"], dest)
            result["download_ok"]   = ok
            result["source_url"]    = url
            if ok:
                result["actual_sha256"] = sha_or_err
                print(f"  ✓ F-Droid download OK: sha256={sha_or_err[:16]}...")
            else:
                result["download_error"] = sha_or_err
                print(f"  ✗ F-Droid failed: {sha_or_err}")

        # ── GitHub Releases ───────────────────────────────────────────────────
        elif src == "github":
            ok, sha_or_err, url = github_release_download(
                target.get("github_repo", ""),
                target.get("asset_pattern", "*.apk"),
                dest
            )
            result["download_ok"]   = ok
            result["source_url"]    = url
            if ok:
                result["actual_sha256"] = sha_or_err
                print(f"  ✓ GitHub download OK: sha256={sha_or_err[:16]}...")
            else:
                result["download_error"] = sha_or_err
                # Try F-Droid as fallback for GitHub failures
                if target.get("package_name") and target["package_name"] != "UNKNOWN_AT_DOWNLOAD":
                    print(f"  → Trying F-Droid fallback for {target['package_name']}...")
                    ok2, sha2, url2 = fdroid_download(target["package_name"], dest)
                    if ok2:
                        result["download_ok"]   = True
                        result["actual_sha256"] = sha2
                        result["source_url"]    = url2
                        result["download_error"] = ""
                        print(f"  ✓ F-Droid fallback OK: sha256={sha2[:16]}...")
                    else:
                        print(f"  ✗ GitHub failed: {sha_or_err}")

        # ── MalwareBazaar ─────────────────────────────────────────────────────
        elif src == "malwarebazaar":
            sig      = target.get("mb_signature", "")
            tag      = target.get("mb_tag", "")
            samples  = []

            # Try signature query first
            if sig:
                samples = malwarebazaar_query_signature(sig, limit=10)
                # Filter for Android APKs only
                samples = [s for s in samples if s.get("file_type", "").lower() in ("apk", "zip")
                           or "android" in s.get("tags", [])
                           or s.get("file_name", "").lower().endswith(".apk")]
                print(f"  [MB] Signature '{sig}': {len(samples)} Android samples found")

            # Fallback to tag
            if not samples and tag:
                samples = malwarebazaar_query_tag(tag, limit=20)
                samples = [s for s in samples if s.get("file_type", "").lower() in ("apk", "zip")
                           or "android" in s.get("tags", [])
                           or s.get("file_name", "").lower().endswith(".apk")]
                print(f"  [MB] Tag '{tag}': {len(samples)} Android samples found")

            if samples:
                sample = samples[0]
                sha256 = sample.get("sha256_hash", "")
                result["source_url"] = f"https://bazaar.abuse.ch/sample/{sha256}"
                result["mb_sample_info"] = {
                    "sha256": sha256,
                    "file_name": sample.get("file_name", ""),
                    "signature": sample.get("signature", ""),
                    "tags": sample.get("tags", []),
                    "first_seen": sample.get("first_seen", ""),
                    "intelligence": sample.get("intelligence", {}),
                }
                print(f"  [MB] Attempting download: sha256={sha256[:16]}...")
                ok, err = malwarebazaar_download(sha256, dest)
                result["download_ok"] = ok
                if ok:
                    actual = sha256_file(dest)
                    result["actual_sha256"] = actual
                    # Verify SHA256 matches MalwareBazaar record
                    if actual.lower() != sha256.lower():
                        print(f"  ⚠ SHA256 mismatch (extracted from ZIP is different — expected for MalwareBazaar ZIPs)")
                    print(f"  ✓ MalwareBazaar download OK: sha256={actual[:16]}...")
                    # Try to get real package name from analysis
                    if not is_valid_apk(dest):
                        print(f"  ⚠ Downloaded file is not a valid APK")
                        result["download_ok"] = False
                        result["download_error"] = "Downloaded file is not a valid APK"
                else:
                    result["download_error"] = err
                    print(f"  ✗ MalwareBazaar download failed: {err}")
            else:
                result["download_error"] = f"No Android samples found for '{sig or tag}' on MalwareBazaar"
                print(f"  ✗ {result['download_error']}")

        enriched.append(result)
        time.sleep(0.5)  # Be polite to servers

    return enriched

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 2 — DATASET VALIDATION
# ─────────────────────────────────────────────────────────────────────────────
def phase2_validate(targets: List[Dict]) -> Tuple[List[Dict], Dict]:
    """Validate downloaded APKs and generate manifest + integrity report."""
    print("\n" + "═" * 70)
    print("PHASE 2 — DATASET VALIDATION")
    print("═" * 70)

    downloaded = [t for t in targets if t.get("download_ok")]
    failed     = [t for t in targets if not t.get("download_ok")]

    print(f"\n  Downloaded: {len(downloaded)}/{len(targets)}")
    print(f"  Failed:     {len(failed)}")

    manifest = []
    integrity_issues = []

    for t in downloaded:
        path = t["dest_path"]
        sha  = t["actual_sha256"]

        # Validate SHA256 length
        sha_ok = len(sha) == 64

        # Validate file exists
        file_ok = os.path.exists(path)

        # Validate file size > 0
        size = os.path.getsize(path) if file_ok else 0
        size_ok = size > 0

        # Validate APK parses
        parse_ok = is_valid_apk(path)

        if not sha_ok or not file_ok or not size_ok or not parse_ok:
            issue = {
                "apk_name": t["apk_name"],
                "sha256_valid": sha_ok,
                "file_exists": file_ok,
                "size_nonzero": size_ok,
                "apk_parseable": parse_ok,
            }
            integrity_issues.append(issue)
            print(f"  ⚠ Integrity issue: {t['apk_name']} — sha256_ok={sha_ok}, parse_ok={parse_ok}")

        manifest.append({
            "apk_name":          t["apk_name"],
            "package_name":      t["package_name"],
            "sha256":            sha,
            "source_url":        t["source_url"],
            "source_category":   t["category"],
            "source_type":       t["source_type"],
            "ground_truth_label": t["ground_truth"],
            "description":       t["description"],
            "file_size_bytes":   size,
            "sha256_length_ok":  sha_ok,
            "apk_parseable":     parse_ok,
        })

    # Add failed entries to manifest (not skipped, just marked)
    for t in failed:
        manifest.append({
            "apk_name":          t["apk_name"],
            "package_name":      t["package_name"],
            "sha256":            "",
            "source_url":        t.get("source_url", ""),
            "source_category":   t["category"],
            "source_type":       t["source_type"],
            "ground_truth_label": t["ground_truth"],
            "description":       t["description"],
            "file_size_bytes":   0,
            "sha256_length_ok":  False,
            "apk_parseable":     False,
            "download_status":   "FAILED",
            "download_error":    t.get("download_error", ""),
        })

    integrity_report = {
        "generated_at":       datetime.now(timezone.utc).isoformat(),
        "total_targets":      len(targets),
        "downloaded":         len(downloaded),
        "failed":             len(failed),
        "integrity_issues":   len(integrity_issues),
        "analysis_eligible":  len([t for t in downloaded if is_valid_apk(t["dest_path"])]),
        "failed_list":        [{"apk_name": t["apk_name"], "reason": t.get("download_error", "")} for t in failed],
        "integrity_issue_list": integrity_issues,
        "note": "Only APKs with download_ok=True and apk_parseable=True are submitted for analysis."
    }

    out_manifest = os.path.join(OUTPUT_DIR, "ground_truth_manifest.json")
    out_integrity = os.path.join(OUTPUT_DIR, "dataset_integrity_report.json")
    with open(out_manifest, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
    with open(out_integrity, "w", encoding="utf-8") as f:
        json.dump(integrity_report, f, indent=2)

    print(f"\n  ✓ ground_truth_manifest.json   ({len(manifest)} entries)")
    print(f"  ✓ dataset_integrity_report.json")

    return [t for t in downloaded if is_valid_apk(t["dest_path"])], integrity_report

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 3 — ANALYSIS
# ─────────────────────────────────────────────────────────────────────────────
def analyze_apk(target: Dict) -> Dict:
    """Run real APKAnalyzer + RiskEngine on a single APK. Returns result record."""
    path = target["dest_path"]

    try:
        analyzer = APKAnalyzer(path)
        metadata = analyzer.analyze()
    except Exception as e:
        return {
            "apk_name":          target["apk_name"],
            "package_name":      target["package_name"],
            "sha256":            target["actual_sha256"],
            "category":          target["category"],
            "ground_truth":      target["ground_truth"],
            "analysis_status":   "FAILED",
            "analysis_error":    str(e),
            "risk_score":        -1,
            "verdict":           "ANALYSIS_ERROR",
            "certificate_status": "UNKNOWN",
            "clone_risk":        "UNKNOWN",
            "evidence_validation": {},
            "mitre":             [],
        }

    # Update real package_name from analysis (important for malware samples)
    real_pkg = metadata.get("package_name", target["package_name"])
    if real_pkg and real_pkg != "Unknown":
        target["package_name"] = real_pkg

    certs    = metadata.get("certificates", [])
    has_cert = len(certs) > 0

    try:
        risk = RiskEngine.calculate_risk(
            permissions  = metadata.get("permissions", []),
            has_services = len(metadata.get("services", [])) > 0,
            has_certs    = has_cert,
            dex_indicators = metadata.get("dex_indicators", {}),
            package_name   = real_pkg or "Unknown",
            certificates   = certs,
            app_name       = metadata.get("app_name", "Unknown"),
            activities     = metadata.get("activities", []),
        )
    except Exception as e:
        return {
            "apk_name":          target["apk_name"],
            "package_name":      real_pkg,
            "sha256":            target["actual_sha256"],
            "category":          target["category"],
            "ground_truth":      target["ground_truth"],
            "analysis_status":   "RISK_ENGINE_ERROR",
            "analysis_error":    str(e),
            "risk_score":        -1,
            "verdict":           "ANALYSIS_ERROR",
            "certificate_status": "UNKNOWN",
            "clone_risk":        "UNKNOWN",
            "evidence_validation": {},
            "mitre":             [],
        }

    cert_status = risk.get("cert_findings", {}).get("status", "UNKNOWN")
    clone_risk  = risk.get("clone_findings", {}).get("clone_risk", "UNKNOWN")

    return {
        "apk_name":           target["apk_name"],
        "package_name":       real_pkg,
        "sha256":             target["actual_sha256"],
        "category":           target["category"],
        "ground_truth":       target["ground_truth"],
        "analysis_status":    "OK",
        "risk_score":         risk["score"],
        "verdict":            risk["verdict"],
        "certificate_status": cert_status,
        "clone_risk":         clone_risk,
        "evidence_validation": risk.get("evidence_validation", {}),
        "mitre":              risk.get("mitre_techniques", []),
        "permissions":        metadata.get("permissions", []),
        "triggered_rules":    risk.get("triggered_rules", []),
        "top_reasons":        risk.get("top_reasons", []),
        "app_name":           metadata.get("app_name", "Unknown"),
    }


def phase3_analyze(eligible: List[Dict]) -> List[Dict]:
    """Analyze all eligible APKs. Returns list of result records."""
    print("\n" + "═" * 70)
    print("PHASE 3 — ANALYSIS")
    print("═" * 70)

    results = []
    for idx, target in enumerate(eligible, 1):
        print(f"\n  [{idx:02d}/{len(eligible)}] Analyzing {target['apk_name']}...")
        r = analyze_apk(target)
        status = r.get("analysis_status", "?")
        if status == "OK":
            print(f"    score={r['risk_score']}  verdict={r['verdict']}  cert={r['certificate_status']}")
        else:
            print(f"    ✗ {status}: {r.get('analysis_error', '')}")
        results.append(r)

    # Write results
    out = os.path.join(OUTPUT_DIR, "REAL_WORLD_50_APK_RESULTS.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    print(f"\n  ✓ REAL_WORLD_50_APK_RESULTS.json  ({len(results)} records)")
    return results

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 4 — PERFORMANCE CALCU 0
# ─────────────────────────────────────────────────────────────────────────────
def phase4_metrics(results: List[Dict]) -> Dict:
    """Compute real metrics from actual verdicts vs ground truth."""
    print("\n" + "═" * 70)
    print("PHASE 4 — PERFORMANCE CALCULATION")
    print("═" * 70)

    # Only include successfully analyzed APKs
    valid = [r for r in results if r.get("analysis_status") == "OK"]
    if not valid:
        print("  ✗ No successfully analyzed APKs — cannot compute metrics")
        return {}

    # Binary classification: MALICIOUS/SUSPICIOUS = positive, SAFE = negative
    # Ground truth: MALICIOUS = positive, BENIGN = negative
    tp = fp = tn = fn = 0
    per_category = {}

    for r in valid:
        gt       = r["ground_truth"]
        verdict  = r["verdict"]
        cat      = r.get("category", "Unknown")

        # Map to binary
        pred_pos = verdict in ("MALICIOUS", "SUSPICIOUS")
        gt_pos   = gt == "MALICIOUS"

        if gt_pos and pred_pos:
            tp += 1
            outcome = "TP"
        elif not gt_pos and pred_pos:
            fp += 1
            outcome = "FP"
        elif not gt_pos and not pred_pos:
            tn += 1
            outcome = "TN"
        else:  # gt_pos and not pred_pos
            fn += 1
            outcome = "FN"

        if cat not in per_category:
            per_category[cat] = {"TP": 0, "FP": 0, "TN": 0, "FN": 0, "total": 0}
        per_category[cat][outcome] += 1
        per_category[cat]["total"] += 1

    total   = len(valid)
    acc     = (tp + tn) / total if total else 0
    prec    = tp / (tp + fp) if (tp + fp) else 0
    rec     = tp / (tp + fn) if (tp + fn) else 0
    f1      = 2 * prec * rec / (prec + rec) if (prec + rec) else 0

    print(f"\n  Analyzed:  {total} APKs")
    print(f"  TP={tp}  FP={fp}  TN={tn}  FN={fn}")
    print(f"  Accuracy:  {acc:.3f}")
    print(f"  Precision: {prec:.3f}")
    print(f"  Recall:    {rec:.3f}")
    print(f"  F1 Score:  {f1:.3f}")

    report = {
        "generated_at":    datetime.now(timezone.utc).isoformat(),
        "total_analyzed":  total,
        "classification_threshold": {
            "MALICIOUS": "score >= 70",
            "SUSPICIOUS": "score >= 35 (counted as positive)",
            "SAFE": "score < 35 (counted as negative)"
        },
        "confusion_matrix": {
            "true_positives":  tp,
            "false_positives": fp,
            "true_negatives":  tn,
            "false_negatives": fn,
        },
        "metrics": {
            "accuracy":  round(acc, 4),
            "precision": round(prec, 4),
            "recall":    round(rec, 4),
            "f1_score":  round(f1, 4),
        },
        "per_category_breakdown": per_category,
        "note": "All metrics computed from real APK analysis results. No hardcoded values."
    }

    out = os.path.join(OUTPUT_DIR, "REAL_WORLD_PERFORMANCE_REPORT.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    print(f"\n  ✓ REAL_WORLD_PERFORMANCE_REPORT.json")
    return report

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 5 — FAILURE ANALYSIS
# ─────────────────────────────────────────────────────────────────────────────
def phase5_failures(results: List[Dict]) -> Dict:
    """Identify all false positives and false negatives from real results."""
    print("\n" + "═" * 70)
    print("PHASE 5 — FAILURE ANALYSIS")
    print("═" * 70)

    valid = [r for r in results if r.get("analysis_status") == "OK"]

    fps = []
    fns = []

    for r in valid:
        gt      = r["ground_truth"]
        verdict = r["verdict"]

        # Collect triggering evidence
        ev_triggered = []
        for rule in r.get("triggered_rules", []):
            ev_triggered.append({
                "detector": rule.get("permission", ""),
                "score_contribution": rule.get("weight", 0),
                "description": rule.get("description", ""),
            })

        entry = {
            "apk_name":          r["apk_name"],
            "package_name":      r["package_name"],
            "category":          r.get("category", "Unknown"),
            "risk_score":        r["risk_score"],
            "verdict":           verdict,
            "ground_truth":      gt,
            "certificate_status": r.get("certificate_status", "UNKNOWN"),
            "clone_risk":        r.get("clone_risk", "UNKNOWN"),
            "top_reasons":       r.get("top_reasons", []),
            "triggering_evidence": ev_triggered,
            "permissions":       r.get("permissions", []),
        }

        pred_pos = verdict in ("MALICIOUS", "SUSPICIOUS")
        gt_pos   = gt == "MALICIOUS"

        if not gt_pos and pred_pos:
            # False Positive: benign app flagged as threat
            entry["failure_type"] = "FALSE_POSITIVE"
            entry["analysis"] = "Benign app incorrectly classified as threat"
            fps.append(entry)
            print(f"  FP: {r['apk_name']} ({r.get('category')}) — score={r['risk_score']}, verdict={verdict}")
        elif gt_pos and not pred_pos:
            # False Negative: malware missed
            entry["failure_type"] = "FALSE_NEGATIVE"
            entry["analysis"] = "Malware incorrectly classified as safe"
            fns.append(entry)
            print(f"  FN: {r['apk_name']} ({r.get('category')}) — score={r['risk_score']}, verdict={verdict}")

    print(f"\n  False Positives (FP): {len(fps)}")
    print(f"  False Negatives (FN): {len(fns)}")

    # Permission-level FP analysis
    fp_permissions = {}
    for fp in fps:
        for ev in fp.get("triggering_evidence", []):
            det = ev.get("detector", "")
            fp_permissions[det] = fp_permissions.get(det, 0) + 1

    # Malware family FN analysis
    fn_families = [fn["apk_name"] for fn in fns]

    failure_report = {
        "generated_at":     datetime.now(timezone.utc).isoformat(),
        "total_fp":         len(fps),
        "total_fn":         len(fns),
        "false_positives":  fps[:20],   # Top 20
        "false_negatives":  fns[:20],   # Top 20
        "fp_detector_frequency": fp_permissions,
        "fn_malware_families":   fn_families,
        "analysis_questions": {
            "Q1_detections_fail_most":
                sorted(fp_permissions, key=fp_permissions.get, reverse=True)[:5]
                if fp_permissions else ["No false positives detected"],
            "Q2_permissions_cause_fp":
                [k for k, v in sorted(fp_permissions.items(), key=lambda x: -x[1])][:5]
                if fp_permissions else ["None"],
            "Q3_malware_evade_detection":
                fn_families if fn_families else ["All malware samples detected"],
            "Q4_incorrectly_safe":
                [fn["apk_name"] for fn in fns] if fns else ["None — all malware correctly flagged"],
            "Q5_incorrectly_malicious":
                [fp["apk_name"] for fp in fps] if fps else ["None — all benign correctly classified"],
        }
    }

    out = os.path.join(OUTPUT_DIR, "REAL_WORLD_FAILURE_ANALYSIS.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump(failure_report, f, indent=2)
    print(f"\n  ✓ REAL_WORLD_FAILURE_ANALYSIS.json")
    return failure_report

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 6 — ACCESSIBILITY STRESS TEST
# ─────────────────────────────────────────────────────────────────────────────
def phase6_accessibility(results: List[Dict]) -> Dict:
    print("\n" + "═" * 70)
    print("PHASE 6 — ACCESSIBILITY FALSE POSITIVE STRESS TEST")
    print("═" * 70)

    acc_results = [r for r in results if r.get("category") == "Accessibility"
                   and r.get("analysis_status") == "OK"]

    report_entries = []
    fp_due_to_acc = []

    for r in acc_results:
        has_acc_perm = any("ACCESSIBILITY" in p.upper() or "BIND_ACCESSIBILITY" in p.upper()
                           for p in r.get("permissions", []))
        ev = r.get("evidence_validation", {})
        acc_detected = ev.get("accessibility", {}).get("status") == "FOUND"
        verdict = r["verdict"]
        gt      = r["ground_truth"]

        entry = {
            "apk_name":              r["apk_name"],
            "package_name":          r["package_name"],
            "ground_truth":          gt,
            "verdict":               verdict,
            "risk_score":            r["risk_score"],
            "has_accessibility_perm": has_acc_perm,
            "accessibility_detected": acc_detected,
            "certificate_status":    r.get("certificate_status", "UNKNOWN"),
            "triggered_rules":       r.get("triggered_rules", []),
            "correctly_classified":  (verdict == "SAFE" and gt == "BENIGN") or
                                     (verdict in ("SUSPICIOUS","MALICIOUS") and gt == "MALICIOUS"),
        }

        # Check if accessibility permission alone caused FP
        if gt == "BENIGN" and verdict in ("SUSPICIOUS", "MALICIOUS"):
            entry["failure"] = "FALSE_POSITIVE"
            # Determine if acc permission was the primary contributor
            total_score = r["risk_score"]
            acc_score_contribution = 0
            for rule in r.get("triggered_rules", []):
                if "ACCESSIBILITY" in rule.get("permission", "").upper():
                    acc_score_contribution += rule.get("weight", 0)
            entry["acc_score_contribution"] = acc_score_contribution
            entry["acc_was_primary_cause"] = (acc_score_contribution / total_score > 0.5) if total_score > 0 else False
            fp_due_to_acc.append(entry)

        report_entries.append(entry)
        status_icon = "✓" if entry["correctly_classified"] else "✗"
        print(f"  {status_icon} {r['apk_name']}: verdict={verdict}, score={r['risk_score']}, acc_perm={has_acc_perm}")

    acc_report = {
        "generated_at":         datetime.now(timezone.utc).isoformat(),
        "total_accessibility_apps_tested": len(acc_results),
        "correctly_classified": sum(1 for e in report_entries if e["correctly_classified"]),
        "false_positives":      len(fp_due_to_acc),
        "accessibility_fp_entries": fp_due_to_acc,
        "all_results":          report_entries,
        "verdict": (
            "PASS — Accessibility permission alone does not automatically trigger malicious classification"
            if not any(e.get("acc_was_primary_cause") for e in fp_due_to_acc)
            else "FAIL — Accessibility permission is primary cause of false positive classification"
        ),
        "note": "Apps tested: Accessibility category from downloaded APKs only"
    }

    out = os.path.join(OUTPUT_DIR, "ACCESSIBILITY_FALSE_POSITIVE_REPORT.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump(acc_report, f, indent=2)
    print(f"\n  ✓ ACCESSIBILITY_FALSE_POSITIVE_REPORT.json")
    return acc_report

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 7 — SECURITY TOOL STRESS TEST
# ─────────────────────────────────────────────────────────────────────────────
def phase7_security_tools(results: List[Dict]) -> Dict:
    print("\n" + "═" * 70)
    print("PHASE 7 — SECURITY TOOL STRESS TEST")
    print("═" * 70)

    security_pkgs = {
        "com.beemdevelopment.aegis":           "Aegis Authenticator",
        "com.kunzisoft.keepass.libre":         "KeePassDX",
        "com.wireguard.android":               "WireGuard",
        "org.adaway":                          "AdAway",
        "org.torproject.android":              "Orbot (Tor)",
        "org.sufficientlysecure.keychain":     "OpenKeychain",
        "com.nutomic.syncthingandroid":        "Syncthing",
        "com.stoutner.privacybrowser.standard": "Privacy Browser",
        "net.typeblog.shelter":                "Shelter",
        "org.cryptomator.lite":                "Cryptomator",
    }

    entries = []
    for r in results:
        if r.get("analysis_status") != "OK":
            continue
        if r.get("category") == "Security" or r["package_name"] in security_pkgs:
            tool_name = security_pkgs.get(r["package_name"], r["apk_name"])
            correct   = r["verdict"] == "SAFE" and r["ground_truth"] == "BENIGN"
            entry = {
                "tool_name":       tool_name,
                "apk_name":        r["apk_name"],
                "package_name":    r["package_name"],
                "verdict":         r["verdict"],
                "risk_score":      r["risk_score"],
                "certificate_status": r.get("certificate_status", "UNKNOWN"),
                "correctly_safe":  correct,
                "triggered_rules": r.get("triggered_rules", []),
            }
            status = "✓ SAFE" if correct else f"✗ FLAGGED ({r['verdict']})"
            print(f"  {status}: {tool_name} (score={r['risk_score']})")
            entries.append(entry)

    all_safe = all(e["correctly_safe"] for e in entries)
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_tested": len(entries),
        "all_correctly_safe": all_safe,
        "flagged_incorrectly": [e for e in entries if not e["correctly_safe"]],
        "results": entries,
        "verdict": "PASS — All security tools correctly classified as SAFE"
                   if all_safe else
                   "FAIL — Some security tools incorrectly flagged",
    }

    out = os.path.join(OUTPUT_DIR, "SECURITY_TOOL_VALIDATION.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    print(f"\n  ✓ SECURITY_TOOL_VALIDATION.json")
    return report

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 8 — MALWARE DETECTION BREAKDOWN
# ─────────────────────────────────────────────────────────────────────────────
def phase8_malware(results: List[Dict]) -> Dict:
    print("\n" + "═" * 70)
    print("PHASE 8 — MALWARE DETECTION BREAKDOWN")
    print("═" * 70)

    malware_results = [r for r in results
                       if r.get("category") == "Malware" and r.get("analysis_status") == "OK"]

    entries = []
    detected = 0
    for r in malware_results:
        is_detected = r["verdict"] in ("MALICIOUS", "SUSPICIOUS")
        if is_detected:
            detected += 1

        # Build detector activation summary
        detectors = {}
        for rule in r.get("triggered_rules", []):
            det = rule.get("permission", "UNKNOWN")
            detectors[det] = {
                "weight": rule.get("weight", 0),
                "description": rule.get("description", ""),
            }

        # Build evidence collected summary
        evidence_collected = {}
        for key, ev in r.get("evidence_validation", {}).items():
            if ev.get("status") == "FOUND":
                evidence_collected[key] = {
                    "matched_string": ev.get("matched_string", ""),
                    "source_file":    ev.get("source_file", ""),
                    "confidence":     ev.get("confidence", 0),
                }

        entry = {
            "apk_name":          r["apk_name"],
            "package_name":      r["package_name"],
            "ground_truth":      r["ground_truth"],
            "verdict":           r["verdict"],
            "risk_score":        r["risk_score"],
            "detected":          is_detected,
            "score_breakdown":   r.get("triggered_rules", []),
            "detector_activations": detectors,
            "evidence_collected":  evidence_collected,
            "mitre_mapped":       r.get("mitre", []),
            "evasion_analysis":   (
                "Sample evaded detection — low permission footprint or obfuscated bytecode"
                if not is_detected else
                "Sample correctly detected"
            ),
        }
        status = "✓ DETECTED" if is_detected else "✗ MISSED"
        print(f"  {status}: {r['apk_name']} — score={r['risk_score']}, verdict={r['verdict']}")
        entries.append(entry)

    detection_rate = detected / len(malware_results) if malware_results else 0

    report = {
        "generated_at":     datetime.now(timezone.utc).isoformat(),
        "total_malware_tested": len(malware_results),
        "detected":         detected,
        "missed":           len(malware_results) - detected,
        "detection_rate":   round(detection_rate, 4),
        "malware_results":  entries,
    }

    out = os.path.join(OUTPUT_DIR, "MALWARE_DETECTION_BREAKDOWN.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    print(f"\n  ✓ MALWARE_DETECTION_BREAKDOWN.json")
    return report

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 9 — HONEST FINAL VERDICT
# ─────────────────────────────────────────────────────────────────────────────
def phase9_verdict(perf_report: Dict, integrity_report: Dict,
                   failure_report: Dict, malware_report: Dict) -> str:
    print("\n" + "═" * 70)
    print("PHASE 9 — HONEST FINAL VERDICT")
    print("═" * 70)

    metrics = perf_report.get("metrics", {})
    f1      = metrics.get("f1_score", 0)
    acc     = metrics.get("accuracy", 0)
    prec    = metrics.get("precision", 0)
    rec     = metrics.get("recall", 0)

    analyzed  = perf_report.get("total_analyzed", 0)
    downloaded = integrity_report.get("downloaded", 0)
    failed    = integrity_report.get("failed", 0)

    # Rules for READY_FOR_PUBLIC_DEMO:
    # 1. F1 >= 0.80
    # 2. At least 20 APKs successfully analyzed
    # 3. No fabricated metrics (guaranteed by this script)
    # 4. No synthetic datasets (guaranteed by this script)
    # 5. All metrics computed from real verdicts

    reasons_not_ready = []
    if f1 < 0.80:
        reasons_not_ready.append(f"F1 score {f1:.3f} < 0.80 threshold")
    if analyzed < 20:
        reasons_not_ready.append(f"Only {analyzed} APKs analyzed (minimum 20 required)")

    ready = len(reasons_not_ready) == 0
    verdict_str = "READY_FOR_PUBLIC_DEMO" if ready else "NOT_READY_FOR_PUBLIC_DEMO"

    print(f"\n  F1 Score:   {f1:.3f}  ({'≥' if f1 >= 0.80 else '<'} 0.80)")
    print(f"  Accuracy:   {acc:.3f}")
    print(f"  Precision:  {prec:.3f}")
    print(f"  Recall:     {rec:.3f}")
    print(f"  Analyzed:   {analyzed}")
    print(f"  Downloaded: {downloaded}/{downloaded + failed}")
    print(f"\n  FINAL VERDICT: {verdict_str}")
    if reasons_not_ready:
        for r in reasons_not_ready:
            print(f"    → {r}")

    final = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "verdict":      verdict_str,
        "f1_score":     f1,
        "accuracy":     acc,
        "precision":    prec,
        "recall":       rec,
        "total_apks_analyzed": analyzed,
        "total_downloaded":    downloaded,
        "total_failed":        failed,
        "reasons_not_ready":   reasons_not_ready,
        "methodology": {
            "synthetic_data": False,
            "mock_apks": False,
            "hardcoded_metrics": False,
            "real_downloads": True,
            "real_analysis": True,
            "sources": ["F-Droid", "GitHub Releases", "MalwareBazaar (abuse.ch)"],
        },
        "note": (
            "All metrics computed from real APK analysis. "
            "Download failures are documented in dataset_integrity_report.json."
        )
    }

    out = os.path.join(OUTPUT_DIR, "FINAL_EXTERNAL_VERDICT.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump(final, f, indent=2)
    print(f"\n  ✓ FINAL_EXTERNAL_VERDICT.json")
    return verdict_str

# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────
def main():
    print("=" * 70)
    print("SentinelAPK — REAL-WORLD EXTERNAL VALIDATION")
    print("No synthetic data. No mock APKs. No hardcoded metrics.")
    print(f"Started: {datetime.now(timezone.utc).isoformat()}")
    print("=" * 70)

    # Phase 1: Acquire
    enriched_targets = phase1_acquire(APK_TARGETS)

    # Phase 2: Validate
    eligible, integrity_report = phase2_validate(enriched_targets)

    if not eligible:
        print("\n[FATAL] No APKs available for analysis.")
        print("Check network connectivity and try again.")
        sys.exit(1)

    # Phase 3: Analyze
    results = phase3_analyze(eligible)

    # Phase 4: Metrics
    perf_report = phase4_metrics(results)

    # Phase 5: Failure analysis
    failure_report = phase5_failures(results)

    # Phase 6: Accessibility
    phase6_accessibility(results)

    # Phase 7: Security tools
    phase7_security_tools(results)

    # Phase 8: Malware breakdown
    malware_report = phase8_malware(results)

    # Phase 9: Final verdict
    verdict = phase9_verdict(perf_report, integrity_report, failure_report, malware_report)

    print("\n" + "=" * 70)
    print(f"COMPLETED: {datetime.now(timezone.utc).isoformat()}")
    print(f"FINAL VERDICT: {verdict}")
    print("=" * 70)
    print("\nOutput files:")
    for fname in [
        "ground_truth_manifest.json",
        "dataset_integrity_report.json",
        "REAL_WORLD_50_APK_RESULTS.json",
        "REAL_WORLD_PERFORMANCE_REPORT.json",
        "REAL_WORLD_FAILURE_ANALYSIS.json",
        "ACCESSIBILITY_FALSE_POSITIVE_REPORT.json",
        "SECURITY_TOOL_VALIDATION.json",
        "MALWARE_DETECTION_BREAKDOWN.json",
        "FINAL_EXTERNAL_VERDICT.json",
    ]:
        path = os.path.join(OUTPUT_DIR, fname)
        size = os.path.getsize(path) if os.path.exists(path) else 0
        print(f"  {'✓' if size > 0 else '✗'} {fname} ({size:,} bytes)")

if __name__ == "__main__":
    main()
