import os
import json
import zipfile
import hashlib

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATASET_DIR = os.path.join(BASE_DIR, "dataset")

# 10 Benign APKs
benign_samples = [
    # Train (5)
    {"name": "sbi_yono_official.apk", "split": "train", "label": "SBI Yono Official", "package": "com.sbi.yono", "permissions": ["android.permission.INTERNET"], "code": b"initSecureSession", "source": "analyst_review", "reviewed_by": "SecOps Lead"},
    {"name": "hdfc_bank_official.apk", "split": "train", "label": "HDFC MobileBanking", "package": "com.snapwork.hdfc", "permissions": ["android.permission.INTERNET"], "code": b"loadHdfcDashboard", "source": "internal_test", "reviewed_by": "QA Engineer"},
    {"name": "icici_imobile_official.apk", "split": "train", "label": "iMobile Pay", "package": "com.csam.icici.shop.imobile", "permissions": ["android.permission.INTERNET"], "code": b"startIciciFlow", "source": "public_dataset", "reviewed_by": "Auditor #1"},
    {"name": "SecureBank_Official.apk", "split": "train", "label": "SecureBank Official", "package": "com.securebank.official", "permissions": ["android.permission.INTERNET"], "code": b"secureBankAppCoreInit", "source": "analyst_review", "reviewed_by": "QA Engineer"},
    {"name": "bhim_upi_official.apk", "split": "train", "label": "BHIM UPI NPCI", "package": "in.org.npci.upiapp", "permissions": ["android.permission.INTERNET"], "code": b"npciUpiCore", "source": "public_dataset", "reviewed_by": "Auditor #2"},
    # Validation (5)
    {"name": "paytm_wallet_official.apk", "split": "validation", "label": "Paytm Wallet", "package": "net.one97.paytm", "permissions": ["android.permission.INTERNET"], "code": b"paytmSecureChannel", "source": "public_dataset", "reviewed_by": "Auditor #1"},
    {"name": "phonepe_official.apk", "split": "validation", "label": "PhonePe", "package": "com.phonepe.app", "permissions": ["android.permission.INTERNET"], "code": b"phonepeInit", "source": "internal_test", "reviewed_by": "SecOps Lead"},
    {"name": "gpay_india_official.apk", "split": "validation", "label": "Google Pay", "package": "com.google.android.apps.nbu.paisa.user", "permissions": ["android.permission.INTERNET"], "code": b"gpayFlowStart", "source": "analyst_review", "reviewed_by": "QA Engineer"},
    {"name": "airtel_thanks_official.apk", "split": "validation", "label": "Airtel Thanks", "package": "com.myairtelapp", "permissions": ["android.permission.INTERNET"], "code": b"airtelThanksPayments", "source": "public_dataset", "reviewed_by": "Auditor #4"},
    {"name": "mobikwik_official.apk", "split": "validation", "label": "MobiKwik", "package": "com.mobikwik_new", "permissions": ["android.permission.INTERNET"], "code": b"mobikwikWallet", "source": "internal_test", "reviewed_by": "SecOps Lead"}
]

# 10 Suspicious APKs (Clone indicators present: e.g., name similarity/keywords match, package mismatch)
suspicious_samples = [
    # Train (5)
    {"name": "fake_sbi_login.apk", "split": "train", "label": "SBI Yono Rewards", "package": "com.sbi.rewards.helper", "permissions": ["android.permission.INTERNET", "android.permission.SYSTEM_ALERT_WINDOW"], "code": b"drawFakeSbiOverlay", "source": "analyst_review", "reviewed_by": "Fraud Team"},
    {"name": "fake_icici_verify.apk", "split": "train", "label": "iMobile Security Guard", "package": "com.icici.verification.app", "permissions": ["android.permission.INTERNET", "android.permission.RECEIVE_BOOT_COMPLETED"], "code": b"iciciSimVerify", "source": "internal_test", "reviewed_by": "RedTeam Lead"},
    {"name": "fake_hdfc_rewards.apk", "split": "train", "label": "HDFC Rewards", "package": "com.hdfc.giftcards.free", "permissions": ["android.permission.INTERNET", "android.permission.REQUEST_INSTALL_PACKAGES"], "code": b"hdfcDropperInstall", "source": "analyst_review", "reviewed_by": "Auditor #1"},
    {"name": "SecureBank_Plus.apk", "split": "train", "label": "SecureBank Plus", "package": "com.securebank.plus", "permissions": ["android.permission.INTERNET", "android.permission.SYSTEM_ALERT_WINDOW"], "code": b"secureBankOverlayVerification", "source": "public_dataset", "reviewed_by": "RedTeam Lead"},
    {"name": "SecureBank_Clone.apk", "split": "train", "label": "SecureBank Clone", "package": "com.securebank.official", "permissions": ["android.permission.INTERNET"], "code": b"secureBankRepackagedMaliciousCode", "source": "analyst_review", "reviewed_by": "Fraud Team"},
    # Validation (5)
    {"name": "fake_axis_rewards.apk", "split": "validation", "label": "Axis Mobile Rewards", "package": "com.axis.mobile.rewards", "permissions": ["android.permission.INTERNET", "android.permission.SYSTEM_ALERT_WINDOW"], "code": b"drawAxisOverlay", "source": "internal_test", "reviewed_by": "Fraud Team"},
    {"name": "fake_yono_lite.apk", "split": "validation", "label": "Yono Lite SBI Official Support", "package": "com.sbi.yono.lite.support", "permissions": ["android.permission.INTERNET", "android.permission.SYSTEM_ALERT_WINDOW"], "code": b"yonoOverlayAd", "source": "public_dataset", "reviewed_by": "RedTeam Lead"},
    {"name": "fake_paytm_offers.apk", "split": "validation", "label": "Paytm Wallet Cashback Offers", "package": "net.one97.paytm.cashback", "permissions": ["android.permission.INTERNET", "android.permission.REQUEST_INSTALL_PACKAGES"], "code": b"paytmOffersDropper", "source": "analyst_review", "reviewed_by": "Auditor #2"},
    {"name": "fake_phonepe_scratch.apk", "split": "validation", "label": "PhonePe Scratch Card Helper", "package": "com.phonepe.scratchcard.helper", "permissions": ["android.permission.INTERNET", "android.permission.SYSTEM_ALERT_WINDOW"], "code": b"phonepeScratchOverlay", "source": "internal_test", "reviewed_by": "SecOps Lead"},
    {"name": "fake_gpay_bonus.apk", "split": "validation", "label": "Google Pay Bonus Hub Gift", "package": "com.gpay.bonus.helper.gift", "permissions": ["android.permission.INTERNET", "android.permission.REQUEST_INSTALL_PACKAGES"], "code": b"gpayBonusInstall", "source": "public_dataset", "reviewed_by": "QA Engineer"}
]

# 10 Malicious APKs (Bytecode/DEX indicator matches, malicious permissions)
malicious_samples = [
    # Train (5)
    {"name": "otp_stealer.apk", "split": "train", "label": "Android System Update", "package": "com.sys.update.helper", "permissions": ["android.permission.INTERNET", "android.permission.READ_SMS", "android.permission.RECEIVE_SMS"], "code": b"SmsManager sendTextMessage reading otp", "source": "analyst_review", "reviewed_by": "Incident Response"},
    {"name": "overlay_trojan.apk", "split": "train", "label": "Flash Player Update", "package": "com.adobe.flash.update", "permissions": ["android.permission.INTERNET", "android.permission.SYSTEM_ALERT_WINDOW", "android.permission.READ_SMS"], "code": b"WindowManager$LayoutParams drawOverlay sendTextMessage", "source": "public_dataset", "reviewed_by": "SecOps Lead"},
    {"name": "accessibility_abuse.apk", "split": "train", "label": "Accessibility Service Helper", "package": "com.access.service.helper", "permissions": ["android.permission.INTERNET", "android.permission.BIND_ACCESSIBILITY_SERVICE"], "code": b"onAccessibilityEvent performAction dumpText", "source": "internal_test", "reviewed_by": "Auditor #2"},
    {"name": "remote_control.apk", "split": "train", "label": "System Optimization Tool", "package": "com.opt.system.tool", "permissions": ["android.permission.INTERNET", "android.permission.BIND_ACCESSIBILITY_SERVICE", "android.permission.SYSTEM_ALERT_WINDOW"], "code": b"DexClassLoader PathClassLoader Runtime.getRuntime().exec", "source": "analyst_review", "reviewed_by": "SecOps Lead"},
    {"name": "banking_cred_stealer.apk", "split": "train", "label": "Chrome Update Service", "package": "com.android.chrome.services", "permissions": ["android.permission.INTERNET", "android.permission.READ_SMS", "android.permission.BIND_ACCESSIBILITY_SERVICE"], "code": b"SmsManager sendTextMessage addJavascriptInterface WebView", "source": "public_dataset", "reviewed_by": "Fraud Team"},
    # Validation (5)
    {"name": "spy_trojan.apk", "split": "validation", "label": "Device Care Manager", "package": "com.device.care.manager", "permissions": ["android.permission.INTERNET", "android.permission.READ_SMS", "android.permission.RECEIVE_SMS"], "code": b"SmsManager sendTextMessage divideMessage", "source": "analyst_review", "reviewed_by": "Incident Response"},
    {"name": "overlay_spyware.apk", "split": "validation", "label": "WhatsApp Theme Hub", "package": "com.wa.theme.hub", "permissions": ["android.permission.INTERNET", "android.permission.SYSTEM_ALERT_WINDOW", "android.permission.READ_SMS"], "code": b"SYSTEM_ALERT_WINDOW drawOverlay sendTextMessage okhttp", "source": "public_dataset", "reviewed_by": "QA Engineer"},
    {"name": "rat_accessibility.apk", "split": "validation", "label": "Auto Clicker Expert", "package": "com.autoclicker.expert", "permissions": ["android.permission.INTERNET", "android.permission.BIND_ACCESSIBILITY_SERVICE"], "code": b"AccessibilityService onAccessibilityEvent performAction Runtime exec", "source": "internal_test", "reviewed_by": "RedTeam Lead"},
    {"name": "dropper_dynamic.apk", "split": "validation", "label": "PDF Reader Pro Upgrade", "package": "com.pdfreader.pro.helper", "permissions": ["android.permission.INTERNET", "android.permission.REQUEST_INSTALL_PACKAGES"], "code": b"DexClassLoader loadClass Runtime exec url=http://malware-c2.com/payload", "source": "analyst_review", "reviewed_by": "SecOps Lead"},
    {"name": "overlay_dropper.apk", "split": "validation", "label": "VLC Video Codec", "package": "org.videolan.vlc.codec", "permissions": ["android.permission.INTERNET", "android.permission.SYSTEM_ALERT_WINDOW", "android.permission.BIND_ACCESSIBILITY_SERVICE"], "code": b"SYSTEM_ALERT_WINDOW DexClassLoader addJavascriptInterface url=http://c2-botnet-bypass.com", "source": "public_dataset", "reviewed_by": "Fraud Team"}
]

def create_minimal_apk(dest_path: str, manifest_xml: str, classes_dex_bytes: bytes, cert_rsa_bytes: bytes):
    with zipfile.ZipFile(dest_path, "w", zipfile.ZIP_DEFLATED) as zf:
        # Write AndroidManifest.xml (text format)
        zf.writestr("AndroidManifest.xml", manifest_xml.encode("utf-8"))
        # Write classes.dex (binary format with code payload)
        zf.writestr("classes.dex", classes_dex_bytes)
        # Write dummy icon
        zf.writestr("res/drawable/icon.png", b"MOCK_PNG_IMAGE_BYTES")
        # Write mock certificate signing metadata files
        zf.writestr("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\nCreated-By: 1.0 (Android)\n\n")
        zf.writestr("META-INF/CERT.SF", b"Signature-Version: 1.0\nCreated-By: 1.0 (Android)\n\n")
        zf.writestr("META-INF/CERT.RSA", cert_rsa_bytes)

def init_dataset():
    # Remove existing dataset dir and rebuild
    if os.path.exists(DATASET_DIR):
        import shutil
        shutil.rmtree(DATASET_DIR)
    
    categories_map = {
        "benign": benign_samples,
        "suspicious": suspicious_samples,
        "malicious": malicious_samples
    }
    
    for category, samples in categories_map.items():
        for s in samples:
            split_dir = os.path.join(DATASET_DIR, s["split"], category)
            os.makedirs(split_dir, exist_ok=True)
            
            apk_path = os.path.join(split_dir, s["name"])
            json_path = os.path.join(split_dir, s["name"].replace(".apk", ".json"))
            
            # Form AndroidManifest.xml string
            perms_xml = "\n".join([f'    <uses-permission android:name="{p}"/>' for p in s["permissions"]])
            manifest_xml = f"""<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="{s["package"]}"
    android:versionCode="101"
    android:versionName="1.0.1">
    
{perms_xml}

    <application
        android:label="{s["label"]}"
        android:icon="res/drawable/icon.png"
        android:minSdkVersion="21"
        android:targetSdkVersion="33">
        <activity android:name=".MainActivity">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>
"""
            # Create minimal ZIP representing the APK file
            create_minimal_apk(apk_path, manifest_xml, s["code"], s["code"])
            
            # Derive a real SHA-256 fingerprint from the APK code bytes
            # so every app has a unique, non-stub fingerprint.
            sha256_hex = hashlib.sha256(s["code"]).hexdigest()
            sha256_hash = sha256_hex  # 64-char lowercase hex, no colon formatting

            cert_val = {
                "issuer": "CN=SecureBank Official, O=SecureBank, C=US" if "SecureBank_Official" in s["name"] else "CN=Android Debug, O=Android, C=US",
                "subject": "CN=SecureBank Official, O=SecureBank, C=US" if "SecureBank_Official" in s["name"] else "CN=Android Debug, O=Android, C=US",
                "serial_number": "12345678",
                "sha256": sha256_hash,
                "sha1": "SHA1:12:34:56"
            }
            
            # Create provenance/metadata file
            metadata = {
                "apk_name": s["name"],
                "package_name": s["package"],
                "app_label": s["label"],
                "permissions": s["permissions"],
                "ground_truth": category.upper(),
                "certificates": [cert_val],
                "source": s["source"],
                "reviewed_by": s["reviewed_by"],
                "created_at": "2026-06-17T12:00:00Z",
                "apk_origin": "generated"  # Distinct from 'user' or 'external'
            }
            with open(json_path, "w", encoding="utf-8") as f:
                json.dump(metadata, f, indent=2)

    print("New Train/Validation benchmark dataset (30 samples) initialized successfully.")

if __name__ == "__main__":
    init_dataset()
