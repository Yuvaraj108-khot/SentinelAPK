import os
import json
import zipfile

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATASET_DIR = os.path.join(BASE_DIR, "dataset")

# 1. Hard Benign Samples (Designed to trigger False Positives)
# Often ask for SYSTEM_ALERT_WINDOW, RECEIVE_BOOT_COMPLETED or look like official banking names but are signed legitimately.
benign_samples = [
    # Train
    {
        "name": "legit_bank_assistant.apk",
        "split": "train",
        "label": "SecureBank Assistant Utility",
        "package": "com.securebank.assistant",
        "permissions": ["android.permission.INTERNET", "android.permission.SYSTEM_ALERT_WINDOW", "android.permission.RECEIVE_BOOT_COMPLETED"],
        "code": b"renderOverlayHelper renderDashboard",
        "source": "official_repository",
        "reviewed_by": "SecOps Auditor #1"
    },
    {
        "name": "sbi_customer_help.apk",
        "split": "train",
        "label": "Yono SBI Support Helpdesk",
        "package": "com.sbi.yono.support",
        "permissions": ["android.permission.INTERNET", "android.permission.SYSTEM_ALERT_WINDOW"],
        "code": b"yonoSupportInit",
        "source": "official_repository",
        "reviewed_by": "SecOps Auditor #2"
    },
    {
        "name": "hdfc_smart_auth.apk",
        "split": "train",
        "label": "HDFC Smart Authentication",
        "package": "com.hdfcbank.smartauth",
        "permissions": ["android.permission.INTERNET", "android.permission.USE_BIOMETRIC"],
        "code": b"hdfcAuthCore",
        "source": "internal_test",
        "reviewed_by": "QA Lead"
    },
    {
        "name": "gpay_rewards_official.apk",
        "split": "train",
        "label": "Google Pay Rewards Engine",
        "package": "com.google.android.apps.nbu.paisa.user",
        "permissions": ["android.permission.INTERNET"],
        "code": b"gpayRewardsCore",
        "source": "official_repository",
        "reviewed_by": "Google Auditor"
    },
    {
        "name": "phonepe_business_legit.apk",
        "split": "train",
        "label": "PhonePe Business Merchant",
        "package": "com.phonepe.app.business",
        "permissions": ["android.permission.INTERNET", "android.permission.ACCESS_FINE_LOCATION"],
        "code": b"phonepeMerchantInit",
        "source": "official_repository",
        "reviewed_by": "SecOps Auditor #1"
    },
    # Validation
    {
        "name": "icici_imobile_helper.apk",
        "split": "validation",
        "label": "iMobile Pay Support Assistant",
        "package": "com.csam.icici.shop.imobile.helper",
        "permissions": ["android.permission.INTERNET", "android.permission.SYSTEM_ALERT_WINDOW"],
        "code": b"iciciHelperMain",
        "source": "official_repository",
        "reviewed_by": "SecOps Auditor #2"
    },
    {
        "name": "paytm_legit_merchant.apk",
        "split": "validation",
        "label": "Paytm Business Wallet",
        "package": "net.one97.paytm.merchant",
        "permissions": ["android.permission.INTERNET", "android.permission.ACCESS_COARSE_LOCATION"],
        "code": b"paytmMerchantCore",
        "source": "official_repository",
        "reviewed_by": "QA Engineer"
    },
    {
        "name": "axis_bank_official_legit.apk",
        "split": "validation",
        "label": "Axis Mobile official",
        "package": "com.axis.mobile",
        "permissions": ["android.permission.INTERNET"],
        "code": b"axisMobileCoreMain",
        "source": "official_repository",
        "reviewed_by": "QA Lead"
    },
    {
        "name": "airtel_thanks_legit.apk",
        "split": "validation",
        "label": "Airtel Thanks",
        "package": "com.myairtelapp",
        "permissions": ["android.permission.INTERNET"],
        "code": b"airtelThanksCore",
        "source": "official_repository",
        "reviewed_by": "Airtel Security"
    },
    {
        "name": "mobikwik_official_wallet.apk",
        "split": "validation",
        "label": "MobiKwik",
        "package": "com.mobikwik_new",
        "permissions": ["android.permission.INTERNET"],
        "code": b"mobikwikCoreWallet",
        "source": "official_repository",
        "reviewed_by": "Auditor #2"
    }
]

# 2. Hard Suspicious Samples (Borderline classification cases, e.g. clone name similar or unrecognized cert, but minimal permissions)
suspicious_samples = [
    # Train
    {
        "name": "fake_sbi_login.apk",
        "split": "train",
        "label": "Yono SBI Rewards Hub",
        "package": "com.sbi.yono.rewards.hub",
        "permissions": ["android.permission.INTERNET", "android.permission.SYSTEM_ALERT_WINDOW"],
        "code": b"drawFakeSbiOverlay",
        "source": "adversarial_honeypot",
        "reviewed_by": "Incident Response"
    },
    {
        "name": "fake_hdfc_gift.apk",
        "split": "train",
        "label": "HDFC Rewards Free Card",
        "package": "com.hdfcbank.rewards.free",
        "permissions": ["android.permission.INTERNET"],
        "code": b"hdfcGiftAdOverlay",
        "source": "adversarial_honeypot",
        "reviewed_by": "Fraud Team"
    },
    {
        "name": "fake_axis_rewards.apk",
        "split": "train",
        "label": "Axis Mobile Rewards Pro",
        "package": "com.axis.rewards.pro",
        "permissions": ["android.permission.INTERNET", "android.permission.SYSTEM_ALERT_WINDOW"],
        "code": b"axisAdOverlay",
        "source": "adversarial_honeypot",
        "reviewed_by": "Fraud Team"
    },
    {
        "name": "SecureBank_Plus_Clone.apk",
        "split": "train",
        "label": "SecureBank Plus Hub",
        "package": "com.securebank.plus",
        "permissions": ["android.permission.INTERNET", "android.permission.SYSTEM_ALERT_WINDOW"],
        "code": b"renderSecureBankOverlay",
        "source": "adversarial_honeypot",
        "reviewed_by": "RedTeam Lead"
    },
    {
        "name": "SecureBank_Official_Repackaged.apk",
        "split": "train",
        "label": "SecureBank Official",
        "package": "com.securebank.official",
        "permissions": ["android.permission.INTERNET"],
        "code": b"repackagedSecureBankCore",
        "source": "adversarial_honeypot",
        "reviewed_by": "Fraud Team"
    },
    # Validation
    {
        "name": "fake_icici_imobile_rewards.apk",
        "split": "validation",
        "label": "iMobile Pay Cashback Assistant",
        "package": "com.icici.imobile.cashback.assistant",
        "permissions": ["android.permission.INTERNET", "android.permission.SYSTEM_ALERT_WINDOW"],
        "code": b"drawIciciOverlayWindow",
        "source": "adversarial_honeypot",
        "reviewed_by": "SecOps Auditor #2"
    },
    {
        "name": "fake_paytm_bonus.apk",
        "split": "validation",
        "label": "Paytm Wallet Cash Bonus Helper",
        "package": "net.one97.paytm.cashback.bonus",
        "permissions": ["android.permission.INTERNET"],
        "code": b"paytmBonusOverlay",
        "source": "adversarial_honeypot",
        "reviewed_by": "Fraud Team"
    },
    {
        "name": "fake_phonepe_cashback.apk",
        "split": "validation",
        "label": "PhonePe Scratch Coupon Pro",
        "package": "com.phonepe.scratch.coupon.pro",
        "permissions": ["android.permission.INTERNET", "android.permission.SYSTEM_ALERT_WINDOW"],
        "code": b"phonepeCashbackOverlay",
        "source": "adversarial_honeypot",
        "reviewed_by": "Fraud Team"
    },
    {
        "name": "fake_gpay_scratch.apk",
        "split": "validation",
        "label": "Google Pay Bonus Hub",
        "package": "com.gpay.bonus.helper",
        "permissions": ["android.permission.INTERNET"],
        "code": b"gpayBonusOverlayWindow",
        "source": "adversarial_honeypot",
        "reviewed_by": "Incident Response"
    },
    {
        "name": "fake_yono_lite.apk",
        "split": "validation",
        "label": "Yono Lite SBI Official Helpdesk",
        "package": "com.sbi.yono.lite.helpdesk",
        "permissions": ["android.permission.INTERNET", "android.permission.SYSTEM_ALERT_WINDOW"],
        "code": b"yonoLiteAdOverlay",
        "source": "adversarial_honeypot",
        "reviewed_by": "Fraud Team"
    }
]

# 3. Hard Malicious Samples (Designed to trigger False Negatives, obfuscated DEX or minimal malicious permission combinations)
malicious_samples = [
    # Train
    {
        "name": "obfuscated_otp_stealer.apk",
        "split": "train",
        "label": "Android System Optimization",
        "package": "com.optimization.helper",
        "permissions": ["android.permission.INTERNET", "android.permission.RECEIVE_SMS"],
        "code": b"obfuscatedSmsReceiver readMessage textMsg C2Url",
        "source": "active_malware_wild",
        "reviewed_by": "SecOps Analyst #2"
    },
    {
        "name": "stealth_dropper.apk",
        "split": "train",
        "label": "PDF Reader Upgrade",
        "package": "com.pdf.reader.upgrade",
        "permissions": ["android.permission.INTERNET", "android.permission.REQUEST_INSTALL_PACKAGES"],
        "code": b"DexClassLoader loadClass runtimeExec",
        "source": "active_malware_wild",
        "reviewed_by": "Incident Response"
    },
    {
        "name": "stealth_accessibility.apk",
        "split": "train",
        "label": "Accessibility Assistant Tool",
        "package": "com.assist.tool",
        "permissions": ["android.permission.INTERNET", "android.permission.BIND_ACCESSIBILITY_SERVICE"],
        "code": b"AccessibilityService onAccessibilityEvent performAction",
        "source": "active_malware_wild",
        "reviewed_by": "Incident Response"
    },
    {
        "name": "stealth_banking_overlay.apk",
        "split": "train",
        "label": "Chrome Update Assistant",
        "package": "com.chrome.update.assistant",
        "permissions": ["android.permission.INTERNET", "android.permission.SYSTEM_ALERT_WINDOW"],
        "code": b"SYSTEM_ALERT_WINDOW drawOverlay injectJs addJavascriptInterface",
        "source": "active_malware_wild",
        "reviewed_by": "Fraud Team"
    },
    {
        "name": "rat_stealth.apk",
        "split": "train",
        "label": "VLC Codec Plugin",
        "package": "org.videolan.vlc.codec.plugin",
        "permissions": ["android.permission.INTERNET", "android.permission.BIND_ACCESSIBILITY_SERVICE", "android.permission.SYSTEM_ALERT_WINDOW"],
        "code": b"AccessibilityService DexClassLoader executeCommand",
        "source": "active_malware_wild",
        "reviewed_by": "Incident Response"
    },
    # Validation
    {
        "name": "spy_trojan.apk",
        "split": "validation",
        "label": "Device Care Manager Official",
        "package": "com.device.care.manager.official",
        "permissions": ["android.permission.INTERNET", "android.permission.RECEIVE_SMS"],
        "code": b"SmsManager readMessage exfiltrateOtp",
        "source": "active_malware_wild",
        "reviewed_by": "Incident Response"
    },
    {
        "name": "overlay_spyware.apk",
        "split": "validation",
        "label": "WhatsApp Theme Plus",
        "package": "com.wa.theme.plus",
        "permissions": ["android.permission.INTERNET", "android.permission.SYSTEM_ALERT_WINDOW"],
        "code": b"SYSTEM_ALERT_WINDOW drawOverlay",
        "source": "active_malware_wild",
        "reviewed_by": "Incident Response"
    },
    {
        "name": "rat_accessibility.apk",
        "split": "validation",
        "label": "Auto Tap Helper",
        "package": "com.autotap.helper",
        "permissions": ["android.permission.INTERNET", "android.permission.BIND_ACCESSIBILITY_SERVICE"],
        "code": b"AccessibilityService onAccessibilityEvent performAction runtimeExec",
        "source": "active_malware_wild",
        "reviewed_by": "SecOps Analyst #2"
    },
    {
        "name": "dropper_dynamic.apk",
        "split": "validation",
        "label": "VLC Video Codec Ext",
        "package": "org.videolan.vlc.codec.ext",
        "permissions": ["android.permission.INTERNET", "android.permission.REQUEST_INSTALL_PACKAGES"],
        "code": b"DexClassLoader loadClass url=http://malware-server.com",
        "source": "active_malware_wild",
        "reviewed_by": "SecOps Analyst #1"
    },
    {
        "name": "overlay_dropper.apk",
        "split": "validation",
        "label": "Airtel Thanks Promo Help",
        "package": "com.myairtelapp.promo.help",
        "permissions": ["android.permission.INTERNET", "android.permission.SYSTEM_ALERT_WINDOW", "android.permission.BIND_ACCESSIBILITY_SERVICE"],
        "code": b"SYSTEM_ALERT_WINDOW AccessibilityService DexClassLoader",
        "source": "active_malware_wild",
        "reviewed_by": "Fraud Team"
    }
]

def create_mock_apk(dest_path: str, manifest_xml: str, classes_dex_bytes: bytes):
    with zipfile.ZipFile(dest_path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("AndroidManifest.xml", manifest_xml.encode("utf-8"))
        zf.writestr("classes.dex", classes_dex_bytes)
        zf.writestr("res/drawable/icon.png", b"PNG_MOCK_IMAGE_BYTES")
        zf.writestr("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\nCreated-By: 1.0\n\n")
        zf.writestr("META-INF/CERT.SF", b"Signature-Version: 1.0\nCreated-By: 1.0\n\n")
        zf.writestr("META-INF/CERT.RSA", b"SIGNATURE_RSA_BYTES")

def init_dataset():
    if os.path.exists(DATASET_DIR):
        import shutil
        shutil.rmtree(DATASET_DIR)
        
    categories = {
        "benign": benign_samples,
        "suspicious": suspicious_samples,
        "malicious": malicious_samples
    }
    
    for category, samples in categories.items():
        for s in samples:
            split_dir = os.path.join(DATASET_DIR, s["split"], category)
            os.makedirs(split_dir, exist_ok=True)
            
            apk_path = os.path.join(split_dir, s["name"])
            json_path = os.path.join(split_dir, s["name"].replace(".apk", ".json"))
            
            # Form XML permissions
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
            create_mock_apk(apk_path, manifest_xml, s["code"])
            
            # Setup certificate reputation SHA256 hashes
            if "legit" in s["name"] or "official" in s["name"]:
                if "sbi" in s["name"]:
                    sha256_hash = "SHA256:7B:A9:E2"
                elif "hdfc" in s["name"]:
                    sha256_hash = "SHA256:9D:E1:F3"
                elif "icici" in s["name"]:
                    sha256_hash = "SHA256:8C:B2:D4"
                else:
                    sha256_hash = "SHA256:7A:B3:C2"  # Trusted fallback signature
            else:
                sha256_hash = "SHA256:FF:EE:DD"  # Unknown certificate

            cert_val = {
                "issuer": "CN=Android Debug, O=Android, C=US",
                "subject": "CN=Android Debug, O=Android, C=US",
                "serial_number": "12345678",
                "sha256": sha256_hash,
                "sha1": "SHA1:12:34:56"
            }
            
            metadata = {
                "apk_name": s["name"],
                "permissions": s["permissions"],
                "dex_indicators": [s["code"].decode("utf-8", errors="ignore")],
                "package_name": s["package"],
                "app_label": s["label"],
                "certificate_hash": sha256_hash,
                "ground_truth": category.upper(),
                "certificates": [cert_val],
                "source": s["source"],
                "reviewed_by": s["reviewed_by"],
                "apk_origin": "generated"
            }
            
            with open(json_path, "w", encoding="utf-8") as f:
                json.dump(metadata, f, indent=2)

    print("Hard learning-focused train/validation dataset initialized successfully.")

if __name__ == "__main__":
    init_dataset()
