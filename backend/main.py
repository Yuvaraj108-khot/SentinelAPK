import os
import json
import uuid
import logging
from typing import Dict, Any, List
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse
from pydantic import BaseModel
from dotenv import load_dotenv

# Load env variables
load_dotenv()

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("sentinel.main")

# Import our modular backend code
from analyzer import APKAnalyzer
from risk_engine import RiskEngine
from llm_client import LLMClient
from report_generator import ReportGenerator
from evader_agent import EvaderAgent
import memory_store

app = FastAPI(
    title="SentinelAPK API",
    description="Explainable AI Threat Intelligence for Android Banking Applications"
)

# Enable CORS for Next.js frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Ensure temp directories exist
UPLOAD_DIR = os.path.join(os.path.dirname(__file__), "temp_uploads")
REPORT_DIR = os.path.join(os.path.dirname(__file__), "temp_reports")
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(REPORT_DIR, exist_ok=True)

@app.get("/")
async def read_root():
    return {
        "status": "online",
        "message": "SentinelAPK Explainable Threat Intelligence API is running",
        "documentation": "/docs"
    }

# Initialize LLM Client
llm_client = LLMClient()
evader_agent = EvaderAgent()

# Sample data store
SAMPLES = {
    "anubis": {
        "metadata": {
            "app_name": "Anubis Bank Authenticator",
            "package_name": "com.security.authenticator.anubis",
            "version_name": "4.12.0",
            "version_code": "48",
            "min_sdk": "21",
            "target_sdk": "33",
            "permissions": [
                "android.permission.BIND_ACCESSIBILITY_SERVICE",
                "android.permission.READ_SMS",
                "android.permission.RECEIVE_SMS",
                "android.permission.SEND_SMS",
                "android.permission.SYSTEM_ALERT_WINDOW",
                "android.permission.INTERNET",
                "android.permission.QUERY_ALL_PACKAGES",
                "android.permission.RECEIVE_BOOT_COMPLETED"
            ],
            "activities": ["com.anubis.auth.MainActivity", "com.anubis.auth.OverlayActivity", "com.anubis.auth.SettingsActivity"],
            "services": ["com.anubis.auth.BackgroundService", "com.anubis.auth.AccessibilityHandler"],
            "receivers": ["com.anubis.auth.BootReceiver", "com.anubis.auth.SMSReceiver"],
            "providers": [],
            "certificates": [
                {
                    "issuer": "CN=Anubis Dev, OU=Security, O=AnubisInc, L=Unknown, C=US",
                    "subject": "CN=Anubis Dev, OU=Security, O=AnubisInc, L=Unknown, C=US",
                    "serial_number": "18471204812903",
                    "sha256": "8f3e2a1b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f",
                    "sha1": "7e6f5d4c3b2a1a0987654321fedcba9876543210"
                }
            ],
            "dex_indicators": {
                "sms_send": True,
                "accessibility_callback": True,
                "overlay_window": True,
                "http_client": True
            }
        },
        "risk": {
            "score": 85,
            "verdict": "MALICIOUS",
            "severity": "Critical",
            "confidence": 95,
            "top_reasons": [
                "Uses Accessibility Service (highly abused by Trojans)",
                "Requests SMS reading/interception permissions (OTP theft risk)",
                "Requests System Alert overlay permission (overlay phishing risk)",
                "Queries all installed packages (targets specific banking apps)"
            ],
            "triggered_rules": [
                {"permission": "android.permission.BIND_ACCESSIBILITY_SERVICE", "weight": 25, "description": "Requests high-risk permission: BIND_ACCESSIBILITY_SERVICE"},
                {"permission": "android.permission.READ_SMS", "weight": 20, "description": "Requests high-risk permission: READ_SMS"},
                {"permission": "android.permission.RECEIVE_SMS", "weight": 20, "description": "Requests high-risk permission: RECEIVE_SMS"},
                {"permission": "android.permission.SYSTEM_ALERT_WINDOW", "weight": 20, "description": "Requests high-risk permission: SYSTEM_ALERT_WINDOW"},
                {"permission": "android.permission.INTERNET", "weight": 5, "description": "Requests permission: INTERNET"}
            ],
            "mitre_techniques": [
                {"id": "T1430", "name": "Input Capture / Accessibility Abuse", "description": "Abusing Accessibility APIs to capture keystrokes, read screen contents, and click buttons automatically."},
                {"id": "T1636", "name": "SMS Data Collection", "description": "Reading incoming SMS messages to extract transaction notifications or OTPs."},
                {"id": "T1636.002", "name": "SMS Interception", "description": "Intercepting incoming SMS text messages, often to bypass two-factor authentication (2FA)."},
                {"id": "T1418", "name": "Input Overlay / Spoofing", "description": "Creating windows over other apps to capture credentials via custom overlays (phishing)."}
            ],
            "attack_chain": [
                {"step": "Accessibility Enabled", "desc": "User is tricked into granting accessibility permissions."},
                {"step": "Fake UI Overlay", "desc": "Intercepts launching target apps and overlays credential harvesting screens."},
                {"step": "SMS Interception", "desc": "Reads incoming messages containing OTPs / Verification Codes."},
                {"step": "Data Exfiltration", "desc": "Sends harvested credentials and OTPs to remote Command & Control (C2) server."}
            ],
            "evidence_validation": {
                "sms": {"status": "FOUND", "matched_string": "android.permission.READ_SMS, android.permission.RECEIVE_SMS", "source_file": "AndroidManifest.xml", "offset": 0, "extraction_method": "manifest_permission_tag", "confidence": 1.0},
                "accessibility": {"status": "FOUND", "matched_string": "android.permission.BIND_ACCESSIBILITY_SERVICE", "source_file": "AndroidManifest.xml", "offset": 0, "extraction_method": "manifest_permission_tag", "confidence": 1.0},
                "overlay": {"status": "FOUND", "matched_string": "android.permission.SYSTEM_ALERT_WINDOW", "source_file": "AndroidManifest.xml", "offset": 0, "extraction_method": "manifest_permission_tag", "confidence": 1.0},
                "runtime_exec": {"status": "UNKNOWN", "reason": "NO_EVIDENCE_AVAILABLE"},
                "dynamic_loading": {"status": "UNKNOWN", "reason": "NO_EVIDENCE_AVAILABLE"},
                "clone_detection": {"status": "UNKNOWN", "reason": "NO_EVIDENCE_AVAILABLE"},
                "certificate_validation": {"status": "UNKNOWN", "reason": "NO_EVIDENCE_AVAILABLE"}
            }
        },
        "ai": {
            "suspicious_permissions_rationale": "The app requests BIND_ACCESSIBILITY_SERVICE and SYSTEM_ALERT_WINDOW. These are highly privileged permissions that are almost never required for authenticators. They allow full UI automation and interface overlays.",
            "otp_theft_capability": "CRITICAL RISK. Declaring SMS read and receive receiver permissions grants full control over reading incoming messages, enabling the app to silently parse, extract, and suppress SMS OTPs before the user notices.",
            "accessibility_abuse": "CRITICAL RISK. The Accessibility Service permission allows the application to log keystrokes, extract input field text, bypass security warnings, and execute tap controls on behalf of the user.",
            "impersonation_risk": "HIGH RISK. Using SYSTEM_ALERT_WINDOW allows custom web view overlays. When a legitimate financial application is launched, the malware can display a fake overlay login UI designed to harvest passwords.",
            "data_exfiltration": "HIGH RISK. Coupled with INTERNET access, any captured credentials, keystrokes, or intercepted SMS messages can be immediately transmitted to command-and-control (C2) servers.",
            "verdict_reasoning": "Marked as Malicious. The permission footprint is identical to standard banking Trojan structures (e.g., Anubis/Cerberus). There is no legitimate reason for an authenticator to request SMS interception, accessibility binding, and general overlays."
        }
    },
    "cerberus": {
        "metadata": {
            "app_name": "Flash Player Update",
            "package_name": "com.adobe.flash.updater",
            "version_name": "11.2.8",
            "version_code": "112",
            "min_sdk": "19",
            "target_sdk": "31",
            "permissions": [
                "android.permission.READ_SMS",
                "android.permission.RECEIVE_SMS",
                "android.permission.SEND_SMS",
                "android.permission.INTERNET",
                "android.permission.RECEIVE_BOOT_COMPLETED",
                "android.permission.REQUEST_INSTALL_PACKAGES"
            ],
            "activities": ["com.flash.updater.MainActivity", "com.flash.updater.InstallActivity"],
            "services": ["com.flash.updater.SMSListenerService", "com.flash.updater.UpdateDaemon"],
            "receivers": ["com.flash.updater.BootReceiver", "com.flash.updater.SMSReceiver"],
            "providers": [],
            "certificates": [
                {
                    "issuer": "CN=Android Debug, O=Android, C=US",
                    "subject": "CN=Android Debug, O=Android, C=US",
                    "serial_number": "1",
                    "sha256": "ac82e3f4e5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2",
                    "sha1": "abcdef0123456789abcdef0123456789abcdef01"
                }
            ],
            "dex_indicators": {
                "sms_send": True,
                "accessibility_callback": False,
                "overlay_window": False,
                "http_client": True
            }
        },
        "risk": {
            "score": 75,
            "verdict": "MALICIOUS",
            "severity": "Critical",
            "confidence": 92,
            "top_reasons": [
                "Requests SMS reading/interception permissions (OTP theft risk)",
                "Requests installing package packages (dropper payload risk)"
            ],
            "triggered_rules": [
                {"permission": "android.permission.READ_SMS", "weight": 20, "description": "Requests high-risk permission: READ_SMS"},
                {"permission": "android.permission.RECEIVE_SMS", "weight": 20, "description": "Requests high-risk permission: RECEIVE_SMS"},
                {"permission": "android.permission.SEND_SMS", "weight": 20, "description": "Requests high-risk permission: SEND_SMS"},
                {"permission": "android.permission.REQUEST_INSTALL_PACKAGES", "weight": 15, "description": "Requests permission: REQUEST_INSTALL_PACKAGES"}
            ],
            "mitre_techniques": [
                {"id": "T1636", "name": "SMS Data Collection", "description": "Reading incoming SMS messages to extract transaction notifications or OTPs."},
                {"id": "T1636.002", "name": "SMS Interception", "description": "Intercepting incoming SMS text messages, often to bypass two-factor authentication (2FA)."},
                {"id": "T1407", "name": "Malicious App Download / Update", "description": "Requesting to install additional APK files, which can bypass store-level security checks."}
            ],
            "attack_chain": [
                {"step": "Dropper Execution", "desc": "Malicious app executes and requests package install permissions."},
                {"step": "SMS Interception", "desc": "Reads incoming messages containing OTPs / Verification Codes."},
                {"step": "Data Exfiltration", "desc": "Sends harvested credentials and OTPs to remote Command & Control (C2) server."}
            ],
            "evidence_validation": {
                "sms": {"status": "FOUND", "matched_string": "android.permission.READ_SMS, android.permission.RECEIVE_SMS", "source_file": "AndroidManifest.xml", "offset": 0, "extraction_method": "manifest_permission_tag", "confidence": 1.0},
                "accessibility": {"status": "UNKNOWN", "reason": "NO_EVIDENCE_AVAILABLE"},
                "overlay": {"status": "UNKNOWN", "reason": "NO_EVIDENCE_AVAILABLE"},
                "runtime_exec": {"status": "UNKNOWN", "reason": "NO_EVIDENCE_AVAILABLE"},
                "dynamic_loading": {"status": "UNKNOWN", "reason": "NO_EVIDENCE_AVAILABLE"},
                "clone_detection": {"status": "UNKNOWN", "reason": "NO_EVIDENCE_AVAILABLE"},
                "certificate_validation": {"status": "UNKNOWN", "reason": "NO_EVIDENCE_AVAILABLE"}
            }
        },
        "ai": {
            "suspicious_permissions_rationale": "The app claims to be a Flash Player update but requests full SMS management capabilities and the permission to install other apps, which is classic dropper behavior.",
            "otp_theft_capability": "CRITICAL RISK. Full capabilities to intercept and send SMS enable OTP grabbing and forwarding, defeating standard SMS-based authentication.",
            "accessibility_abuse": "No direct Accessibility request. However, it can still intercept keystrokes if the user grants other API helpers.",
            "impersonation_risk": "Low direct overlay risk, but it can download and launch custom prompt windows via package installer APIs.",
            "data_exfiltration": "HIGH RISK. Sends local network logs, installed package lists, and SMS contents directly over internet channels.",
            "verdict_reasoning": "Marked as Malicious. A Flash Player clone asking for SMS interception and dropper permissions is a textbook banking Trojan/SMS stealer dropper."
        }
    },
    "safe_wallet": {
        "metadata": {
            "app_name": "Secure Wallet",
            "package_name": "com.legit.securewallet",
            "version_name": "1.0.4",
            "version_code": "5",
            "min_sdk": "24",
            "target_sdk": "34",
            "permissions": [
                "android.permission.INTERNET",
                "android.permission.ACCESS_NETWORK_STATE",
                "android.permission.USE_BIOMETRIC"
            ],
            "activities": ["com.legit.securewallet.MainActivity", "com.legit.securewallet.PinActivity"],
            "services": [],
            "receivers": [],
            "providers": [],
            "certificates": [
                {
                    "issuer": "CN=SecureWallet LLC, OU=Mobile Dev, O=SecureWallet LLC, C=US",
                    "subject": "CN=SecureWallet LLC, OU=Mobile Dev, O=SecureWallet LLC, C=US",
                    "serial_number": "9021849021",
                    "sha256": "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b",
                    "sha1": "1234567890abcdef1234567890abcdef12345678"
                }
            ],
            "dex_indicators": {
                "sms_send": False,
                "accessibility_callback": False,
                "overlay_window": False,
                "http_client": True
            }
        },
        "risk": {
            "score": 5,
            "verdict": "SAFE",
            "severity": "Low",
            "confidence": 80,
            "top_reasons": [
                "Minimal permission usage; behaves within standard boundaries."
            ],
            "triggered_rules": [
                {"permission": "android.permission.INTERNET", "weight": 5, "description": "Requests permission: INTERNET"}
            ],
            "mitre_techniques": [],
            "attack_chain": [
                {"step": "Standard Execution", "desc": "App starts up and requests permissions."},
                {"step": "Local API Usage", "desc": "Uses declared permissions for internal functions."},
                {"step": "Safe Execution", "desc": "No exfiltration or interception chains detected."}
            ],
            "evidence_validation": {
                "sms": {"status": "UNKNOWN", "reason": "NO_EVIDENCE_AVAILABLE"},
                "accessibility": {"status": "UNKNOWN", "reason": "NO_EVIDENCE_AVAILABLE"},
                "overlay": {"status": "UNKNOWN", "reason": "NO_EVIDENCE_AVAILABLE"},
                "runtime_exec": {"status": "UNKNOWN", "reason": "NO_EVIDENCE_AVAILABLE"},
                "dynamic_loading": {"status": "UNKNOWN", "reason": "NO_EVIDENCE_AVAILABLE"},
                "clone_detection": {"status": "UNKNOWN", "reason": "NO_EVIDENCE_AVAILABLE"},
                "certificate_validation": {"status": "UNKNOWN", "reason": "NO_EVIDENCE_AVAILABLE"}
            }
        },
        "ai": {
            "suspicious_permissions_rationale": "No suspicious permissions requested. Only standard Internet access is declared for banking servers.",
            "otp_theft_capability": "No SMS permissions declared. The application does not present an OTP theft threat.",
            "accessibility_abuse": "No Accessibility service requests found.",
            "impersonation_risk": "No overlay permissions requested. Impersonation of other applications is not possible.",
            "data_exfiltration": "Internet access is requested, but the app has no access to sensitive local resources (contacts, SMS, location, recording) to exfiltrate.",
            "verdict_reasoning": "Marked as Safe. Highly conservative permission profile. Signature is valid and serial number matches corporate standard."
        }
    }
}

# In-memory session store for generated reports
ACTIVE_REPORTS = {}

@app.post("/api/analyze")
async def analyze_apk(file: UploadFile = File(...)):
    """
    Receives an APK, parses static manifest elements, computes risk metrics,
    queries LLM analysis, and generates a downloadable PDF and HTML report.
    """
    if not file.filename.endswith(".apk"):
        raise HTTPException(status_code=400, detail="Only .apk files are supported.")
        
    session_id = str(uuid.uuid4())
    temp_path = os.path.join(UPLOAD_DIR, f"{session_id}.apk")
    
    try:
        # Save file locally
        with open(temp_path, "wb") as buffer:
            content = await file.read()
            buffer.write(content)
            
        # Parse APK
        analyzer = APKAnalyzer(temp_path)
        metadata = analyzer.analyze()
        
        # Calculate Risk
        has_services = len(metadata.get("services", [])) > 0
        has_certs = len(metadata.get("certificates", [])) > 0
        risk_data = RiskEngine.calculate_risk(
            metadata["permissions"], 
            has_services, 
            has_certs, 
            metadata.get("dex_indicators"),
            metadata.get("package_name", "Unknown"),
            metadata.get("certificates", []),
            metadata.get("app_name", "Unknown"),
            metadata.get("activities", [])
        )
        
        # Explainable AI Analysis
        ai_data = llm_client.analyze_apk(metadata, risk_data)
        
        # Generate HTML report and path for PDF
        pdf_path = os.path.join(REPORT_DIR, f"{session_id}.pdf")
        ReportGenerator.generate_pdf(metadata, risk_data, ai_data, pdf_path)
        
        response_data = {
            "session_id": session_id,
            "metadata": metadata,
            "risk": risk_data,
            "ai": ai_data,
            "analysis_version": risk_data.get("analysis_version", "V2"),
            "behavioral_threats": risk_data.get("behavioral_threats", []),
            "attack_chains": risk_data.get("attack_chains", [])
        }
        
        # Store report details in memory for session
        ACTIVE_REPORTS[session_id] = {
            "metadata": metadata,
            "risk": risk_data,
            "ai": ai_data,
            "pdf_path": pdf_path,
            "original_filename": file.filename,
            "analysis_version": risk_data.get("analysis_version", "V2"),
            "behavioral_threats": risk_data.get("behavioral_threats", []),
            "attack_chains": risk_data.get("attack_chains", [])
        }
        
        return response_data
        
    except Exception as e:
        logger.error(f"Error analyzing uploaded APK: {e}")
        err_msg = str(e)
        if "MANIFEST_PARSE_FAILED" in err_msg:
            raise HTTPException(status_code=400, detail="MANIFEST_PARSE_FAILED")
        elif "CERTIFICATE_UNKNOWN" in err_msg:
            raise HTTPException(status_code=400, detail="CERTIFICATE_UNKNOWN")
        elif "DEX_SCAN_FAILED" in err_msg:
            raise HTTPException(status_code=400, detail="DEX_SCAN_FAILED")
        elif "ANALYSIS_ERROR" in err_msg:
            raise HTTPException(status_code=400, detail="ANALYSIS_ERROR")
        raise HTTPException(status_code=500, detail=f"APK Analysis Failed: {err_msg}")
    finally:
        # Clean up uploaded APK
        if os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except Exception as clean_err:
                logger.warning(f"Failed to remove temp file {temp_path}: {clean_err}")

@app.get("/api/report/download/{session_id}")
async def download_report(session_id: str):
    """
    Serves the generated PDF report.
    """
    # Check session
    if session_id in ACTIVE_REPORTS:
        pdf_path = ACTIVE_REPORTS[session_id]["pdf_path"]
        app_name = ACTIVE_REPORTS[session_id]["metadata"]["app_name"]
        
        # Get original filename from session metadata (defaulting if not present)
        orig_filename = ACTIVE_REPORTS[session_id].get("original_filename", "uploaded_app.apk")
        if orig_filename.lower().endswith(".apk"):
            orig_filename = orig_filename[:-4]
            
        safe_name = "".join(c for c in app_name if c.isalnum() or c in (" ", "_", "-")).strip().replace(" ", "_")
        safe_orig = "".join(c for c in orig_filename if c.isalnum() or c in (" ", "_", "-")).strip().replace(" ", "_")
        
        filename = f"SentinelAPK_Report_{safe_name}_{safe_orig}.pdf"
        return FileResponse(pdf_path, media_type="application/pdf", filename=filename)
        
    # Check if we are downloading a pre-generated sample report
    if session_id in SAMPLES:
        sample = SAMPLES[session_id]
        pdf_path = os.path.join(REPORT_DIR, f"sample_{session_id}.pdf")
        
        # Generate on-the-fly if it doesn't exist
        if not os.path.exists(pdf_path):
            ReportGenerator.generate_pdf(sample["metadata"], sample["risk"], sample["ai"], pdf_path)
            
        filename = f"SentinelAPK_Report_{session_id.capitalize()}.pdf"
        return FileResponse(pdf_path, media_type="application/pdf", filename=filename)
        
    raise HTTPException(status_code=404, detail="Analysis report not found.")

@app.get("/api/samples")
async def list_samples() -> List[Dict[str, str]]:
    """
    Lists available preloaded sample analyses for quick demo selection, 
    or dynamically shows user uploaded apps once available.
    """
    if not ACTIVE_REPORTS:
        return [
            {"id": "anubis", "name": "Anubis Banking Trojan", "verdict": "MALICIOUS", "score": "85"},
            {"id": "cerberus", "name": "Cerberus SMS Stealer", "verdict": "MALICIOUS", "score": "75"},
            {"id": "safe_wallet", "name": "Secure Wallet App (Benign)", "verdict": "SAFE", "score": "5"}
        ]
    
    # If the user has uploaded apps, show those instead.
    uploaded_samples = []
    for session_id, report in ACTIVE_REPORTS.items():
        score = str(report.get("risk", {}).get("score", 0))
        verdict = report.get("risk", {}).get("verdict", "UNKNOWN")
        app_name = report.get("metadata", {}).get("app_name", "Unknown")
        orig_filename = report.get("original_filename", "uploaded_app.apk")
        
        # Use app name if available, otherwise fallback to filename
        name_to_show = app_name if app_name and app_name != "Unknown" else orig_filename
        
        uploaded_samples.append({
            "id": session_id,
            "name": name_to_show,
            "verdict": verdict,
            "score": score
        })
        
    # Return newest first
    return list(reversed(uploaded_samples))

@app.get("/api/samples/{sample_id}")
async def get_sample(sample_id: str):
    """
    Fetches mock analysis data for a preloaded demo app, or dynamically fetches uploaded app data.
    """
    if sample_id in SAMPLES:
        return SAMPLES[sample_id]
    if sample_id in ACTIVE_REPORTS:
        return ACTIVE_REPORTS[sample_id]
    raise HTTPException(status_code=404, detail="Sample not found")

class RedTeamRequest(BaseModel):
    app_name: str
    package_name: str
    permissions: List[str]
    risk_score: int
    verdict: str

@app.post("/api/redteam/mutate")
async def mutate_app(req: RedTeamRequest):
    """
    Dual-Agent Execution Pipeline:
    1. Analyst Initial Assessment
    2. Evader Strategy Generation
    3. Memory Store Update & Retrieval
    4. Analyst Re-Evaluation
    """
    metadata = {
        "app_name": req.app_name,
        "package_name": req.package_name,
        "permissions": req.permissions
    }
    
    # 1. Analyst Initial Assessment
    analyst_initial = llm_client.generate_initial_verdict(metadata, req.risk_score)
    
    # 2. Evader Mutation Strategy Generation
    evader_response = evader_agent.generate_evasive_variant(metadata, analyst_initial)
    
    # 3. Persistent Memory Update
    mutation_name = evader_response.get("mutation_name", "Adversarial Variant")
    evasion_strategy = evader_response.get("evasion_strategy", "")
    difficulty_score = evader_response.get("difficulty_score", 50)
    
    # Deduce pattern key/lesson
    permissions = req.permissions
    has_sms = any("SMS" in p.upper() for p in permissions)
    has_accessibility = any("ACCESSIBILITY" in p.upper() for p in permissions)
    
    pattern = "READ_SMS + Dynamic Loading" if has_sms else ("Accessibility + Obfuscated Network" if has_accessibility else "Overlay + Banking UI")
    
    memory_store.append_lesson(
        pattern=pattern,
        lesson=f"[{mutation_name}] {evasion_strategy}",
        difficulty=difficulty_score
    )
    lessons = memory_store.load_memory()
    
    # 4. Analyst Re-Evaluation
    analyst_re_evaluation = llm_client.generate_re_evaluation(metadata, evader_response, lessons)
    
    # Format to match frontend state keys
    return {
        "mutation": {
            "mutation": mutation_name,
            "reason": evasion_strategy,
            "difficulty": "Critical" if difficulty_score >= 80 else ("High" if difficulty_score >= 60 else "Medium"),
            "difficulty_score": difficulty_score
        },
        "initial_detection": {
            "verdict": analyst_initial.get("verdict", req.verdict),
            "confidence": analyst_initial.get("confidence", 41)
        },
        "memory_update": {
            "pattern": pattern,
            "learned": True
        },
        "re_evaluation": {
            "verdict": analyst_re_evaluation.get("verdict", "MALICIOUS"),
            "confidence": analyst_re_evaluation.get("confidence", 89)
        }
    }

@app.get("/api/system/llm-status")
async def get_llm_status():
    """
    Returns the current configuration status of the pluggable LLM system.
    """
    if llm_client.mode == "GROQ" and llm_client.healthy:
        return {
            "provider": "groq",
            "model": llm_client.model,
            "mode": "GROQ",
            "healthy": True
        }
    else:
        return {
            "provider": "fallback",
            "mode": "FALLBACK",
            "healthy": False
        }

@app.get("/api/redteam/lessons")
async def get_lessons():
    """
    Retrieves the persistent memory data store for frontend rendering.
    """
    return memory_store.load_memory()

@app.get("/api/learning/status")
async def get_learning_status():
    from adaptive_learning import AdaptiveRiskCalibrationEngine
    engine = AdaptiveRiskCalibrationEngine()
    return engine.load_weights()

@app.get("/api/learning/history")
async def get_learning_history():
    history_file = os.path.join(os.path.dirname(__file__), "data", "learning_history.json")
    if os.path.exists(history_file):
        with open(history_file, "r", encoding="utf-8") as f:
            return json.load(f)
    return []

@app.get("/api/learning/explanations")
async def get_learning_explanations():
    explanations_file = os.path.join(os.path.dirname(__file__), "data", "learning_explanations.json")
    if os.path.exists(explanations_file):
        with open(explanations_file, "r", encoding="utf-8") as f:
            return json.load(f)
    return []

@app.get("/api/learning/effectiveness")
async def get_learning_effectiveness():
    effectiveness_file = os.path.join(os.path.dirname(__file__), "data", "effectiveness_report.json")
    if os.path.exists(effectiveness_file):
        with open(effectiveness_file, "r", encoding="utf-8") as f:
            return json.load(f)
    return {
        "success": False,
        "before": {"accuracy": 0.0, "recall": 0.0, "f1_score": 0.0, "confusion_matrix": {"tp": 0, "fp": 0, "tn": 0, "fn": 0}},
        "after": {"accuracy": 0.0, "recall": 0.0, "f1_score": 0.0, "confusion_matrix": {"tp": 0, "fp": 0, "tn": 0, "fn": 0}}
    }

@app.post("/api/benchmark/run")
async def run_benchmark():
    from benchmark import BenchmarkEngine
    engine = BenchmarkEngine()
    return engine.run_benchmark()

@app.get("/api/benchmark/run/{run_id}")
async def get_benchmark_run(run_id: str):
    run_file = os.path.join(os.path.dirname(__file__), "data", "runs", f"{run_id}.json")
    if os.path.exists(run_file):
        with open(run_file, "r", encoding="utf-8") as f:
            return json.load(f)
    raise HTTPException(status_code=404, detail=f"Benchmark run {run_id} not found.")

@app.get("/api/benchmark/history")
async def get_benchmark_history():
    history_file = os.path.join(os.path.dirname(__file__), "data", "benchmark_history.json")
    if os.path.exists(history_file):
        with open(history_file, "r", encoding="utf-8") as f:
            return json.load(f)
    return []

@app.get("/api/reality-check")
async def get_reality_check():
    return {
        "implemented": [
            "APK parsing",
            "DEX analysis",
            "Permission analysis",
            "Certificate validation",
            "Clone detection",
            "Adaptive calibration"
        ],
        "research_or_future_work": [
            "Dynamic sandbox execution",
            "Runtime behavioral analysis",
            "Autonomous LLM learning",
            "Adversarial malware generation"
        ]
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
