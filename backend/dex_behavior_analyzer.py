import os
import zipfile
import logging
from typing import Dict, Any, List
import json

try:
    from loguru import logger as loguru_logger
    loguru_logger.remove()
except Exception:
    pass

try:
    from androguard.misc import AnalyzeAPK
except ImportError:
    pass

logger = logging.getLogger("sentinel.dex_analyzer")

class DexBehaviorAnalyzer:
    """
    V2.5 Unified Structural Evidence Engine
    Uses Androguard Dalvik Cross-Reference (XREF) mapping for small samples,
    and high-performance direct Dalvik scanning for larger / multi-DEX APKs.
    """
    
    def __init__(self, apk_path: str):
        self.apk_path = apk_path
        
    def analyze(self) -> Dict[str, Any]:
        if not os.path.exists(self.apk_path):
            return {"evidence": {}, "chains": []}

        file_size = os.path.getsize(self.apk_path)
        dex_count = 0
        try:
            with zipfile.ZipFile(self.apk_path, "r") as zf:
                dex_count = sum(1 for n in zf.namelist() if n.endswith(".dex"))
        except Exception:
            pass

        # If large (> 1.5MB) or multi-dex (> 1 dex), AnalyzeAPK takes minutes to hours in pure Python.
        # Use high-performance bytecode scanning engine (executes in < 0.5s) to prevent blocking the platform.
        if file_size > 1.5 * 1024 * 1024 or dex_count > 1:
            return self._analyze_fast()

        # For small single-dex APKs (benchmarks / POC tests), run full Dalvik XREF analysis with safety timeout
        try:
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(self._analyze_androguard)
                return future.result(timeout=2.0)
        except Exception as e:
            logger.info(f"Androguard structural analysis timed out or failed ({e}), using fast scan fallback.")
            return self._analyze_fast()

    def _analyze_fast(self) -> Dict[str, Any]:
        """
        High-performance bytecode scanner that evaluates DEX bytecode structures
        directly from ZIP archives without full method basic block decompilation.
        """
        results = {
            "evidence": {},
            "chains": []
        }
        has_reflection = False
        has_webview = False
        has_sms = False
        has_exec = False
        has_net = False
        
        try:
            with zipfile.ZipFile(self.apk_path, "r") as zf:
                for name in zf.namelist():
                    if not name.endswith(".dex"):
                        continue
                    data = zf.read(name)
                    
                    if b"javascript:" in data:
                        results["evidence"][f"webview_js_{name}"] = {
                            "evidence_type": "WEBVIEW_INJECTION",
                            "caller_class": "DexBytecode",
                            "caller_method": "javascript:",
                            "api": "javascript: protocol",
                            "confidence": 0.95
                        }
                        has_webview = True

                    if b"content://sms" in data:
                        results["evidence"][f"sms_content_{name}"] = {
                            "evidence_type": "SMS_ACCESS",
                            "caller_class": "DexBytecode",
                            "caller_method": "content://sms",
                            "api": "content://sms",
                            "confidence": 0.95
                        }
                        has_sms = True

                    if b"Ljava/lang/Runtime;->exec" in data or b"Runtime;->exec" in data:
                        results["evidence"][f"Runtime_Exec_{name}"] = {
                            "evidence_type": "RUNTIME_EXECUTION",
                            "caller_class": "Ljava/lang/Runtime;",
                            "caller_method": "exec",
                            "api": "Ljava/lang/Runtime;->exec",
                            "confidence": 1.0
                        }
                        has_exec = True

                    if b"Ldalvik/system/DexClassLoader;" in data or b"Ldalvik/system/PathClassLoader;" in data:
                        results["evidence"][f"DexClassLoader_{name}"] = {
                            "evidence_type": "DYNAMIC_LOADING",
                            "caller_class": "Ldalvik/system/DexClassLoader;",
                            "caller_method": "<init>",
                            "api": "Ldalvik/system/DexClassLoader;-><init>",
                            "confidence": 1.0
                        }
                        has_exec = True

                    if any(p in data for p in [b"performGlobalAction", b"dispatchGesture", b"findAccessibilityNodeInfosByText", b"getRootInActiveWindow", b"onAccessibilityEvent"]):
                        results["evidence"][f"Accessibility_{name}"] = {
                            "evidence_type": "ACCESSIBILITY_ABUSE",
                            "caller_class": "Landroid/accessibilityservice/AccessibilityService;",
                            "caller_method": "performGlobalAction",
                            "api": "AccessibilityService API",
                            "confidence": 1.0
                        }

                    if any(p in data for p in [b"Ljava/lang/Class;->forName", b"Ljava/lang/reflect/Method;->invoke", b"loadClass"]):
                        results["evidence"][f"Reflection_{name}"] = {
                            "evidence_type": "REFLECTION",
                            "caller_class": "Ljava/lang/Class;",
                            "caller_method": "forName",
                            "api": "Ljava/lang/Class;->forName",
                            "confidence": 0.8
                        }
                        has_reflection = True

                    if any(p in data for p in [b"Landroid/telephony/SmsManager;", b"sendTextMessage", b"getLine1Number", b"createFromPdu"]):
                        results["evidence"][f"SMS_{name}"] = {
                            "evidence_type": "SMS_ACCESS",
                            "caller_class": "Landroid/telephony/SmsManager;",
                            "caller_method": "sendTextMessage",
                            "api": "Landroid/telephony/SmsManager;->sendTextMessage",
                            "confidence": 1.0
                        }
                        has_sms = True

                    if any(p in data for p in [b"Landroid/webkit/WebView;", b"loadUrl", b"evaluateJavascript", b"addJavascriptInterface"]):
                        results["evidence"][f"WebView_{name}"] = {
                            "evidence_type": "WEBVIEW_USAGE",
                            "caller_class": "Landroid/webkit/WebView;",
                            "caller_method": "loadUrl",
                            "api": "Landroid/webkit/WebView;->loadUrl",
                            "confidence": 0.9
                        }
                        has_webview = True

                    if any(p in data for p in [b"okhttp", b"HttpURLConnection", b"HttpClient"]):
                        has_net = True
        except Exception as e:
            logger.warning(f"Fast DEX analysis encountered error: {e}")

        # Correlation Chains
        if has_reflection and has_exec:
            results["chains"].append({
                "chain_type": "REFLECTION_TO_EXECUTION",
                "caller": "Reflection",
                "chain": ["Reflection", "Execution"],
                "confidence": 0.95
            })
        if has_webview and has_exec:
            results["chains"].append({
                "chain_type": "WEBVIEW_TO_EXECUTION",
                "caller": "WebView",
                "chain": ["WebView", "Execution"],
                "confidence": 0.95
            })
        if has_sms and has_net:
            results["chains"].append({
                "chain_type": "SMS_TO_EXFILTRATION",
                "caller": "SMS",
                "chain": ["SMS", "Network Exfiltration"],
                "confidence": 0.95
            })

        return results

    def _analyze_androguard(self) -> Dict[str, Any]:
        results = {
            "evidence": {},
            "chains": []
        }
        
        try:
            a, d, dx = AnalyzeAPK(self.apk_path)
        except Exception as e:
            logger.error(f"Androguard structural analysis failed: {e}")
            return results

        callers_of_reflection = {}
        callers_of_webview = {}
        callers_of_sms = {}
        
        for string_val, xrefs in dx.get_strings().items():
            val = string_val.get_value().lower()
            
            if "javascript:" in val:
                for path in xrefs:
                    caller_class = path[0].get_class_name()
                    caller_method = path[1].get_name()
                    caller_str = f"{caller_class}->{caller_method}"
                    
                    results["evidence"][f"webview_js_{caller_str}"] = {
                        "evidence_type": "WEBVIEW_INJECTION",
                        "caller_class": str(caller_class),
                        "caller_method": str(caller_method),
                        "api": "javascript: protocol",
                        "confidence": 0.95
                    }
                    if caller_str not in callers_of_webview:
                        callers_of_webview[caller_str] = {"apis": set(), "analysis": path[1]}
                    callers_of_webview[caller_str]["apis"].add("javascript:")
                    
            if "content://sms" in val:
                for path in xrefs:
                    caller_class = path[0].get_class_name()
                    caller_method = path[1].get_name()
                    caller_str = f"{caller_class}->{caller_method}"
                    
                    results["evidence"][f"sms_content_{caller_str}"] = {
                        "evidence_type": "SMS_ACCESS",
                        "caller_class": str(caller_class),
                        "caller_method": str(caller_method),
                        "api": "content://sms",
                        "confidence": 0.95
                    }
                    if caller_str not in callers_of_sms:
                        callers_of_sms[caller_str] = {"apis": set(), "analysis": path[1]}
                    callers_of_sms[caller_str]["apis"].add("content://sms")

        targets = {
            "Runtime_Exec": {"Ljava/lang/Runtime;": ["exec"]},
            "DexClassLoader": {
                "Ldalvik/system/DexClassLoader;": ["<init>"],
                "Ldalvik/system/PathClassLoader;": ["<init>"]
            },
            "Accessibility": {"*": ["performGlobalAction", "dispatchGesture", "findAccessibilityNodeInfosByText", "getRootInActiveWindow"]},
            "Reflection": {
                "Ljava/lang/Class;": ["forName"],
                "Ljava/lang/reflect/Method;": ["invoke"],
                "Ljava/lang/ClassLoader;": ["loadClass"]
            },
            "SMS": {
                "Landroid/telephony/SmsManager;": ["sendTextMessage", "getDefault"],
                "Landroid/telephony/TelephonyManager;": ["getLine1Number"],
                "Landroid/telephony/SmsMessage;": ["createFromPdu"]
            },
            "WebView": {
                "Landroid/webkit/WebView;": ["loadUrl", "evaluateJavascript", "addJavascriptInterface"]
            }
        }
        
        for method in dx.get_methods():
            m = method.get_method()
            class_name = m.get_class_name()
            method_name = m.get_name()
            
            is_accessibility = False
            if 'Accessibility' in class_name and method_name in targets["Accessibility"]["*"]:
                is_accessibility = True
                
            match_category = None
            
            for category, class_dict in targets.items():
                if category == "Accessibility" and is_accessibility:
                    match_category = "Accessibility"
                    break
                elif class_name in class_dict and method_name in class_dict[class_name]:
                    match_category = category
                    break
                    
            if match_category:
                for path in method.get_xref_from():
                    caller_analysis = path[1]
                    caller_m = caller_analysis.get_method()
                    caller_str = f"{caller_m.get_class_name()}->{caller_m.get_name()}"
                    
                    evidence_key = f"{match_category}_{caller_str}"
                    
                    if match_category == "Runtime_Exec":
                        results["evidence"][evidence_key] = {
                            "evidence_type": "RUNTIME_EXECUTION",
                            "caller_class": str(caller_m.get_class_name()),
                            "caller_method": str(caller_m.get_name()),
                            "api": f"{class_name}->{method_name}",
                            "confidence": 1.0
                        }
                    elif match_category == "DexClassLoader":
                        results["evidence"][evidence_key] = {
                            "evidence_type": "DYNAMIC_LOADING",
                            "caller_class": str(caller_m.get_class_name()),
                            "caller_method": str(caller_m.get_name()),
                            "api": f"{class_name}->{method_name}",
                            "confidence": 1.0
                        }
                    elif match_category == "Accessibility":
                        results["evidence"][evidence_key] = {
                            "evidence_type": "ACCESSIBILITY_ABUSE",
                            "caller_class": str(caller_m.get_class_name()),
                            "caller_method": str(caller_m.get_name()),
                            "api": f"{class_name}->{method_name}",
                            "confidence": 1.0
                        }
                    elif match_category == "Reflection":
                        results["evidence"][evidence_key] = {
                            "evidence_type": "REFLECTION",
                            "caller_class": str(caller_m.get_class_name()),
                            "caller_method": str(caller_m.get_name()),
                            "api": f"{class_name}->{method_name}",
                            "confidence": 0.8
                        }
                        if caller_str not in callers_of_reflection:
                            callers_of_reflection[caller_str] = {"apis": set(), "analysis": caller_analysis}
                        callers_of_reflection[caller_str]["apis"].add(f"{class_name}->{method_name}")
                        
                    elif match_category == "SMS":
                        results["evidence"][evidence_key] = {
                            "evidence_type": "SMS_ACCESS",
                            "caller_class": str(caller_m.get_class_name()),
                            "caller_method": str(caller_m.get_name()),
                            "api": f"{class_name}->{method_name}",
                            "confidence": 1.0
                        }
                        if caller_str not in callers_of_sms:
                            callers_of_sms[caller_str] = {"apis": set(), "analysis": caller_analysis}
                        callers_of_sms[caller_str]["apis"].add(f"{class_name}->{method_name}")
                        
                    elif match_category == "WebView":
                        results["evidence"][evidence_key] = {
                            "evidence_type": "WEBVIEW_USAGE",
                            "caller_class": str(caller_m.get_class_name()),
                            "caller_method": str(caller_m.get_name()),
                            "api": f"{class_name}->{method_name}",
                            "confidence": 0.9
                        }
                        if caller_str not in callers_of_webview:
                            callers_of_webview[caller_str] = {"apis": set(), "analysis": caller_analysis}
                        callers_of_webview[caller_str]["apis"].add(f"{class_name}->{method_name}")

        dangerous_targets = [
            "Ljava/lang/Runtime;->exec",
            "Ldalvik/system/DexClassLoader;-><init>",
            "Ldalvik/system/PathClassLoader;-><init>",
            "Landroid/accessibilityservice/AccessibilityService;->performGlobalAction",
            "Ljava/net/HttpURLConnection;->connect",
            "Ljava/net/HttpURLConnection;->getOutputStream",
            "Lokhttp3/OkHttpClient;->newCall"
        ]

        def check_correlation(caller_dict, chain_name):
            for caller_str, data in caller_dict.items():
                caller_analysis = data["analysis"]
                apis_called = data["apis"]
                
                called_dangerous = []
                try:
                    for path in caller_analysis.get_xref_to():
                        callee_m = path[1].get_method()
                        callee_str = f"{callee_m.get_class_name()}->{callee_m.get_name()}"
                        if callee_str in dangerous_targets:
                            called_dangerous.append(callee_str)
                except AttributeError:
                    pass
                    
                if called_dangerous:
                    chain = list(apis_called) + called_dangerous
                    results["chains"].append({
                        "chain_type": chain_name,
                        "caller": caller_str,
                        "chain": chain,
                        "confidence": 0.95
                    })

        check_correlation(callers_of_reflection, "REFLECTION_TO_EXECUTION")
        check_correlation(callers_of_webview, "WEBVIEW_TO_EXECUTION")
        check_correlation(callers_of_sms, "SMS_TO_EXFILTRATION")
            
        return results
