import logging
from typing import Dict, Any, List
import json

try:
    from androguard.misc import AnalyzeAPK
except ImportError as e:
    pass

logger = logging.getLogger("sentinel.dex_analyzer")

class DexBehaviorAnalyzer:
    """
    V2.5 Unified Structural Evidence Engine
    Uses Androguard Dalvik Cross-Reference (XREF) mapping to establish concrete call chains.
    """
    
    def __init__(self, apk_path: str):
        self.apk_path = apk_path
        
    def analyze(self) -> Dict[str, Any]:
        results = {
            "evidence": {},
            "chains": []
        }
        
        try:
            a, d, dx = AnalyzeAPK(self.apk_path)
        except Exception as e:
            logger.error(f"Androguard structural analysis failed: {e}")
            return results

        # State trackers for correlation
        callers_of_reflection = {}
        callers_of_webview = {}
        callers_of_sms = {}
        
        # 1. String Based XREFS (SMS & WebView)
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

        # Target API Dictionary
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
        
        # 2. Method Invocation Analysis
        for method in dx.get_methods():
            m = method.get_method()
            class_name = m.get_class_name()
            method_name = m.get_name()
            
            # Accessibility wildcard match
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

        # 3. Correlation Engine (XREF_TO bridging)
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
