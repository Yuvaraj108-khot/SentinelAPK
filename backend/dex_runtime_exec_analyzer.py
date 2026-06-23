import json
import sys
import os

try:
    from androguard.misc import AnalyzeAPK
except ImportError as e:
    print(json.dumps({"error": f"Failed to import androguard: {str(e)}"}))
    sys.exit(1)

def run_analysis(apk_path):
    try:
        # Load the APK and create the cross-reference graphs
        a, d, dx = AnalyzeAPK(apk_path)
        
        runtime_exec_calls = []
        
        # Search all methods in the Analysis object to find Runtime.exec
        for method in dx.get_methods():
            m = method.get_method()
            if m.get_class_name() == 'Ljava/lang/Runtime;' and m.get_name() == 'exec':
                
                # We found the target API. Now extract cross references (XREF FROM)
                for path in method.get_xref_from():
                    caller_method = path[1]
                    offset = path[2]
                    
                    runtime_exec_calls.append({
                        "caller_class": str(caller_method.get_method().get_class_name()),
                        "caller_method": str(caller_method.get_method().get_name()),
                        "callee_method": "Runtime.exec",
                        "offset": offset,
                        "confidence": 1.0
                    })
                    
        return {
            "runtime_exec_calls": runtime_exec_calls
        }
        
    except Exception as e:
        return {"error": str(e)}

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python dex_runtime_exec_analyzer.py <path_to_apk>")
        sys.exit(1)
        
    apk_path = sys.argv[1]
    results = run_analysis(apk_path)
    print(json.dumps(results, indent=4))
