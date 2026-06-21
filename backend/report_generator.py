import os
from datetime import datetime
from typing import Dict, Any
from jinja2 import Template
from fpdf import FPDF

# HTML Template for SentinelAPK Report
HTML_REPORT_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>SentinelAPK Security Report - {{ metadata.app_name }}</title>
    <style>
        body { font-family: 'Segoe UI', Arial, sans-serif; background-color: #0d1117; color: #c9d1d9; margin: 0; padding: 40px; }
        .container { max-width: 900px; margin: 0 auto; background: #161b22; padding: 30px; border-radius: 12px; border: 1px solid #30363d; box-shadow: 0 8px 32px rgba(0,0,0,0.4); }
        .header { display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid #30363d; padding-bottom: 20px; }
        .title { color: #f0f6fc; margin: 0; font-size: 28px; font-weight: 700; }
        .subtitle { color: #8b949e; font-size: 14px; margin-top: 5px; }
        .badge { padding: 8px 16px; border-radius: 20px; font-weight: bold; text-transform: uppercase; font-size: 14px; }
        .badge-MALICIOUS { background-color: #f85149; color: #fff; }
        .badge-SUSPICIOUS { background-color: #d29922; color: #fff; }
        .badge-SAFE { background-color: #2ea043; color: #fff; }
        
        .section { margin-top: 30px; border-top: 1px solid #21262d; padding-top: 20px; }
        .section-title { color: #58a6ff; font-size: 20px; margin-bottom: 15px; }
        
        .metadata-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 15px; }
        .metadata-item { background: #0d1117; padding: 12px; border-radius: 6px; border: 1px solid #21262d; }
        .metadata-label { color: #8b949e; font-size: 12px; text-transform: uppercase; }
        .metadata-value { color: #c9d1d9; font-size: 15px; font-weight: 500; margin-top: 4px; word-break: break-all; }
        
        .verdict-card { display: flex; background: #21262d; padding: 20px; border-radius: 8px; border-left: 5px solid; align-items: center; margin-top: 20px; }
        .verdict-card-MALICIOUS { border-left-color: #f85149; }
        .verdict-card-SUSPICIOUS { border-left-color: #d29922; }
        .verdict-card-SAFE { border-left-color: #2ea043; }
        .verdict-score { font-size: 36px; font-weight: 800; margin-right: 20px; }
        
        .reasons-list { margin: 10px 0 0 0; padding-left: 20px; }
        .reasons-list li { margin-bottom: 6px; }
        
        .perm-table { width: 100%; border-collapse: collapse; margin-top: 10px; }
        .perm-table th, .perm-table td { padding: 10px; text-align: left; border-bottom: 1px solid #21262d; }
        .perm-table th { color: #8b949e; font-weight: 600; }
        .danger-weight { font-weight: bold; color: #f85149; }
        
        .ai-card { background: #1f242c; border: 1px dashed #388bfd; padding: 20px; border-radius: 8px; line-height: 1.6; }
        .ai-paragraph { margin-bottom: 15px; }
        .ai-paragraph strong { color: #58a6ff; }
        
        .footer { text-align: center; color: #8b949e; font-size: 12px; margin-top: 40px; border-top: 1px solid #21262d; padding-top: 20px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <h1 class="title">SentinelAPK Investigation Report</h1>
                <div class="subtitle">Explainable AI Threat Intelligence for Android Banking Applications</div>
            </div>
            <span class="badge badge-{{ risk.verdict }}">{{ risk.verdict }}</span>
        </div>
        
        <div class="verdict-card verdict-card-{{ risk.verdict }}">
            <div class="verdict-score">
                {{ risk.score }}/100
                <div style="font-size: 12px; color: #8b949e; text-align: center; margin-top: 5px;">Confidence: {{ risk.confidence }}%</div>
            </div>
            <div>
                <strong style="font-size: 18px; color: #f0f6fc;">Executive Verdict: {{ risk.verdict }}</strong>
                <ul class="reasons-list">
                    {% for reason in risk.top_reasons %}
                        <li>{{ reason }}</li>
                    {% endfor %}
                </ul>
            </div>
        </div>

        <div class="section">
            <div class="section-title">APK Metadata</div>
            <div class="metadata-grid">
                <div class="metadata-item">
                    <div class="metadata-label">Application Name</div>
                    <div class="metadata-value">{{ metadata.app_name }}</div>
                </div>
                <div class="metadata-item">
                    <div class="metadata-label">Package Name</div>
                    <div class="metadata-value">{{ metadata.package_name }}</div>
                </div>
                <div class="metadata-item">
                    <div class="metadata-label">Version</div>
                    <div class="metadata-value">{{ metadata.version_name }} (Code: {{ metadata.version_code }})</div>
                </div>
                <div class="metadata-item">
                    <div class="metadata-label">Target SDK / Min SDK</div>
                    <div class="metadata-value">SDK {{ metadata.target_sdk }} (Min: {{ metadata.min_sdk }})</div>
                </div>
            </div>
        </div>

        <div class="section">
            <div class="section-title">AI Intent Analysis</div>
            <div class="ai-card">
                <div class="ai-paragraph">
                    <strong>Suspicious Permissions Rationale:</strong><br>
                    {{ ai.suspicious_permissions_rationale }}
                </div>
                <div class="ai-paragraph">
                    <strong>OTP Interception Capability:</strong><br>
                    {{ ai.otp_theft_capability }}
                </div>
                <div class="ai-paragraph">
                    <strong>Accessibility Abuse Risk:</strong><br>
                    {{ ai.accessibility_abuse }}
                </div>
                <div class="ai-paragraph">
                    <strong>Impersonation & Overlay Attack Potential:</strong><br>
                    {{ ai.impersonation_risk }}
                </div>
                <div class="ai-paragraph">
                    <strong>Data Exfiltration Paths:</strong><br>
                    {{ ai.data_exfiltration }}
                </div>
                <div class="ai-paragraph">
                    <strong>Verdict Rationale & Logic:</strong><br>
                    {{ ai.verdict_reasoning }}
                </div>
            </div>
        </div>

        <div class="section">
            <div class="section-title">Permission Risk Assessment</div>
            <table class="perm-table">
                <thead>
                    <tr>
                        <th>Permission</th>
                        <th>Risk Contribution</th>
                        <th>Mitre Technique Mapping</th>
                    </tr>
                </thead>
                <tbody>
                    {% for rule in risk.triggered_rules %}
                        <tr>
                            <td><code>{{ rule.permission }}</code></td>
                            <td class="danger-weight">+{{ rule.weight }}</td>
                            <td>
                                {% set found = false %}
                                {% for tech in risk.mitre_techniques %}
                                    {% if loop.index0 == loop.index0 %}
                                        {# Simplifying mapping lookup #}
                                    {% endif %}
                                {% endfor %}
                                Triggered Dangerous Rule
                            </td>
                        </tr>
                    {% else %}
                        <tr>
                            <td colspan="3" style="text-align: center; color: #8b949e;">No dangerous permissions requested.</td>
                        </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>

        <div class="section">
            <div class="section-title">Security Recommendation</div>
            <div style="background: #161b22; padding: 15px; border-radius: 6px; border: 1px solid #30363d;">
                <strong>Recommended Action:</strong>
                {% if risk.verdict == "MALICIOUS" %}
                    <span style="color:#f85149; font-weight:bold;">BLOCK (Critical Alert)</span>
                    <p style="margin-top: 8px;">Do not install this application. It exhibits patterns characteristic of financial Trojans, SMS OTP stealers, or overlay collectors.</p>
                {% elif risk.verdict == "SUSPICIOUS" %}
                    <span style="color:#d29922; font-weight:bold;">REVIEW (Manual Inspection Required)</span>
                    <p style="margin-top: 8px;">The app exhibits highly privileged permissions. Verify target URLs and certificate signing authenticity before deployment.</p>
                {% else %}
                    <span style="color:#2ea043; font-weight:bold;">ALLOW (Low Risk Profile)</span>
                    <p style="margin-top: 8px;">Standard risk metrics satisfied. The application does not exhibit banking fraud characteristics in static inspection.</p>
                {% endif %}
            </div>
        </div>

        <div class="footer">
            Report generated by SentinelAPK on {{ timestamp }}<br>
            SentinelAPK &bull; Hackathon MVP Threat Intelligence
        </div>
    </div>
</body>
</html>
"""

class PDFReportGenerator(FPDF):
    def __init__(self, metadata: Dict[str, Any], risk_data: Dict[str, Any], ai_data: Dict[str, Any]):
        super().__init__()
        self.metadata = metadata
        self.risk = risk_data
        self.ai = ai_data
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def header(self):
        # Header banner
        self.set_fill_color(13, 17, 23)
        self.rect(0, 0, 210, 35, "F")
        self.set_text_color(240, 246, 252)
        
        self.set_font("Helvetica", "B", 18)
        self.set_y(8)
        self.cell(0, 8, "SENTINELAPK SECURITY REPORT", ln=True, align="L")
        
        self.set_font("Helvetica", "I", 9)
        self.set_text_color(139, 148, 158)
        self.cell(0, 6, "Explainable AI Threat Intelligence for Android Banking Applications", ln=True, align="L")
        
        self.set_y(38)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(139, 148, 158)
        self.cell(0, 10, f"Generated on {self.timestamp} | SentinelAPK Threat Intel System", align="L")
        self.cell(0, 10, f"Page {self.page_no()}", align="R")

    def add_verdict_summary(self):
        self.ln(5)
        
        # Draw colored verdict background card
        verdict = self.risk["verdict"]
        if verdict == "MALICIOUS":
            self.set_fill_color(248, 81, 73)  # Red
            self.set_text_color(255, 255, 255)
        elif verdict == "SUSPICIOUS":
            self.set_fill_color(210, 153, 34)  # Yellow
            self.set_text_color(255, 255, 255)
        else:
            self.set_fill_color(46, 160, 67)  # Green
            self.set_text_color(255, 255, 255)
            
        self.cell(0, 12, f"  EXECUTIVE VERDICT: {verdict}", ln=True, fill=True, align="L")
        
        self.set_text_color(33, 37, 41)
        self.set_fill_color(240, 240, 240)
        self.ln(2)
        self.set_font("Helvetica", "B", 10)
        self.cell(50, 8, "  Risk Score:", border="LTB", fill=True)
        self.set_font("Helvetica", "", 10)
        self.cell(0, 8, f"{self.risk['score']}/100  (Confidence: {self.risk['confidence']}%)", border="RTB", ln=True, fill=True)
        
        self.ln(3)
        self.set_font("Helvetica", "B", 11)
        self.set_text_color(56, 139, 253)
        self.cell(0, 6, "Primary Reasons Flagged:", ln=True)
        self.set_text_color(0, 0, 0)
        self.set_font("Helvetica", "", 9.5)
        
        for reason in self.risk["top_reasons"]:
            self.cell(0, 5, f" - {reason}", ln=True)
        self.ln(5)

    def add_metadata(self):
        self.set_font("Helvetica", "B", 12)
        self.set_text_color(56, 139, 253)
        self.cell(0, 8, "1. APK Metadata", ln=True)
        self.line(10, self.get_y(), 200, self.get_y())
        self.ln(2)
        
        self.set_font("Helvetica", "", 9.5)
        self.set_text_color(0, 0, 0)
        
        # Metadata Table
        grid = [
            ("App Name", self.metadata["app_name"]),
            ("Package Name", self.metadata["package_name"]),
            ("Version", f"{self.metadata['version_name']} (Code: {self.metadata['version_code']})"),
            ("SDK Support", f"Target SDK {self.metadata['target_sdk']} (Min SDK {self.metadata['min_sdk']})"),
            ("Activities Count", f"{len(self.metadata['activities'])} active screens"),
            ("Services Count", f"{len(self.metadata['services'])} background services"),
        ]
        
        for key, val in grid:
            self.set_font("Helvetica", "B", 9.5)
            self.cell(45, 6, f"  {key}:", border=1)
            self.set_font("Helvetica", "", 9.5)
            self.cell(0, 6, f"  {val}", border=1, ln=True)
            
        self.ln(6)

    def add_dex_indicators(self):
        evidence_val = self.risk.get("evidence_validation", {})
        if not evidence_val:
            return
            
        self.set_font("Helvetica", "B", 11)
        self.set_text_color(56, 139, 253)
        self.cell(0, 6, "  Evidence-Based Detection Status:", ln=True)
        self.set_font("Helvetica", "", 9.5)
        self.set_text_color(0, 0, 0)
        
        labels_map = {
            "sms": "SMS",
            "accessibility": "Accessibility",
            "overlay": "Overlay",
            "runtime_exec": "Runtime.exec",
            "dynamic_loading": "DexClassLoader",
            "clone_detection": "Clone Detection",
            "certificate_validation": "Certificate Validation"
        }
        
        for key, label in labels_map.items():
            info = evidence_val.get(key, {})
            status = info.get("status", "UNKNOWN")
            matched = info.get("matched_string", "N/A")
            val = f"{status} (Evidence: {matched})"
            
            self.set_font("Helvetica", "B", 9.5)
            self.cell(45, 6, f"    {label}:", border=1)
            self.set_font("Helvetica", "", 9.5)
            if status in ("FOUND", "UNTRUSTED", "UNSIGNED"):
                self.set_text_color(248, 81, 73)  # Red
            elif status == "TRUSTED":
                self.set_text_color(46, 160, 67)  # Green
            else:
                self.set_text_color(120, 120, 120)  # Gray
            self.cell(0, 6, f"  {val}", border=1, ln=True)
            self.set_text_color(0, 0, 0)
            
        self.ln(6)

    def add_ai_analysis(self):
        self.set_font("Helvetica", "B", 12)
        self.set_text_color(56, 139, 253)
        self.cell(0, 8, "2. Explainable AI Security Analysis", ln=True)
        self.line(10, self.get_y(), 200, self.get_y())
        self.ln(2)
        
        sections = [
            ("Suspicious Permissions Rationale", self.ai["suspicious_permissions_rationale"]),
            ("SMS OTP Interception Risk", self.ai["otp_theft_capability"]),
            ("Accessibility APIs Abuse Risk", self.ai["accessibility_abuse"]),
            ("Overlay / App Impersonation Risk", self.ai["impersonation_risk"]),
            ("Data Exfiltration Potential", self.ai["data_exfiltration"]),
            ("Analysis Verdict Logic", self.ai["verdict_reasoning"]),
        ]
        
        for title, content in sections:
            self.set_font("Helvetica", "B", 10)
            self.set_text_color(0, 0, 0)
            self.cell(0, 6, f"  {title}:", ln=True)
            self.set_font("Helvetica", "", 9.5)
            self.set_text_color(60, 60, 60)
            self.multi_cell(0, 5, content)
            self.ln(3)
            
        self.ln(3)

    def add_recommendations(self):
        self.set_font("Helvetica", "B", 12)
        self.set_text_color(56, 139, 253)
        self.cell(0, 8, "3. Recommended Actions & Mitigations", ln=True)
        self.line(10, self.get_y(), 200, self.get_y())
        self.ln(3)
        
        verdict = self.risk["verdict"]
        self.set_font("Helvetica", "B", 10.5)
        if verdict == "MALICIOUS":
            self.set_text_color(248, 81, 73)
            self.cell(0, 6, "Action Required: BLOCK & QUARANTINE", ln=True)
            self.set_text_color(0, 0, 0)
            self.set_font("Helvetica", "", 9.5)
            self.multi_cell(0, 5, "The application matches signature layouts of known Android banking overlays and SMS interceptors. Immediately block deployment. If installed, remove device from corporate networks and revoke any administrative/accessibility access details.")
        elif verdict == "SUSPICIOUS":
            self.set_text_color(210, 153, 34)
            self.cell(0, 6, "Action Required: MANUAL SECURITY REVIEW", ln=True)
            self.set_text_color(0, 0, 0)
            self.set_font("Helvetica", "", 9.5)
            self.multi_cell(0, 5, "Elevated permission scope detected without clear classification. Code audit is recommended. Inspect background receivers to ensure no third-party libraries load code dynamically or establish unsolicited sockets.")
        else:
            self.set_text_color(46, 160, 67)
            self.cell(0, 6, "Action Required: ALLOW & MONITOR", ln=True)
            self.set_text_color(0, 0, 0)
            self.set_font("Helvetica", "", 9.5)
            self.multi_cell(0, 5, "The application exhibits standard permission behavior and is safe for general sandbox deploy. Monitor normal lifecycle telemetry.")

class ReportGenerator:
    @staticmethod
    def generate_html(metadata: Dict[str, Any], risk: Dict[str, Any], ai: Dict[str, Any]) -> str:
        template = Template(HTML_REPORT_TEMPLATE)
        return template.render(
            metadata=metadata,
            risk=risk,
            ai=ai,
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        )

    @staticmethod
    def generate_pdf(metadata: Dict[str, Any], risk: Dict[str, Any], ai: Dict[str, Any], output_path: str) -> None:
        pdf = PDFReportGenerator(metadata, risk, ai)
        pdf.add_page()
        pdf.add_verdict_summary()
        pdf.add_metadata()
        pdf.add_dex_indicators()
        pdf.add_ai_analysis()
        pdf.add_page() # Keep recommendations on separate page or clean layout
        pdf.add_recommendations()
        pdf.output(output_path)
