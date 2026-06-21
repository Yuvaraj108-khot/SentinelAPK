import os
import json
import logging
from typing import Dict, Any
from openai import OpenAI

logger = logging.getLogger("sentinel.evader_agent")

class EvaderAgent:
    def __init__(self):
        self.api_key = os.getenv("OPENAI_API_KEY")
        self.api_base = os.getenv("OPENAI_API_BASE", "https://api.openai.com/v1")
        self.model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
        
        if self.api_key:
            self.client = OpenAI(api_key=self.api_key, base_url=self.api_base)
        else:
            self.client = None

    def generate_evasive_variant(self, metadata: Dict[str, Any], initial_verdict: Dict[str, Any]) -> Dict[str, Any]:
        """
        Queries the Evader LLM to generate a simulated APK mutation strategy to bypass the Analyst.
        Falls back to rule heuristics if API key is not present.
        """
        if not self.client:
            logger.info("Evader Agent: No LLM key found. Using heuristics.")
            return self._fallback_evasion(metadata, initial_verdict)
            
        system_prompt = (
            "You are an advanced Android malware developer and adversarial security researcher.\n"
            "Your objective is to review a security analyst's findings and devise an evasion mutation strategy.\n"
            "Analyze the analyst's verdict and the app's declared permissions.\n"
            "Produce an evasion mutation plan that hides these features using methods like reflection, dynamic code loading, or obfuscation.\n"
            "You MUST return valid JSON matching this format exactly:\n"
            "{\n"
            '  "mutation_name": "Name of the mutated evasion technique",\n'
            '  "evasion_strategy": "Explanation of how this strategy bypasses standard static detection.",\n'
            '  "analyst_weakness": "Detail of the static scanner weakness exploited.",\n'
            '  "difficulty_score": 0-100,\n'
            '  "expected_effectiveness": 0-100\n'
            "}"
        )
        
        user_content = (
            f"Original App Name: {metadata.get('app_name')}\n"
            f"Permissions: {', '.join(metadata.get('permissions', []))}\n"
            f"Analyst Verdict: {initial_verdict.get('verdict')}\n"
            f"Analyst Confidence: {initial_verdict.get('confidence')}%\n"
        )
        
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_content}
                ],
                response_format={"type": "json_object"},
                temperature=0.7
            )
            result_text = response.choices[0].message.content
            return json.loads(result_text)
        except Exception as e:
            logger.error(f"Error calling Evader LLM: {e}")
            return self._fallback_evasion(metadata, initial_verdict)

    def _fallback_evasion(self, metadata: Dict[str, Any], initial_verdict: Dict[str, Any]) -> Dict[str, Any]:
        permissions = metadata.get("permissions", [])
        has_sms = any("SMS" in p.upper() for p in permissions)
        has_accessibility = any("ACCESSIBILITY" in p.upper() for p in permissions)
        has_overlay = any("ALERT_WINDOW" in p.upper() for p in permissions)
        
        if has_sms and has_accessibility:
            return {
                "mutation_name": "Accessibility-driven SMS Snooper",
                "evasion_strategy": "Abuses accessibility window event callbacks to read SMS notifications dynamically, hiding standard SMS read/receive permissions.",
                "analyst_weakness": "Static manifest parsing fails to map accessibility actions to target SMS permissions.",
                "difficulty_score": 91,
                "expected_effectiveness": 85
            }
        elif has_sms:
            return {
                "mutation_name": "Dynamic SMS Stealer Payload",
                "evasion_strategy": "Dynamically loads encrypted DEX payload files from remote command control servers to call SMS APIs, camouflaging static strings.",
                "analyst_weakness": "Static scanning cannot inspect decrypted runtime memory chunks loaded by DexClassLoader.",
                "difficulty_score": 78,
                "expected_effectiveness": 75
            }
        elif has_overlay:
            return {
                "mutation_name": "Spoofed Banking Webview Overlay",
                "evasion_strategy": "Creates layout overlays dynamically matched to active package names on foreground task stacks.",
                "analyst_weakness": "Static scanners look for hardcoded resource templates rather than dynamic drawing methods.",
                "difficulty_score": 85,
                "expected_effectiveness": 80
            }
        else:
            return {
                "mutation_name": "Encrypted C2 Beacon Payload",
                "evasion_strategy": "Encrypts direct connection endpoints inside runtime files and decrypts them via custom AES vectors.",
                "analyst_weakness": "Static string match checks only verify plaintext IP endpoints.",
                "difficulty_score": 52,
                "expected_effectiveness": 65
            }
