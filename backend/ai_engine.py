"""
AI Engine — Groq LLM integration for intelligent scan planning and analysis.
"""
import json
import requests
from backend.config import GROQ_API_KEY, GROQ_MODEL, GROQ_API_URL


def _get_api_key_from_db():
    """Try to load the Groq API key from the database settings."""
    try:
        from backend.database import get_setting
        key = get_setting("groq_api_key", "")
        return key if key else None
    except Exception:
        return None


class AIEngine:
    """AI-powered scan planning, analysis, and reporting via Groq LLM."""

    def __init__(self, api_key=None):
        self.api_key = api_key or GROQ_API_KEY
        self.model = GROQ_MODEL
        self.available = bool(self.api_key)

    def _resolve_api_key(self):
        """Resolve API key: instance > DB settings > env var."""
        if self.api_key:
            return self.api_key
        db_key = _get_api_key_from_db()
        if db_key:
            self.api_key = db_key
            self.available = True
            return db_key
        return None

    def _call_llm(self, system_prompt, user_prompt, max_tokens=2048):
        """Make a call to the Groq API."""
        api_key = self._resolve_api_key()
        if not api_key:
            return None

        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }

        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            "max_tokens": max_tokens,
            "temperature": 0.3,
        }

        try:
            resp = requests.post(GROQ_API_URL, json=payload, headers=headers, timeout=30)
            if resp.status_code == 401:
                return "[AI Error] Invalid API key. Please check your Groq API key in Settings."
            if resp.status_code == 429:
                return "[AI Error] Rate limit exceeded. Wait a moment and try again."
            if resp.status_code == 404:
                return f"[AI Error] Model '{self.model}' not found. Check available models at console.groq.com."
            resp.raise_for_status()
            data = resp.json()
            return data["choices"][0]["message"]["content"]
        except requests.exceptions.Timeout:
            return "[AI Error] Request timed out. The Groq API may be slow — try again."
        except requests.exceptions.ConnectionError:
            return "[AI Error] Cannot connect to Groq API. Check your internet connection."
        except Exception as e:
            return f"[AI Error] {str(e)}"

    def generate_scan_plan(self, target, scan_type, config=None):
        """Ask AI to create an intelligent scan plan."""
        system_prompt = """You are an expert penetration testing AI assistant. 
Given a target and scan configuration, create an optimal scan execution plan.
Respond in valid JSON format with the following structure:
{
    "phases": [
        {
            "name": "Phase Name",
            "module": "module_name",
            "description": "What this phase does",
            "priority": 1
        }
    ],
    "strategy": "Brief description of the overall strategy",
    "risk_assessment": "Initial risk level assessment",
    "estimated_duration": "Estimated time"
}
Available modules: network_scan, port_scan, web_scan, vuln_analysis"""

        user_prompt = f"""Target: {target}
Scan Type: {scan_type}
Additional Config: {json.dumps(config or {})}

Create an optimal penetration testing plan for this target."""

        result = self._call_llm(system_prompt, user_prompt)
        if result and not result.startswith("[AI Error]"):
            try:
                # Try to extract JSON from the response
                json_match = result
                if "```json" in result:
                    json_match = result.split("```json")[1].split("```")[0]
                elif "```" in result:
                    json_match = result.split("```")[1].split("```")[0]
                return json.loads(json_match.strip())
            except (json.JSONDecodeError, IndexError):
                pass

        # Fallback plan
        return self._default_plan(scan_type)

    def _default_plan(self, scan_type):
        """Generate a default scan plan without AI."""
        plans = {
            "quick": {
                "phases": [
                    {"name": "Port Discovery", "module": "port_scan", "description": "Quick scan of top 100 ports", "priority": 1}
                ],
                "strategy": "Fast reconnaissance of common ports",
                "risk_assessment": "Low — basic port enumeration only",
                "estimated_duration": "1-2 minutes"
            },
            "standard": {
                "phases": [
                    {"name": "Network Reconnaissance", "module": "network_scan", "description": "Host discovery and OS fingerprinting", "priority": 1},
                    {"name": "Port Scanning", "module": "port_scan", "description": "Comprehensive port scan of top 1000 ports", "priority": 2},
                    {"name": "Web Analysis", "module": "web_scan", "description": "Web application security analysis", "priority": 3},
                    {"name": "Vulnerability Analysis", "module": "vuln_analysis", "description": "CVE correlation and risk assessment", "priority": 4}
                ],
                "strategy": "Methodical scan with service detection and web analysis",
                "risk_assessment": "Medium — includes active web testing",
                "estimated_duration": "5-10 minutes"
            },
            "deep": {
                "phases": [
                    {"name": "Network Reconnaissance", "module": "network_scan", "description": "Full network mapping", "priority": 1},
                    {"name": "Full Port Scan", "module": "port_scan", "description": "Complete port range scan (1-65535)", "priority": 2},
                    {"name": "Web Security Audit", "module": "web_scan", "description": "Deep web vulnerability scan", "priority": 3},
                    {"name": "Vulnerability Assessment", "module": "vuln_analysis", "description": "Full CVE analysis and risk scoring", "priority": 4}
                ],
                "strategy": "Exhaustive scan of all ports with full vulnerability analysis",
                "risk_assessment": "High — thorough assessment with active probing",
                "estimated_duration": "15-30 minutes"
            }
        }
        return plans.get(scan_type, plans["standard"])

    def analyze_results(self, target, scan_results):
        """Ask AI to analyze scan results and provide insights."""
        system_prompt = """You are an expert cybersecurity analyst. Analyze the following penetration test results 
and provide a professional security assessment. Focus on:
1. Critical findings that need immediate attention
2. Attack surface analysis
3. Risk prioritization
4. Specific remediation recommendations

Be concise but thorough. Format your response in clear sections."""

        # Summarize results to fit in context
        summary = self._summarize_results(scan_results)

        user_prompt = f"""Target: {target}

Scan Results Summary:
{summary}

Provide a comprehensive security assessment."""

        result = self._call_llm(system_prompt, user_prompt, max_tokens=3000)
        return result if result else "AI analysis unavailable. Review findings manually."

    def generate_remediation(self, finding):
        """Generate specific remediation advice for a finding."""
        system_prompt = """You are a cybersecurity remediation expert. Provide specific, actionable
remediation steps for the given vulnerability. Include:
1. Immediate mitigation steps
2. Long-term fix
3. Prevention measures
Keep your response under 200 words."""

        user_prompt = f"""Vulnerability: {finding.get('title', 'Unknown')}
Severity: {finding.get('severity', 'unknown')}
Description: {finding.get('description', 'No description')}
Evidence: {finding.get('evidence', 'No evidence')}

Provide specific remediation steps."""

        result = self._call_llm(system_prompt, user_prompt, max_tokens=500)
        return result if result else finding.get("remediation", "Review and patch the affected service.")

    def generate_executive_summary(self, target, findings, scan_duration):
        """Generate an executive summary for the report."""
        system_prompt = """You are a senior penetration tester writing an executive summary for a client.
Be professional, clear, and highlight the most important findings. Keep it under 300 words.
Include an overall risk rating (Critical/High/Medium/Low)."""

        severity_counts = {}
        for f in findings:
            sev = f.get("severity", "info")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        user_prompt = f"""Target: {target}
Scan Duration: {scan_duration}
Total Findings: {len(findings)}
Severity Breakdown: {json.dumps(severity_counts)}

Top Findings:
{self._format_top_findings(findings[:10])}

Write a professional executive summary."""

        result = self._call_llm(system_prompt, user_prompt, max_tokens=1000)
        return result if result else f"Penetration test completed on {target}. {len(findings)} findings identified."

    def _summarize_results(self, results):
        """Summarize scan results for AI context."""
        lines = []
        if "network" in results:
            net = results["network"]
            lines.append(f"- IP: {net.get('ip', 'unknown')}, OS: {net.get('os_guess', 'unknown')}, Alive: {net.get('alive', 'unknown')}")

        if "ports" in results:
            ports = results["ports"]
            lines.append(f"- Open ports: {len(ports)}")
            for p in ports[:20]:
                lines.append(f"  Port {p['port']}/{p['service']}: {p.get('banner', '')[:60]}")

        if "web" in results:
            web = results["web"]
            lines.append(f"- Technologies: {', '.join(web.get('technologies', []))}")
            lines.append(f"- Missing headers: {', '.join(web.get('missing_headers', []))}")
            lines.append(f"- Web vulnerabilities: {len(web.get('vulnerabilities', []))}")

        if "vulnerabilities" in results:
            vulns = results["vulnerabilities"]
            lines.append(f"- Total CVE findings: {len(vulns)}")
            for v in vulns[:10]:
                lines.append(f"  [{v.get('severity', 'info').upper()}] {v.get('title', 'Unknown')}")

        return "\n".join(lines) if lines else "No results available."

    def _format_top_findings(self, findings):
        """Format top findings for AI prompt."""
        lines = []
        for f in findings:
            lines.append(f"- [{f.get('severity', 'info').upper()}] {f.get('title', 'Unknown')}: {f.get('description', '')[:100]}")
        return "\n".join(lines)
