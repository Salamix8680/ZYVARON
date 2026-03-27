"""
ZYVARON CVE Vulnerability Checker — Layer 6
Agent-side module that:
1. Reads installed software from Windows registry/wmic
2. Queries NVD (NIST) CVE API for known vulnerabilities
3. Caches results locally (API has rate limits)
4. Reports findings to server
"""

import asyncio, json, os, subprocess, logging, time
from pathlib import Path
from datetime import datetime, timedelta

log = logging.getLogger("CVEChecker")

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CACHE_FILE = Path("cve_cache.json")
CACHE_TTL_HOURS = 6  # Re-check every 6 hours

# Well-known software → CPE keyword mapping
# CPE (Common Platform Enumeration) is how NVD identifies software
SOFTWARE_CPE_MAP = {
    "python":          "python",
    "node":            "node.js",
    "nodejs":          "node.js",
    "chrome":          "chrome",
    "firefox":         "firefox",
    "openssh":         "openssh",
    "openssl":         "openssl",
    "apache":          "apache_http_server",
    "nginx":           "nginx",
    "java":            "java",
    "microsoft office":"microsoft_office",
    "word":            "microsoft_word",
    "excel":           "microsoft_excel",
    "outlook":         "microsoft_outlook",
    "edge":            "edge",
    "teams":           "microsoft_teams",
    "zoom":            "zoom",
    "7-zip":           "7-zip",
    "vlc":             "vlc_media_player",
    "notepad++":       "notepad\\+\\+",
    "git":             "git",
    "visual studio":   "visual_studio",
    "vscode":          "visual_studio_code",
    "powershell":      "powershell",
    "windows":         "windows_11",
}

class CVEChecker:
    def __init__(self, config: dict = None):
        self.config  = config or {}
        self.cache   = self._load_cache()
        log.info("CVEChecker initialized")

    def _load_cache(self) -> dict:
        if CACHE_FILE.exists():
            try:
                with open(CACHE_FILE) as f:
                    return json.load(f)
            except Exception:
                pass
        return {}

    def _save_cache(self):
        try:
            with open(CACHE_FILE, "w") as f:
                json.dump(self.cache, f, indent=2)
        except Exception as e:
            log.debug(f"Cache save error: {e}")

    def _cache_valid(self, key: str) -> bool:
        entry = self.cache.get(key)
        if not entry:
            return False
        cached_at = datetime.fromisoformat(entry.get("cached_at", "2000-01-01"))
        return datetime.utcnow() - cached_at < timedelta(hours=CACHE_TTL_HOURS)

    def get_installed_software(self) -> list:
        """Read installed software from Windows registry via PowerShell."""
        software = []
        try:
            # Query both 32-bit and 64-bit registry keys
            ps_script = """
$paths = @(
    'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',
    'HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',
    'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*'
)
$apps = Get-ItemProperty $paths -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName -ne $null -and $_.DisplayName -ne '' } |
    Select-Object DisplayName, DisplayVersion, Publisher |
    Sort-Object DisplayName -Unique
$apps | ConvertTo-Json -Compress
"""
            result = subprocess.run(
                ["powershell", "-NonInteractive", "-Command", ps_script],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0 and result.stdout.strip():
                raw = json.loads(result.stdout.strip())
                # PowerShell returns object or array
                if isinstance(raw, dict):
                    raw = [raw]
                for item in raw:
                    name    = item.get("DisplayName", "").strip()
                    version = item.get("DisplayVersion", "").strip()
                    pub     = item.get("Publisher", "").strip()
                    if name:
                        software.append({
                            "name":      name,
                            "version":   version or "unknown",
                            "publisher": pub,
                        })
        except Exception as e:
            log.warning(f"Software enumeration error: {e}")
            # Fallback: return a minimal known list based on common Windows software
            software = [
                {"name": "Microsoft Windows", "version": "11", "publisher": "Microsoft"},
                {"name": "Python", "version": "3.14", "publisher": "Python Software Foundation"},
            ]
        log.info(f"Found {len(software)} installed applications")
        return software

    async def check_cves_for_software(self, name: str, version: str) -> list:
        """Query NVD CVE API for vulnerabilities in a specific software."""
        # Find matching CPE keyword
        keyword = None
        name_lower = name.lower()
        for sw_key, cpe in SOFTWARE_CPE_MAP.items():
            if sw_key in name_lower:
                keyword = cpe
                break
        if not keyword:
            return []

        cache_key = f"{keyword}:{version}"
        if self._cache_valid(cache_key):
            return self.cache[cache_key].get("cves", [])

        try:
            import aiohttp
            params = {
                "keywordSearch": keyword,
                "resultsPerPage": 10,
                "startIndex": 0,
            }
            # Only add version filter if we have a real version
            if version and version != "unknown":
                # Search for version in the keyword to narrow results
                params["keywordSearch"] = f"{keyword} {version.split('.')[0]}"

            async with aiohttp.ClientSession() as session:
                async with session.get(
                    NVD_API, params=params,
                    headers={"User-Agent": "ZYVARON-SecurityScanner/1.0"},
                    timeout=aiohttp.ClientTimeout(total=15)
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        cves = self._parse_nvd_response(data, name, version)
                        # Cache result
                        self.cache[cache_key] = {
                            "cached_at": datetime.utcnow().isoformat(),
                            "cves": cves,
                        }
                        self._save_cache()
                        return cves
                    elif resp.status == 429:
                        log.warning("NVD API rate limited — using cache or empty")
                        return self.cache.get(cache_key, {}).get("cves", [])
        except Exception as e:
            log.debug(f"NVD API error for {name}: {e}")
        return []

    def _parse_nvd_response(self, data: dict, sw_name: str, sw_version: str) -> list:
        """Parse NVD API response into clean CVE list."""
        cves = []
        vulnerabilities = data.get("vulnerabilities", [])
        for item in vulnerabilities[:5]:  # Top 5 most relevant
            cve_data = item.get("cve", {})
            cve_id   = cve_data.get("id", "")
            # Get CVSS score
            score    = 0.0
            severity = "UNKNOWN"
            metrics  = cve_data.get("metrics", {})
            # Try CVSS v3.1 first, then v3.0, then v2
            for metric_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                m_list = metrics.get(metric_key, [])
                if m_list:
                    cvss_data = m_list[0].get("cvssData", {})
                    score     = cvss_data.get("baseScore", 0.0)
                    severity  = cvss_data.get("baseSeverity", "UNKNOWN")
                    break
            # Get description
            desc = ""
            for d in cve_data.get("descriptions", []):
                if d.get("lang") == "en":
                    desc = d.get("value", "")[:200]
                    break
            # Get published date
            published = cve_data.get("published", "")[:10]
            if cve_id and score >= 4.0:  # Only medium+ severity
                sev = severity if severity != "UNKNOWN" else _score_to_severity(score)
                cves.append({
                    "cve_id":      cve_id,
                    "software":    sw_name,
                    "version":     sw_version,
                    "score":       score,
                    "severity":    sev,
                    "description": desc,
                    "published":   published,
                    "url":         f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                    "patch_action": _get_patch_action(sw_name, sev),
                })
        # Sort by CVSS score descending
        cves.sort(key=lambda x: x["score"], reverse=True)
        return cves

    async def run_full_scan(self) -> dict:
        """Run full CVE scan against all installed software."""
        log.info("CVE scan starting...")
        software = self.get_installed_software()
        all_cves = []
        scanned  = 0

        # Only scan software we have CPE mappings for (avoid wasting API calls)
        relevant = []
        for sw in software:
            name_lower = sw["name"].lower()
            for sw_key in SOFTWARE_CPE_MAP:
                if sw_key in name_lower:
                    relevant.append(sw)
                    break

        log.info(f"Scanning {len(relevant)} relevant apps (of {len(software)} total)...")

        for sw in relevant[:15]:  # Limit to 15 to respect rate limits
            cves = await self.check_cves_for_software(sw["name"], sw["version"])
            all_cves.extend(cves)
            scanned += 1
            if cves:
                log.warning(f"  {sw['name']} {sw['version']}: {len(cves)} CVE(s) found")
            # Rate limit: NVD allows 5 req/30s without API key
            await asyncio.sleep(2)

        # Deduplicate by CVE ID
        seen_ids = set()
        unique_cves = []
        for cve in all_cves:
            if cve["cve_id"] not in seen_ids:
                seen_ids.add(cve["cve_id"])
                unique_cves.append(cve)

        unique_cves.sort(key=lambda x: x["score"], reverse=True)

        critical = [c for c in unique_cves if c["score"] >= 9.0]
        high     = [c for c in unique_cves if 7.0 <= c["score"] < 9.0]
        medium   = [c for c in unique_cves if 4.0 <= c["score"] < 7.0]

        result = {
            "scanned_at":      datetime.utcnow().isoformat(),
            "apps_scanned":    scanned,
            "apps_total":      len(software),
            "total_cves":      len(unique_cves),
            "critical_count":  len(critical),
            "high_count":      len(high),
            "medium_count":    len(medium),
            "cves":            unique_cves,
            "software_list":   software[:50],  # Send first 50 for display
        }
        log.info(f"CVE scan complete | {len(unique_cves)} CVEs | Critical: {len(critical)} | High: {len(high)}")
        return result


def _score_to_severity(score: float) -> str:
    if score >= 9.0:  return "CRITICAL"
    if score >= 7.0:  return "HIGH"
    if score >= 4.0:  return "MEDIUM"
    return "LOW"


def _get_patch_action(software: str, severity: str) -> dict:
    """Return guidance on how to patch this CVE."""
    sw_lower = software.lower()

    # winget-upgradeable apps
    WINGET = {
        "git":           ("winget upgrade --id Git.Git", "Git.Git"),
        "chrome":        ("winget upgrade --id Google.Chrome", "Google.Chrome"),
        "google chrome": ("winget upgrade --id Google.Chrome", "Google.Chrome"),
        "python":        ("winget upgrade --id Python.Python.3.14", "Python.Python.3.14"),
        "firefox":       ("winget upgrade --id Mozilla.Firefox", "Mozilla.Firefox"),
        "vscode":        ("winget upgrade --id Microsoft.VisualStudioCode", "Microsoft.VisualStudioCode"),
        "visual studio code": ("winget upgrade --id Microsoft.VisualStudioCode", "Microsoft.VisualStudioCode"),
        "7-zip":         ("winget upgrade --id 7zip.7zip", "7zip.7zip"),
        "vlc":           ("winget upgrade --id VideoLAN.VLC", "VideoLAN.VLC"),
        "zoom":          ("winget upgrade --id Zoom.Zoom", "Zoom.Zoom"),
        "notepad++":     ("winget upgrade --id Notepad++.Notepad++", "Notepad++.Notepad++"),
        "node":          ("winget upgrade --id OpenJS.NodeJS", "OpenJS.NodeJS"),
        "teams":         ("winget upgrade --id Microsoft.Teams", "Microsoft.Teams"),
    }
    for key, (cmd, pkg_id) in WINGET.items():
        if key in sw_lower:
            return {
                "method":      "winget",
                "command":     cmd,
                "winget_id":   pkg_id,
                "auto_update": True,
                "description": f"Run in PowerShell (Admin): {cmd}",
            }

    # Windows Update for OS-level
    if "windows" in sw_lower or "microsoft" in sw_lower:
        return {
            "method":      "windows_update",
            "command":     "Start-Process 'ms-settings:windowsupdate'",
            "auto_update": False,
            "description": "Open Windows Update and install all available updates",
        }

    # Generic
    return {
        "method":      "manual",
        "command":     None,
        "auto_update": False,
        "description": f"Visit {software} official website to download the latest version",
    }
