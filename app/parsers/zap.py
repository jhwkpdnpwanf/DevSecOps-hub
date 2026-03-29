from app.database.models import Severity, Vulnerability, VulnStatus


class ZAPParser:
    RISK_MAP = {
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
        "informational": Severity.INFO,
    }

    def parse(self, json_data: dict, scan_id: int):
        vulnerabilities = []
        seen_keys: set[str] = set()

        sites = json_data.get("site", [])
        if isinstance(sites, dict):
            sites = [sites]
        if not sites and isinstance(json_data.get("report"), dict):
            report_sites = json_data.get("report", {}).get("site", [])
            if isinstance(report_sites, dict):
                report_sites = [report_sites]
            sites = report_sites
        for site in sites:
            for alert in site.get("alerts", []):
                risk = str(alert.get("risk", "medium")).lower()
                severity = self.RISK_MAP.get(risk, Severity.MEDIUM)
                plugin_id = alert.get("pluginid", "unknown-plugin")
                name = alert.get("name", "ZAP Alert")
                description = alert.get("description") or alert.get("desc")

                for instance in alert.get("instances", []) or [{}]:
                    uri = instance.get("uri", site.get("@name", "unknown-uri"))
                    param = instance.get("param", "")
                    key = f"{plugin_id}:{uri}:{param}"
                    
                    if key in seen_keys:
                        continue
                    seen_keys.add(key)

                    vulnerabilities.append(
                        Vulnerability(
                            scan_id=scan_id,
                            vulnerability_key=key,
                            title=name,
                            severity=severity,
                            status=VulnStatus.DETECTED,
                            category="DAST",
                            cwe_id=str(alert.get("cweid")) if alert.get("cweid") else None,
                            description=description,
                            location=uri,
                            extra_context={
                                "plugin_id": plugin_id,
                                "risk_desc": alert.get("riskdesc"),
                                "solution": alert.get("solution"),
                                "reference": alert.get("reference"),
                                "attack": instance.get("attack"),
                                "evidence": instance.get("evidence"),
                                "method": instance.get("method"),
                            },
                        )
                    )

        return vulnerabilities