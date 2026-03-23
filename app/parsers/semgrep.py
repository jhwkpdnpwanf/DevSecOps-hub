import json
from app.database.models import Vulnerability, Severity, VulnStatus

class SemgrepParser:
    SEVERITY_MAP = {
        "ERROR": Severity.HIGH,
        "WARNING": Severity.MEDIUM,
        "INFO": Severity.INFO
    }

    def parse(self, json_data: dict, scan_id: int):
        vulnerabilities = []
        for result in json_data.get("results", []):
            extra = result.get("extra", {})
            
            vuln = Vulnerability(
                scan_id=scan_id,
                title=result.get("check_id"),
                severity=self.SEVERITY_MAP.get(extra.get("severity"), Severity.MEDIUM),
                status=VulnStatus.OPEN,
                category=extra.get("metadata", {}).get("category", "Security"),
                extra_context={
                    "file_path": result.get("path"),
                    "line_number": result.get("start", {}).get("line"),
                    "message": extra.get("message"),
                    "remediation": extra.get("metadata", {}).get("remediation_v1")
                }
            )
            vulnerabilities.append(vuln)
        return vulnerabilities