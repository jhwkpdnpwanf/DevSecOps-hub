import json
from app.database.models import Vulnerability, Severity, VulnStatus

class PipAuditParser:
    def parse(self, json_data: dict, scan_id: int):
        vulnerabilities = []
        
        for dep in json_data.get("dependencies", []):
            package_name = dep.get("name")
            version = dep.get("version")
            
            for issue in dep.get("vulns", []):
                vuln = Vulnerability(
                    scan_id=scan_id,
                    title=f"{package_name} - {issue.get('id')}",
                    severity=Severity.HIGH, 
                    status=VulnStatus.OPEN,
                    cve_id=issue.get("id"),
                    category="SCA",
                    description=issue.get("description"), 
                    extra_context={
                        "package_name": package_name,
                        "version": version,
                        "fix_versions": issue.get("fix_versions", [])
                    }
                )
                vulnerabilities.append(vuln)
        return vulnerabilities