from app.database.models import Severity, Vulnerability, VulnStatus


class PipAuditParser:
    def parse(self, json_data: dict, scan_id: int):
        vulnerabilities = []
        seen_keys: set[str] = set()

        for dep in json_data.get("dependencies", []):
            package_name = dep.get("name", "unknown-package")
            version = dep.get("version", "unknown")

            for issue in dep.get("vulns", []):
                vuln_id = issue.get("id", "unknown-vuln")
                vulnerability_key = f"{package_name}:{vuln_id}"
                
                if vulnerability_key in seen_keys:
                    continue
                seen_keys.add(vulnerability_key)

                fix_versions = issue.get("fix_versions", [])
                severity = Severity.HIGH if fix_versions else Severity.MEDIUM

                vuln = Vulnerability(
                    scan_id=scan_id,
                    vulnerability_key=vulnerability_key,
                    title=f"{package_name} - {vuln_id}",
                    severity=severity,
                    status=VulnStatus.DETECTED,
                    cve_id=vuln_id if vuln_id.startswith("CVE-") else None,
                    category="SCA",
                    description=issue.get("description") or issue.get("aliases", ["-"])[0],
                    location=f"requirements: {package_name}",
                    extra_context={
                        "package_name": package_name,
                        "version": version,
                        "aliases": issue.get("aliases", []),
                        "fix_versions": fix_versions,
                    },
                )
                vulnerabilities.append(vuln)
                
        return vulnerabilities