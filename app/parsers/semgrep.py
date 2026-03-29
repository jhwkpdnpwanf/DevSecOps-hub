from app.database.models import Severity, Vulnerability, VulnStatus


class SemgrepParser:
    SEVERITY_MAP = {
        "ERROR": Severity.HIGH,
        "WARNING": Severity.MEDIUM,
        "INFO": Severity.INFO,
    }

    def parse(self, json_data: dict, scan_id: int):
        vulnerabilities = []
        seen_keys: set[str] = set()

        for result in json_data.get("results", []):
            extra = result.get("extra", {})
            metadata = extra.get("metadata", {})
            check_id = result.get("check_id", "unknown-check")
            path = result.get("path", "unknown-path")
            line = result.get("start", {}).get("line")

            vulnerability_key = f"{check_id}:{path}:{line or 0}"
            if vulnerability_key in seen_keys:
                continue
            seen_keys.add(vulnerability_key)

            severity = self.SEVERITY_MAP.get(extra.get("severity"), Severity.MEDIUM)
            
            shortlink = metadata.get("shortlink")
            title = (
                metadata.get("message")
                or metadata.get("short_description")
                or check_id
            )
            if isinstance(title, str) and title.startswith("https://"):
                title = check_id

            description = (
                extra.get("message")
                or metadata.get("message")
                or metadata.get("short_description")
                or extra.get("lines")
                or metadata.get("technology")
            )

            vuln = Vulnerability(
                scan_id=scan_id,
                vulnerability_key=vulnerability_key,
                title=title,
                severity=severity,
                status=VulnStatus.DETECTED,
                category=metadata.get("category", "SAST"),
                cwe_id=(metadata.get("cwe") or [None])[0] if isinstance(metadata.get("cwe"), list) else metadata.get("cwe"),
                description=description,
                location=path,
                line_number=line,
                extra_context={
                    "check_id": check_id,
                    "shortlink": shortlink,
                    "message": extra.get("message"),
                    "remediation": metadata.get("remediation"),
                    "references": metadata.get("references", []),
                },
            )
            vulnerabilities.append(vuln)
        return vulnerabilities