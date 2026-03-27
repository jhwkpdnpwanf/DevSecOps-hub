from app.database.models import Priority, Severity, VulnStatus


VALID_TRANSITIONS = {
    VulnStatus.DETECTED: {VulnStatus.TRIAGED},
    VulnStatus.TRIAGED: {VulnStatus.IN_PROGRESS, VulnStatus.CLOSED},
    VulnStatus.IN_PROGRESS: {VulnStatus.FIXED, VulnStatus.TRIAGED},
    VulnStatus.FIXED: {VulnStatus.VERIFIED, VulnStatus.IN_PROGRESS},
    VulnStatus.VERIFIED: {VulnStatus.CLOSED, VulnStatus.IN_PROGRESS},
    VulnStatus.CLOSED: set(),
}


class PolicyEngine:
    @staticmethod
    def evaluate_priority(severity: Severity, project_criticality: str, exposure: str):
        default = {
            Severity.CRITICAL: (Priority.P0, 1),
            Severity.HIGH: (Priority.P1, 7),
            Severity.MEDIUM: (Priority.P2, 14),
            Severity.LOW: (Priority.P3, 30),
            Severity.INFO: (Priority.P3, 30),
        }
        priority, sla = default.get(severity, (Priority.P3, 30))

        if project_criticality == "CORE" and priority in {Priority.P2, Priority.P3}:
            priority, sla = Priority.P1, min(sla, 7)
        if exposure == "PUBLIC" and priority in {Priority.P2, Priority.P3}:
            priority, sla = Priority.P1, min(sla, 7)

        return priority, sla

    @staticmethod
    def validate_status_transition(from_status: VulnStatus, to_status: VulnStatus):
        allowed = VALID_TRANSITIONS.get(from_status, set())
        return to_status in allowed