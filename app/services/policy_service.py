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
    SEVERITY_WEIGHTS = {
        Severity.CRITICAL: 100,
        Severity.HIGH: 80,
        Severity.MEDIUM: 55,
        Severity.LOW: 25,
        Severity.INFO: 5,
    }
    PRIORITY_WEIGHTS = {
        Priority.P0: 40,
        Priority.P1: 28,
        Priority.P2: 14,
        Priority.P3: 6,
    }
    CRITICALITY_WEIGHTS = {
        "CORE": 20,
        "IMPORTANT": 10,
        "STANDARD": 0,
    }
    EXPOSURE_WEIGHTS = {
        "PUBLIC": 15,
        "INTERNAL": 0,
    }
    STATUS_WEIGHTS = {
        VulnStatus.DETECTED: 12,
        VulnStatus.TRIAGED: 8,
        VulnStatus.IN_PROGRESS: 6,
        VulnStatus.FIXED: 2,
        VulnStatus.VERIFIED: 1,
        VulnStatus.CLOSED: -100,
    }

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
    def evaluate_risk_score(
        severity: Severity,
        priority: Priority,
        project_criticality: str,
        exposure: str,
        status: VulnStatus,
    ) -> int:
        score = 0
        score += PolicyEngine.SEVERITY_WEIGHTS.get(severity, 0)
        score += PolicyEngine.PRIORITY_WEIGHTS.get(priority, 0)
        score += PolicyEngine.CRITICALITY_WEIGHTS.get(project_criticality, 0)
        score += PolicyEngine.EXPOSURE_WEIGHTS.get(exposure, 0)
        score += PolicyEngine.STATUS_WEIGHTS.get(status, 0)
        return max(score, 0)
    
    @staticmethod
    def validate_status_transition(from_status: VulnStatus, to_status: VulnStatus):
        allowed = VALID_TRANSITIONS.get(from_status, set())
        return to_status in allowed