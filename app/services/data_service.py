from __future__ import annotations

import json
import os
import subprocess
import tempfile
from dataclasses import dataclass


@dataclass
class DASTRunResult:
    report: dict
    exit_code: int
    stdout: str
    stderr: str
    command: list[str]


class DASTScanService:
    """
    OWASP ZAP baseline scan runner.
    - Requires `zap-baseline.py` (or compatible command) to be available in runtime.
    - Command can be overridden by `DAST_ZAP_BASELINE_CMD`.
    """

    def __init__(self):
        self.command = os.getenv("DAST_ZAP_BASELINE_CMD", "zap-baseline.py")
        self.timeout_seconds = int(os.getenv("DAST_SCAN_TIMEOUT_SECONDS", "1200"))
        self.max_minutes = int(os.getenv("DAST_SCAN_MAX_MINUTES", "5"))

    def run_baseline_scan(self, target_url: str) -> DASTRunResult:
        target = target_url.strip()
        if not target.startswith(("http://", "https://")):
            raise ValueError("target_url은 http:// 또는 https:// 로 시작해야 합니다.")

        with tempfile.TemporaryDirectory(prefix="devsecops-zap-") as tmpdir:
            json_path = os.path.join(tmpdir, "zap_report.json")
            cmd = [
                self.command,
                "-t",
                target,
                "-J",
                json_path,
                "-m",
                str(self.max_minutes),
            ]

            try:
                completed = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=self.timeout_seconds,
                    check=False,
                )
            except FileNotFoundError as exc:
                raise RuntimeError(
                    f"DAST 실행 명령을 찾을 수 없습니다: {self.command}. "
                    "런타임에 ZAP baseline 도구를 설치하거나 DAST_ZAP_BASELINE_CMD를 설정해 주세요."
                ) from exc

            if completed.returncode not in (0, 1, 2):
                raise RuntimeError(
                    f"ZAP baseline 실행 실패(exit={completed.returncode}). stderr={completed.stderr.strip()}"
                )

            if not os.path.exists(json_path):
                raise RuntimeError(
                    "ZAP baseline 실행은 완료되었지만 JSON 리포트가 생성되지 않았습니다."
                )

            with open(json_path, "r", encoding="utf-8") as f:
                report = json.load(f)

        return DASTRunResult(
            report=report,
            exit_code=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
            command=cmd,
        )