import os
import subprocess
import json
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app.parsers.semgrep import SemgrepParser
from app.parsers.pip_audit import PipAuditParser

def run_shell_command(command, description):
    print(f"[*] {description} 시작...")
    try:
        env = os.environ.copy()
        env["PYTHONUTF8"] = "1" 
        env["PYTHONIOENCODING"] = "utf-8"
        
        result = subprocess.run(
            command, 
            shell=True, 
            capture_output=True, 
            text=True, 
            check=False,
            env=env,
            encoding="utf-8"
        )
        
        if result.returncode not in [0, 1]:
            print(f"[!] {description} 중 오류 발생: {result.stderr}")
            return False
            
        print(f"[+] {description} 완료 (JSON 생성됨).")
        return True
    except Exception as e:
        print(f"[!] 예외 발생: {str(e)}")
        return False

def main():
    test_dir = os.path.dirname(__file__)
    vuln_app = os.path.join(test_dir, "vulnerable_app.py")
    req_file = os.path.join(test_dir, "requirements.txt")
    
    semgrep_out = os.path.join(test_dir, "semgrep_report.json")
    pip_audit_out = os.path.join(test_dir, "pip_audit_report.json")

    print("=== [Test] 통합 보안 스캔 ===\n")

    sast_cmd = f"semgrep scan --config auto --json --output \"{semgrep_out}\" \"{vuln_app}\""
    if run_shell_command(sast_cmd, "Semgrep 정적 분석"):
        with open(semgrep_out, "r", encoding="utf-8") as f:
            data = json.load(f)
            vulns = SemgrepParser().parse(data, scan_id=101)
            print(f"   -> [SAST] {len(vulns)}개의 취약점을 발견하였습니다.")
            for v in vulns[:2]:
                print(f"      [!] {v.title} ({v.severity.value})")

    print("-" * 60)


    sca_cmd = f"pip-audit -r \"{req_file}\" --format json > \"{pip_audit_out}\""
    if run_shell_command(sca_cmd, "pip-audit 라이브러리 분석"):
        with open(pip_audit_out, "r", encoding="utf-8") as f:
            data = json.load(f)
            vulns = PipAuditParser().parse(data, scan_id=102)
            print(f"   -> [SCA] {len(vulns)}개의 취약점을 발견하였습니다.")
            for v in vulns[:2]:
                print(f"      [!] {v.title} ({v.severity.value})")

    print("\n[+] 모든 검증이 완료되었습니다.")

if __name__ == "__main__":
    main()