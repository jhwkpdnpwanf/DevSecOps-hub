import json
import os
import sys
from pathlib import Path


def main() -> int:
    if len(sys.argv) != 4:
        print("Usage: python automation/build_ingest_payload.py <tool_type> <report_file> <output_file>")
        return 1

    tool_type = sys.argv[1].strip().lower()
    report_file = Path(sys.argv[2])
    output_file = Path(sys.argv[3])

    allowed_tool_types = {"sast", "sca", "dast"}
    if tool_type not in allowed_tool_types:
        print(f"Unsupported tool_type: {tool_type}")
        return 1

    if not report_file.exists():
        print(f"Report file not found: {report_file}")
        return 1

    project_name = os.environ.get("PROJECT_NAME")
    s3_bucket = os.environ.get("S3_BUCKET")
    github_ref_name = os.environ.get("GITHUB_REF_NAME")
    github_sha = os.environ.get("GITHUB_SHA")
    github_run_id = os.environ.get("GITHUB_RUN_ID")

    if not project_name:
        print("Missing env: PROJECT_NAME")
        return 1
    if not s3_bucket:
        print("Missing env: S3_BUCKET")
        return 1

    key_env_map = {
        "sast": "SAST_KEY",
        "sca": "SCA_KEY",
        "dast": "DAST_KEY",
    }
    s3_key = os.environ.get(key_env_map[tool_type])
    if not s3_key:
        print(f"Missing env: {key_env_map[tool_type]}")
        return 1

    with report_file.open("r", encoding="utf-8") as f:
        report = json.load(f)

    payload = {
        "project_name": project_name,
        "tool_type": tool_type,
        "report": report,
        "initiated_by": "github-actions",
        "branch": github_ref_name,
        "commit_sha": github_sha,
        "pipeline_run_id": github_run_id,
        "s3_report_path": f"s3://{s3_bucket}/{s3_key}",
    }

    with output_file.open("w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False)

    print(f"Payload written to {output_file}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())