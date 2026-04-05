import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path


def main() -> int:
    if len(sys.argv) != 2:
        print("Usage: python automation/post_ingest.py <payload_file>")
        return 1

    payload_file = Path(sys.argv[1])
    if not payload_file.exists():
        print(f"Payload file not found: {payload_file}")
        return 1

    hub_url = os.environ.get("HUB_URL")
    project_token = os.environ.get("PROJECT_TOKEN")

    if not hub_url:
        print("Missing env: HUB_URL")
        return 1
    if not project_token:
        print("Missing env: PROJECT_TOKEN")
        return 1

    with payload_file.open("rb") as f:
        payload_bytes = f.read()

    req = urllib.request.Request(
        url=f"{hub_url}/api/ingest",
        data=payload_bytes,
        headers={
            "Content-Type": "application/json",
            "X-Project-Token": project_token,
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            print(body)
            return 0
    except urllib.error.HTTPError as e:
        error_body = e.read().decode("utf-8", errors="replace")
        print(f"HTTP {e.code}: {error_body}")
        return 1
    except urllib.error.URLError as e:
        print(f"URL error: {e}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())