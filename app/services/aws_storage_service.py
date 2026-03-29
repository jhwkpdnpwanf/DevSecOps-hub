
import json
import os
from dataclasses import dataclass

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from app.database.models import ToolType


@dataclass
class S3ReportMeta:
    key: str
    last_modified: str
    size: int
    tool_type: str


class AWSStorageService:
    def __init__(self):
        self.bucket = os.getenv("AWS_S3_REPORT_BUCKET")
        self.region = os.getenv("AWS_REGION", "ap-northeast-2")
        self.prefix_root = os.getenv("AWS_S3_PREFIX_ROOT", "")

    def _s3_client(self):
        return boto3.client("s3", region_name=self.region)

    def is_configured(self) -> bool:
        return bool(self.bucket)

    def _normalize_prefix(self, project: str | None):
        parts = [p.strip("/") for p in [self.prefix_root, project] if p]
        return "/".join(parts)

    def list_reports(self, project: str | None = None):
        if not self.bucket:
            raise ValueError("AWS_S3_REPORT_BUCKET 환경변수가 설정되지 않았습니다.")

        prefix = self._normalize_prefix(project)
        paginator = self._s3_client().get_paginator("list_objects_v2")

        results: list[S3ReportMeta] = []

        try:
            for page in paginator.paginate(Bucket=self.bucket, Prefix=prefix):
                for obj in page.get("Contents", []):
                    key = obj["Key"]
                    if not key.endswith(".json"):
                        continue
                    results.append(
                        S3ReportMeta(
                            key=key,
                            last_modified=obj["LastModified"].isoformat(),
                            size=obj["Size"],
                            tool_type=self._guess_tool_type_from_key(key).value,
                        )
                    )
        except (ClientError, BotoCoreError) as e:
            raise RuntimeError(f"S3 목록 조회 실패(bucket={self.bucket}, prefix={prefix}): {e}") from e
        return results

    def discover_project_names(self) -> list[str]:
        """
        Discover project candidates from S3 report object keys.
        Key pattern expectation:
          - <prefix_root>/<project>/<tool>/...json
          - <project>/<tool>/...json
        """
        if not self.bucket:
            raise ValueError("AWS_S3_REPORT_BUCKET 환경변수가 설정되지 않았습니다.")

        projects: set[str] = set()
        normalized_root = self.prefix_root.strip("/")
        root_prefix = f"{normalized_root}/" if normalized_root else ""

        for report in self.list_reports(project=None):
            key = report.key
            relative = key
            if root_prefix and key.startswith(root_prefix):
                relative = key[len(root_prefix):]

            if "/" not in relative:
                continue

            candidate = relative.split("/", 1)[0].strip()
            if candidate:
                projects.add(candidate)

        if not projects and not normalized_root:
            bucket_name = self.bucket.strip()
            for suffix in ("-reports", "_reports"):
                if bucket_name.endswith(suffix):
                    bucket_name = bucket_name[: -len(suffix)]
                    break
            if bucket_name:
                projects.add(bucket_name)

        return sorted(projects)
    
    def read_report_json(self, key: str) -> dict:
        if not self.bucket:
            raise ValueError("AWS_S3_REPORT_BUCKET 환경변수가 설정되지 않았습니다.")

        try:
            resp = self._s3_client().get_object(Bucket=self.bucket, Key=key)
            data = resp["Body"].read().decode("utf-8")
            return json.loads(data)
        except (ClientError, BotoCoreError) as e:
            raise RuntimeError(f"S3 report 읽기 실패: {e}") from e

    def get_presigned_download_url(self, key: str, expires_in: int = 600):
        if not self.bucket:
            raise ValueError("AWS_S3_REPORT_BUCKET 환경변수가 설정되지 않았습니다.")
        return self._s3_client().generate_presigned_url(
            ClientMethod="get_object",
            Params={"Bucket": self.bucket, "Key": key},
            ExpiresIn=expires_in,
        )

    @staticmethod
    def _guess_tool_type_from_key(key: str) -> ToolType:
        lowered = key.lower()
        if "semgrep" in lowered or "/sast/" in lowered:
            return ToolType.SAST
        if "zap" in lowered or "/dast/" in lowered:
            return ToolType.DAST
        if "pip" in lowered or "sca" in lowered:
            return ToolType.SCA
        return ToolType.SCA