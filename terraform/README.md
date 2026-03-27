# Terraform (AWS S3 + IAM)

이 디렉터리는 DevSecOps Hub가 S3 원본 리포트를 읽고/쓰기 위해 필요한 최소 인프라를 정의합니다.

OIDC Provider는 계정 공용 리소스라 중복 생성이 불가능합니다.
신규 계정에서는 Terraform이 생성하고, 기존 계정에서는 import 또는 기존 ARN 참조 방식으로 전환해 idempotent하게 운영합니다.



## 구성 리소스
- S3 버킷 (`reports`) + 버전닝 + 암호화 + 퍼블릭 차단 + 수명주기
- 애플리케이션 런타임 IAM Role + S3 접근 정책
- GitHub Actions OIDC Provider + Assume Role + S3 접근 정책

## 사용 방법
```bash
cd terraform
terraform init
```

```bash
terraform plan -var="github_org=jhwkpdnpwanf" -var="github_repo=DevSecOps-hub" -var="project_name=devsecops-hub"
```

```bash
terraform apply -var="github_org=jhwkpdnpwanf" -var="github_repo=DevSecOps-hub"
```

## 앱 환경변수
- `AWS_REGION`
- `AWS_S3_REPORT_BUCKET` (terraform output `report_bucket_name`)
- `AWS_S3_PREFIX_ROOT` (선택)

## 권한 설계
- 앱 Role: `s3:ListBucket`, `s3:GetObject`, `s3:PutObject`
- GitHub Actions Role: OIDC Assume 후 S3 업로드/조회