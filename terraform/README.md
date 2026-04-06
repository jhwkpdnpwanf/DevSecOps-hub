# Terraform (AWS S3 + IAM)

이 디렉터리는 DevSecOps Hub가 S3 원본 리포트를 읽고/쓰기 위해 필요한 최소 인프라를 정의합니다.

OIDC Provider는 AWS 계정 단위의 공용 리소스로, 동일한 Provider를 중복 생성할 수 없습니다.
따라서 신규 계정에서는 Terraform을 통해 생성이 가능하지만, 기존 계정에서는 이미 동일한 Provider가 존재할 수 있어 충돌이 발생할 수 있습니다.



## 구성 리소스
- S3 버킷 (`reports`)
  - 버전 관리(Versioning), 서버 측 암호화, 퍼블릭 접근 차단, 수명주기 정책 적용
- 애플리케이션 런타임 IAM Role
  - S3 읽기(Read) 권한 정책 부여
- GitHub Actions용 IAM Role (OIDC 기반)
  - GitHub OIDC Provider를 통한 AssumeRole 구성
  - S3 업로드(Write) 권한 정책 부여

<br>

## terraform-admin

우선 IAM 사용자 `terraform-admin`을 추가해줍니다. 권한은 다음과 같이 설정합니다. 
- AmazonEC2FullAccess
- AmazonRDSFullAccess
- AmazonS3FullAccess
- IAMFullAccess

<br>

## 사용 방법 (예시 수정필요)

`terraform.tfvars`에서 기본 예시값을 수정한 뒤 다음 명령어를 입력합니다.  

```powershell
cd terraform
terraform init
terraform plan
terraform apply
```

<br>

## 앱 환경변수
## Render 환경변수

- `DATABASE_URL=<RDS MySQL 연결 문자열>`
- `DEVSECOPS_PROJECT_NAME=devsecops-hub`
- `DEVSECOPS_PROJECT_TOKEN=<프로젝트 API 토큰>`
- `SESSION_SECRET=<세션 암호화 키>`
- `OPENAI_API_KEY=<OpenAI API Key>`
- `GITHUB_OAUTH_CLIENT_ID=<GitHub OAuth App Client ID>`
- `GITHUB_OAUTH_CLIENT_SECRET=<GitHub OAuth App Client Secret>`
- `GITHUB_OAUTH_REDIRECT_URI=<예: https://<render-service>/auth/github/callback>`
- `AUTH_ADMIN_USERS=<쉼표구분 GitHub username/email 목록>`
- `AUTH_SECURITY_USERS=<쉼표구분 GitHub username/email 목록>`
- `AUTH_VIEWER_USERS=<쉼표구분 GitHub username/email 목록>`


## GitHub Secrets (CI)
- `AWS_REGION`
- `AWS_S3_REPORT_BUCKET`
- `AWS_GITHUB_ROLE_ARN`
- `DEVSECOPS_HUB_URL`
- `DEVSECOPS_PROJECT_NAME`
- `DEVSECOPS_PROJECT_TOKEN`


## 권한 설계
- 앱 Role: `s3:ListBucket`, `s3:GetObject`, `s3:PutObject`
- GitHub Actions Role: OIDC Assume 후 S3 업로드/조회
