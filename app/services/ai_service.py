import os
from dotenv import load_dotenv
from openai import OpenAI


class AISecurityService:
    def __init__(self):
        load_dotenv(override=True)
        self.model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
        self.api_key = os.getenv("OPENAI_API_KEY")
        self.client = OpenAI(api_key=self.api_key) if self.api_key else None

    def _fallback_report(self, title: str, description: str, category: str) -> str:
        return (
            f"[Fallback 분석]\n"
            f"- 취약점: {title}\n"
            f"- 분류: {category}\n"
            f"- 원인 요약: 입력 검증/권한 검증/의존성 관리 미흡 가능성이 높습니다.\n"
            f"- 영향: 공격자가 민감정보 접근 또는 서비스 오동작을 유발할 수 있습니다.\n"
            f"- 조치: 취약 코드 위치를 기준으로 검증 로직과 보안 라이브러리 적용, 재스캔을 수행하세요.\n"
            f"- 상세 설명: {description or '제공된 설명 없음'}"
        )

    def analyze_vulnerability(self, title, description, category):
        if not self.client:
            return self._fallback_report(title, description, category)

        prompt = f"""
당신은 전문 DevSecOps 보안 엔지니어입니다.
다음 보안 취약점에 대해 분석하고, 개발자가 즉시 적용할 수 있는 보안 조치 가이드를 작성하세요.

취약점 제목: {title}
분류: {category}
상세 설명: {description}

요구사항:
1. 취약점 원인
2. 가능한 공격 시나리오
3. 수정 가이드
4. 재검증 체크리스트
"""

        response = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": "당신은 금융권 수준의 보안 가이드를 제공하는 전문가입니다."},
                {"role": "user", "content": prompt},
            ],
            max_tokens=1000,
        )

        return response.choices[0].message.content