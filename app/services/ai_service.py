import os
from dotenv import load_dotenv
from openai import OpenAI

class AISecurityService:
    def __init__(self):
        load_dotenv(override=True)

        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            raise ValueError("OPENAI_API_KEY가 설정되지 않았습니다.")

        self.client = OpenAI(api_key=api_key)
        self.model = "gpt-4o-mini"

    def analyze_vulnerability(self, title, description, category):
        prompt = f"""
당신은 전문 DevSecOps 보안 엔지니어입니다.
다음 보안 취약점에 대해 분석하고, 개발자가 즉시 적용할 수 있는 보안 조치 가이드를 작성하세요.

취약점 제목: {title}
분류: {category}
상세 설명: {description}

요구사항:
1. 이 취약점이 발생하는 원인을 기술할 것.
2. 이로 인해 발생할 수 있는 보안 사고 시나리오를 설명할 것.
3. 가장 안전한 수정 코드 예시를 제공할 것.
4. 이모티콘 없이 전문적인 톤 유지
"""

        response = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": "당신은 금융권 수준의 보안 가이드를 제공하는 전문가입니다."},
                {"role": "user", "content": prompt},
            ],
            max_tokens=2000,
        )

        return response.choices[0].message.content