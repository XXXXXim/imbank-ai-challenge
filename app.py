import json
import streamlit as st
from openai import OpenAI

# ------------------------------------------------------------------
# 피싱아이 (Phishing-Eye)
# 보이스피싱·스미싱 AI 판별기 — 시니어 포용금융 프로토타입
# iM뱅크 2026 AI 경진대회 / 원티드 AI Championship 2026 제출용
# ------------------------------------------------------------------

st.set_page_config(page_title="피싱아이 | 보이스피싱·스미싱 판별기", page_icon="🛡️", layout="centered")

# ---- 시크릿(배포 시 Streamlit Secrets에 입력) --------------------
# OpenAI 사용 시:   API_KEY=sk-...,  BASE_URL 비움,  MODEL=gpt-4o-mini
# Upstage 사용 시:  API_KEY=up_...,  BASE_URL=https://api.upstage.ai/v1,  MODEL=solar-pro2
API_KEY = st.secrets.get("API_KEY", "")
BASE_URL = st.secrets.get("BASE_URL", "").strip()
MODEL = st.secrets.get("MODEL", "gpt-4o-mini")

def get_client():
    if BASE_URL:
        return OpenAI(api_key=API_KEY, base_url=BASE_URL)
    return OpenAI(api_key=API_KEY)

SYSTEM = """너는 한국의 보이스피싱·스미싱 탐지 전문가다.
사용자가 받은 의심스러운 문자메시지나 통화 내용을 분석해서, 특히 디지털에 익숙하지 않은
시니어(어르신)도 이해할 수 있게 판정한다.
반드시 아래 JSON 형식으로만 답하라. 다른 말은 하지 마라.

{
  "risk_level": "위험" | "주의" | "안전",
  "score": 0-100 사이 정수(위험할수록 높음),
  "one_line": "한 문장 요약(어르신도 이해할 쉬운 말)",
  "reasons": ["판단 근거 1", "판단 근거 2", "판단 근거 3"],
  "senior_explain": "왜 위험한지 어르신에게 설명하듯 쉽고 친절하게 2~3문장",
  "actions": ["지금 해야 할 행동 1", "행동 2", "행동 3"]
}

판단 시 다음 신호를 참고하라: 정부·은행·검찰·경찰 사칭, 계좌이체/송금 유도, 링크(URL) 클릭 유도,
앱 설치 요구, 개인정보/카드번호/OTP 요구, 급박함·공포심 조성, 저금리 대출·환급·택배 사칭 등.
확실히 안전해 보여도 개인정보/금전 요구가 있으면 최소 '주의'로 판정하라."""

st.markdown(
    "<h1 style='margin-bottom:0'>🛡️ 피싱아이</h1>"
    "<p style='font-size:20px;color:#555;margin-top:4px'>받은 문자·전화가 보이스피싱인지 <b>3초 만에</b> 확인하세요</p>",
    unsafe_allow_html=True,
)
st.caption("어르신도 안심하고 쓸 수 있는 금융사기 예방 서비스")

examples = {
    "예시① 택배 사칭 문자": "[국제발신] 고객님 택배가 주소불명으로 반송되었습니다. 아래 링크에서 주소를 확인해주세요 http://bit.ly/parcel-check",
    "예시② 대출 사칭": "안녕하세요 OO캐피탈입니다. 정부지원 저금리 대환대출 대상자로 선정되셨습니다. 진행 원하시면 앱 설치 후 상담원과 통화 부탁드립니다.",
    "예시③ 지인 사칭": "엄마 나 폰 액정 깨져서 컴퓨터로 문자해. 급하게 인증받을 게 있는데 문자로 오는 인증번호 좀 불러줘",
}
cols = st.columns(3)
if "text" not in st.session_state:
    st.session_state.text = ""
for i, (label, val) in enumerate(examples.items()):
    if cols[i].button(label, use_container_width=True):
        st.session_state.text = val

text = st.text_area(
    "의심스러운 문자 내용이나 통화 내용을 붙여넣으세요",
    key="text",
    height=160,
    placeholder="예) [Web발신] 고객님 계좌가 도용되어 안전계좌로 이체가 필요합니다...",
)

analyze = st.button("🔍 분석하기", type="primary", use_container_width=True)

def analyze_text(t: str):
    client = get_client()
    resp = client.chat.completions.create(
        model=MODEL,
        messages=[{"role": "system", "content": SYSTEM},
                  {"role": "user", "content": t}],
        temperature=0.2,
    )
    raw = resp.choices[0].message.content.strip()
    if raw.startswith("```"):
        raw = raw.split("```")[1].replace("json", "", 1).strip()
    return json.loads(raw)

if analyze:
    if not API_KEY:
        st.error("API 키가 설정되지 않았습니다. (Streamlit Secrets에 API_KEY를 입력하세요)")
    elif not text.strip():
        st.warning("먼저 내용을 붙여넣어 주세요.")
    else:
        with st.spinner("분석 중입니다..."):
            try:
                data = analyze_text(text)
            except Exception as e:
                st.error(f"분석 중 오류가 발생했습니다: {e}")
                st.stop()

        level = data.get("risk_level", "주의")
        score = int(data.get("score", 50))
        color = {"위험": "#e03131", "주의": "#f08c00", "안전": "#2f9e44"}.get(level, "#f08c00")
        emoji = {"위험": "🚨", "주의": "⚠️", "안전": "✅"}.get(level, "⚠️")

        st.markdown(
            f"<div style='background:{color};color:#fff;border-radius:16px;padding:22px;text-align:center'>"
            f"<div style='font-size:44px'>{emoji} {level}</div>"
            f"<div style='font-size:20px;margin-top:6px'>위험도 {score}점 / 100점</div>"
            f"<div style='font-size:18px;margin-top:10px'>{data.get('one_line','')}</div>"
            f"</div>",
            unsafe_allow_html=True,
        )

        st.markdown("### 🧓 쉬운 설명")
        st.info(data.get("senior_explain", ""))

        st.markdown("### 🔎 이렇게 판단했어요")
        for r in data.get("reasons", []):
            st.markdown(f"- {r}")

        st.markdown("### ✅ 지금 하실 일")
        for a in data.get("actions", []):
            st.markdown(f"- {a}")

        st.divider()
        st.markdown(
            "**의심되면 바로 신고하세요** — 경찰 **112** · 금융감독원 **1332** · "
            "은행 대표번호로 직접 전화해 확인 (문자 속 번호로 걸지 마세요)"
        )

st.divider()
st.caption("피싱아이 · AI 보이스피싱 예방 프로토타입 | 본 결과는 참고용이며 최종 판단은 공식 기관에 확인하세요.")
