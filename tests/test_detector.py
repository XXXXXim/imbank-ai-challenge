"""규칙 탐지기 테스트 — API 키 없이 돈다."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from detector import apply_floor, detect, rule_report  # noqa: E402

SCAMS = {
    "택배 사칭 + 링크": "[국제발신] 고객님 택배가 주소불명으로 반송되었습니다. 아래 링크에서 주소를 확인해주세요 http://bit.ly/parcel-check",
    "대출 사칭 + 앱 설치": "안녕하세요 OO캐피탈입니다. 정부지원 저금리 대환대출 대상자로 선정되셨습니다. 진행 원하시면 앱 설치 후 상담원과 통화 부탁드립니다.",
    "지인 사칭 + 인증번호": "엄마 나 폰 액정 깨져서 컴퓨터로 문자해. 급하게 인증받을 게 있는데 문자로 오는 인증번호 좀 불러줘",
    "검찰 사칭 + 안전계좌": "서울중앙지검 수사관입니다. 고객님 계좌가 범죄에 연루되어 즉시 안전계좌로 이체하셔야 합니다.",
}
NORMAL = {
    "가족 일상": "엄마 오늘 저녁 뭐 먹어? 나 7시쯤 들어갈게",
    "친구 약속": "내일 2시에 서면 스타벅스에서 보자",
    "병원 예약": "OO내과입니다. 10월 25일 오전 10시 진료 예약이 확정되었습니다.",
}


def test_scams_are_not_safe():
    for name, text in SCAMS.items():
        assert detect(text).level != "안전", name


def test_strong_scams_are_danger():
    assert detect(SCAMS["지인 사칭 + 인증번호"]).level == "위험"
    assert detect(SCAMS["검찰 사칭 + 안전계좌"]).level == "위험"
    assert detect(SCAMS["대출 사칭 + 앱 설치"]).level == "위험"


def test_normal_messages_are_safe():
    for name, text in NORMAL.items():
        assert detect(text).level == "안전", name


def test_money_or_info_request_is_at_least_caution():
    # 점수는 낮아도 인증번호 요구가 있으면 최소 '주의'
    assert detect("인증번호 알려줘").level in ("주의", "위험")


def test_rule_report_has_llm_shape():
    out = rule_report(SCAMS["택배 사칭 + 링크"])
    for key in ("risk_level", "score", "one_line", "reasons", "senior_explain", "actions"):
        assert key in out
    assert out["source"] == "rules"


def test_floor_raises_llm_when_it_misses_signals():
    llm_said_safe = {"risk_level": "안전", "score": 10, "one_line": "괜찮아요", "reasons": [],
                     "senior_explain": "", "actions": []}
    out = apply_floor(llm_said_safe, SCAMS["검찰 사칭 + 안전계좌"])
    assert out["risk_level"] == "위험" and out["floor_applied"]
    assert any("규칙 탐지" in r for r in out["reasons"])


def test_floor_keeps_llm_when_it_is_stricter():
    llm_said_danger = {"risk_level": "위험", "score": 90, "reasons": ["새로운 수법"]}
    out = apply_floor(llm_said_danger, NORMAL["친구 약속"])
    assert out["risk_level"] == "위험" and "floor_applied" not in out
