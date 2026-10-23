"""
규칙 기반 피싱 신호 탐지기.

두 가지 역할을 한다.
1. API 키가 없을 때 단독으로 판정한다 → 누구나 데모를 써 볼 수 있다.
2. LLM 판정의 '안전 바닥'이 된다 → LLM 이 위험 신호를 놓쳐도, 규칙이 찾은 신호가 있으면
   최종 등급이 그보다 낮아지지 않는다. (틀리면 안 되는 부분은 코드가 지킨다)
"""
import re
from dataclasses import dataclass, field

# (신호 이름, 점수, 정규식, 어르신용 설명)
SIGNALS = [
    ("인증번호·OTP 요구", 45, r"인증\s*번호|인증\s*코드|OTP|보안\s*카드|비밀\s*번호",
     "인증번호나 비밀번호를 알려 달라는 건 은행·가족 누구도 하지 않는 요청이에요."),
    ("앱 설치 유도", 45, r"앱\s*(을|를)?\s*설치|어플\s*설치|원격|apk|팀뷰어|애니데스크",
     "모르는 앱을 깔게 하면 휴대폰을 몰래 조종당할 수 있어요."),
    ("송금·이체 유도", 40, r"이체|송금|입금|안전\s*계좌|보호\s*계좌|계좌로\s*(보내|옮)",
     "'안전계좌'로 돈을 옮기라는 말은 대표적인 사기 수법이에요."),
    ("링크 클릭 유도", 35, r"https?://|www\.|bit\.ly|me2\.kr|han\.gl|\.kr/|\.com/|링크",
     "문자 속 링크를 누르면 악성 앱이 깔리거나 정보가 털릴 수 있어요."),
    ("기관 사칭", 25, r"검찰|경찰|금융감독원|금감원|국세청|법원|수사관|지검",
     "검찰·경찰·금감원은 전화나 문자로 돈이나 정보를 요구하지 않아요."),
    ("금융사·택배 사칭", 15, r"캐피탈|저축은행|대환\s*대출|저금리|정부\s*지원|택배|반송|주소\s*불명|관세",
     "대출·택배·환급을 핑계로 접근하는 문자가 아주 많아요."),
    # '엄마' 같은 호칭만으로는 잡지 않는다(정상 가족 문자 오탐 방지). 사칭의 핵심 수법만 본다.
    ("지인·가족 사칭", 25, r"액정|폰\s*(이|가)?\s*(고장|깨|박살)|컴퓨터로\s*문자|번호\s*(가|를)?\s*바뀌|임시\s*번호",
     "가족이라며 '폰이 고장 났다'고 하면, 꼭 원래 번호로 직접 전화해 확인하세요."),
    ("개인정보 요구", 25, r"주민\s*(등록)?\s*번호|카드\s*번호|신분증|계좌\s*번호|유효\s*기간|CVC",
     "주민번호·카드번호·신분증 사진은 절대 보내면 안 돼요."),
    ("급박함·공포 조성", 15, r"긴급|급하게|즉시|당장|오늘\s*안|정지|도용|연루|체포|압류",
     "'지금 당장'이라고 재촉하는 건 생각할 시간을 빼앗으려는 거예요."),
    ("해외·웹 발신", 10, r"\[?국제\s*발신\]?|\[?국외\s*발신\]?|\[?Web\s*발신\]?",
     "해외·웹 발신 문자는 출처를 확인하기 어려워요."),
]

ACTIONS = {
    "위험": ["문자 속 링크나 번호로 절대 연락하지 마세요.",
             "돈을 보냈다면 즉시 112 또는 은행 고객센터에 지급정지를 요청하세요.",
             "가족이나 은행 대표번호로 직접 전화해 사실인지 확인하세요."],
    "주의": ["링크를 누르거나 앱을 설치하지 마세요.",
             "보낸 사람이 맞는지 원래 알던 번호로 직접 확인하세요.",
             "의심되면 금융감독원 1332에 물어보세요."],
    "안전": ["뚜렷한 사기 신호는 없지만, 돈·개인정보를 요구하면 다시 확인하세요.",
             "모르는 링크는 누르지 않는 습관을 유지하세요."],
}

LEVEL_ORDER = {"안전": 0, "주의": 1, "위험": 2}


@dataclass
class RuleResult:
    score: int
    level: str
    hits: list = field(default_factory=list)   # [(신호 이름, 설명)]


def level_for(score: int) -> str:
    if score >= 60:
        return "위험"
    if score >= 25:
        return "주의"
    return "안전"


def detect(text: str) -> RuleResult:
    hits = [(name, why) for name, pts, pat, why in SIGNALS if re.search(pat, text, re.IGNORECASE)]
    score = min(100, sum(pts for name, pts, pat, why in SIGNALS if (name, why) in hits))
    level = level_for(score)
    # 돈·정보·앱 요구가 하나라도 있으면 최소 '주의' (시스템 프롬프트와 같은 원칙)
    critical = {"인증번호·OTP 요구", "앱 설치 유도", "송금·이체 유도", "개인정보 요구"}
    if level == "안전" and any(name in critical for name, _ in hits):
        level = "주의"
    return RuleResult(score=score, level=level, hits=hits)


def rule_report(text: str) -> dict:
    """API 키 없이 쓰는 판정 결과(LLM 결과와 같은 모양)."""
    r = detect(text)
    if r.hits:
        one = f"{', '.join(n for n, _ in r.hits[:3])} 신호가 보여요."
        explain = " ".join(why for _, why in r.hits[:3])
    else:
        one = "뚜렷한 사기 신호는 찾지 못했어요."
        explain = "그래도 돈이나 개인정보를 요구하면 꼭 공식 번호로 다시 확인하세요."
    return {
        "risk_level": r.level,
        "score": r.score,
        "one_line": one,
        "reasons": [n for n, _ in r.hits] or ["의심 신호 없음"],
        "senior_explain": explain,
        "actions": ACTIONS[r.level],
        "source": "rules",
    }


def apply_floor(llm: dict, text: str) -> dict:
    """LLM 결과가 규칙 판정보다 낮으면 규칙 쪽으로 끌어올린다(놓친 신호는 근거에 추가)."""
    r = detect(text)
    out = dict(llm)
    out["source"] = "llm"
    if LEVEL_ORDER.get(out.get("risk_level"), 1) < LEVEL_ORDER[r.level]:
        out["risk_level"] = r.level
        out["score"] = max(int(out.get("score", 0)), r.score)
        out["floor_applied"] = True
        missed = [n for n, _ in r.hits if n not in " ".join(out.get("reasons", []))]
        out["reasons"] = list(out.get("reasons", [])) + [f"(규칙 탐지) {n}" for n in missed]
    return out
