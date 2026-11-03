"""규칙 탐지기 평가 — 정탐률(Recall)·오탐률(FPR)·정밀도를 숫자로 잰다.

평가셋: eval/eval_set.jsonl (사기 25 · 정상 25, 직접 작성)
- 사기 문자는 경찰청·금융감독원이 공개한 대표 수법 유형(택배·대출·지인·기관 사칭, 청첩장 링크,
  결제 승인 사칭, 원격 앱 유도, 리딩방 등)을 참고해 새로 작성했다. 실제 피해 문자 원문은 아니다.
- 정상 문자에는 일부러 헷갈리는 것(진짜 은행 인증번호 알림, 입금 알림, 광고 링크, 더치페이 송금)을 넣었다.

판정 기준: '주의' 이상이면 "탐지(양성)", '안전'이면 "통과(음성)".
실행: python eval/run_eval.py   → eval/results.json, 콘솔에 오탐·미탐 목록
API 키가 필요 없다 (규칙 탐지기만 평가).
"""
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from detector import detect  # noqa: E402

EVAL_SET = ROOT / "eval" / "eval_set.jsonl"
OUT = ROOT / "eval" / "results.json"


def load() -> list[dict]:
    return [json.loads(line) for line in EVAL_SET.read_text(encoding="utf-8").splitlines() if line.strip()]


def evaluate(cases: list[dict]) -> dict:
    tp = fp = tn = fn = 0
    levels = Counter()
    by_type = defaultdict(lambda: {"n": 0, "detected": 0})
    misses, false_alarms, rows = [], [], []
    for c in cases:
        r = detect(c["text"])
        flagged = r.level != "안전"
        scam = c["label"] == "scam"
        levels[(c["label"], r.level)] += 1
        if scam:
            by_type[c["type"]]["n"] += 1
            by_type[c["type"]]["detected"] += flagged
        if scam and flagged:
            tp += 1
        elif scam:
            fn += 1
            misses.append({"id": c["id"], "type": c["type"], "text": c["text"]})
        elif flagged:
            fp += 1
            false_alarms.append({"id": c["id"], "type": c["type"], "level": r.level,
                                 "signals": [n for n, _ in r.hits]})
        else:
            tn += 1
        rows.append({"id": c["id"], "label": c["label"], "level": r.level, "score": r.score,
                     "signals": [n for n, _ in r.hits]})

    def ratio(a: int, b: int) -> float:
        return round(a / b, 3) if b else 0.0

    recall, precision = ratio(tp, tp + fn), ratio(tp, tp + fp)
    return {
        "n_scam": tp + fn, "n_normal": tn + fp,
        "confusion": {"tp": tp, "fn": fn, "fp": fp, "tn": tn},
        "recall": recall,                      # 사기 중 잡은 비율 (정탐률)
        "precision": precision,                # 경고 중 진짜 사기 비율
        "f1": round(2 * recall * precision / (recall + precision), 3) if recall + precision else 0.0,
        "false_positive_rate": ratio(fp, fp + tn),   # 정상인데 경고한 비율 (오탐률)
        "accuracy": ratio(tp + tn, len(cases)),
        "scam_danger_rate": ratio(levels[("scam", "위험")], tp + fn),  # 사기 중 '위험'까지 올린 비율
        "level_matrix": {f"{k[0]}→{k[1]}": v for k, v in sorted(levels.items())},
        "recall_by_type": {t: f"{v['detected']}/{v['n']}" for t, v in sorted(by_type.items())},
        "misses": misses,
        "false_alarms": false_alarms,
        "details": rows,
    }


def main() -> None:
    res = evaluate(load())
    OUT.write_text(json.dumps(res, ensure_ascii=False, indent=2), encoding="utf-8")
    c = res["confusion"]
    print(f"사기 {res['n_scam']}건 · 정상 {res['n_normal']}건")
    print(f"정탐률(Recall) {res['recall']:.0%}  정밀도 {res['precision']:.0%}  F1 {res['f1']:.2f}  "
          f"오탐률 {res['false_positive_rate']:.0%}  정확도 {res['accuracy']:.0%}")
    print(f"혼동행렬 TP={c['tp']} FN={c['fn']} FP={c['fp']} TN={c['tn']}  / 사기 중 '위험' 판정 {res['scam_danger_rate']:.0%}")
    print("\n[놓친 사기]")
    for m in res["misses"]:
        print(f"  {m['id']} ({m['type']}) {m['text'][:50]}")
    print("\n[정상인데 경고]")
    for f in res["false_alarms"]:
        print(f"  {f['id']} ({f['type']}) → {f['level']} {f['signals']}")
    print(f"\n→ {OUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
