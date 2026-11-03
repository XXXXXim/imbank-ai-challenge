"""평가셋 회귀 테스트 — 규칙을 고쳤을 때 성능이 기준선 아래로 떨어지면 실패한다."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "eval"))
from run_eval import evaluate, load  # noqa: E402

# 2026-11 기준선 (eval/results.json). 규칙을 개선하면 이 숫자도 함께 올린다.
MIN_RECALL = 0.76
MAX_FALSE_POSITIVE_RATE = 0.28


def test_eval_set_is_balanced():
    cases = load()
    assert sum(c["label"] == "scam" for c in cases) == sum(c["label"] == "normal" for c in cases)
    assert len({c["id"] for c in cases}) == len(cases)


def test_recall_does_not_regress():
    assert evaluate(load())["recall"] >= MIN_RECALL


def test_false_positive_rate_does_not_regress():
    assert evaluate(load())["false_positive_rate"] <= MAX_FALSE_POSITIVE_RATE
