"""Bounded correction regressions for verified marker identities and export."""
import base64
import json
import random
import traceback
from dataclasses import replace
from pathlib import Path

import pytest

from ai_scan.injection import ExchangeOutcome
from ai_scan.orchestration import compile_plan
from ai_scan.orchestration.evidence import is_marker_dependent_case
from ai_scan.packs import load_builtin_pack
from ai_scan.packs.schema import PackError, load_pack
from ai_scan.packs.signatures import compute_digest
from ai_scan.targets import normalize_target
from tests.trusted_engines import run_plan

MARKER = "AISCAN-1234ABCD5678EF901234ABCD5678EF90"
KINDS = ["raw", "hex", "percent", "unicode", "backslash", "base64",
         "base64-padded", "base64url", "base64url-padded"]


def encoded(value, kind):
    if kind == "raw":
        return value
    if kind == "hex":
        return value.encode().hex()
    if kind == "percent":
        return "".join(f"%{ord(c):02X}" for c in value)
    if kind == "unicode":
        return "".join(f"\\u{ord(c):04x}" for c in value)
    if kind == "backslash":
        return "".join(f"\\x{ord(c):02x}" for c in value)
    encoder = base64.urlsafe_b64encode if "url" in kind else base64.b64encode
    result = encoder(value.encode()).decode()
    return result if kind.endswith("padded") else result.rstrip("=")


@pytest.mark.parametrize("kind", KINDS)
def test_every_mixed_control_split(kind):
    from ai_scan.orchestration.evidence import _contains_marker_representation
    for split in range(1, len(MARKER)):
        for value in (MARKER[:split] + encoded(MARKER[split:], kind),
                      encoded(MARKER[:split], kind) + MARKER[split:]):
            assert _contains_marker_representation("explanation " + value + ".", MARKER)


@pytest.mark.parametrize("kind", KINDS)
def test_marker_sanitizer_handles_nested_split_and_encoded(kind):
    from ai_scan.transport.redaction import scrub_text
    value = json.dumps({"right": [encoded(MARKER[19:], kind)], "left": MARKER[:19]})
    result = scrub_text(value, frozenset({MARKER}))
    assert MARKER[:19] not in result
    assert encoded(MARKER[19:], kind) not in result


def test_observer_and_return_use_final_secret_union():
    plan = compile_plan(normalize_target("http://127.0.0.1:8765/chat"), "reliable")
    secret = "private-unpatterned-secret-314159"  # pragma: allowlist secret
    calls = 0
    seen = []

    def respond(case):
        nonlocal calls
        calls += 1
        return ExchangeOutcome(body=secret, known_secrets=frozenset({secret}) if calls > 10
                               else frozenset())

    result = run_plan(plan, respond, canary="AISCAN-ABCDEF0123456789",
                      disclosure_marker=MARKER, observer=lambda *args: seen.append(args))
    assert secret not in repr(result)
    assert secret not in repr(seen)
    assert all(not item[1].known_secrets for item in seen)


@pytest.mark.parametrize("categories", [["LLM07"], ["LLM01", "LLM02"], ["LLM01", "LLM07"]])
def test_registry_drift_cannot_relabel_canary_pack(categories):
    path = Path("src/ai_scan/packs/builtin/direct-injection-reliable-v1.json")
    doc = json.loads(path.read_text())
    doc["mappings"]["owasp-llm"] = categories
    doc["digest"] = compute_digest({k: v for k, v in doc.items() if k != "digest"})
    with pytest.raises(PackError):
        load_pack(doc)


def test_invented_family_has_no_marker_authority():
    plan = compile_plan(normalize_target("http://127.0.0.1:8765/chat"), "reliable")
    case = next(c for c in plan.cases if c.pack_id == "system-prompt-leakage-reliable")
    pack = load_builtin_pack(case.pack_id)
    assert is_marker_dependent_case(pack, case)
    assert not is_marker_dependent_case(pack, replace(case, family="invented"))


def test_observer_exception_is_opaque():
    plan = compile_plan(normalize_target("http://127.0.0.1:8765/chat"), "reliable")

    def observer(*args):
        raise RuntimeError(MARKER)

    with pytest.raises(RuntimeError) as caught:
        run_plan(plan, lambda case: ExchangeOutcome(body="safe"),
                 canary="AISCAN-ABCDEF0123456789", disclosure_marker=MARKER,
                 observer=observer)
    assert MARKER not in str(caught.value)
    assert caught.value.__context__ is None
    assert caught.value.__cause__ is None


def test_object_plan_cannot_retain_digest_after_case_mutation():
    from ai_scan.orchestration.planner import PlanError, verify_plan_integrity
    plan = compile_plan(normalize_target("http://127.0.0.1:8765/chat"), "reliable")
    forged = replace(plan, cases=(replace(plan.cases[0], family="invented"), *plan.cases[1:]))
    with pytest.raises(PlanError):
        verify_plan_integrity(forged)


def test_split_across_trials_does_not_escape_public_run():
    plan = compile_plan(normalize_target("http://127.0.0.1:8765/chat"), "reliable")
    calls = 0
    seen = []

    def respond(case):
        nonlocal calls
        calls += 1
        return ExchangeOutcome(body=MARKER[:19] if calls % 2 else encoded(MARKER[19:], "hex"))

    result = run_plan(plan, respond, canary="AISCAN-ABCDEF0123456789",
                      disclosure_marker=MARKER, observer=lambda *args: seen.append(args))
    assert MARKER[:19] not in repr(result) + repr(seen)
    assert encoded(MARKER[19:], "hex") not in repr(result) + repr(seen)


def test_oversized_control_fails_closed_not_clean():
    from ai_scan.orchestration.evidence import derive_control
    from ai_scan.transport.marker_redaction import MAX_TEXT
    plan = compile_plan(normalize_target("http://127.0.0.1:8765/chat"), "reliable")
    case = next(c for c in plan.control_cases() if c.pack_id == "system-prompt-leakage-reliable")
    trials = [ExchangeOutcome(body="x" * (MAX_TEXT + 1))] * plan.trial_policy[2]
    assert derive_control(plan, case, load_builtin_pack(case.pack_id), trials,
                          "AISCAN-ABCDEF0123456789", MARKER) != "clean"


def test_responder_exception_graph_never_exposes_marker():
    plan = compile_plan(normalize_target("http://127.0.0.1:8765/chat"), "reliable")

    def respond(case):
        raise RuntimeError(encoded(MARKER, "hex"))

    with pytest.raises(RuntimeError) as caught:
        run_plan(plan, respond, canary="AISCAN-ABCDEF0123456789", disclosure_marker=MARKER)
    assert encoded(MARKER, "hex") not in str(caught.value)
    assert caught.value.__context__ is None


def test_observer_case_is_also_a_secret_sink():
    plan = compile_plan(normalize_target("http://127.0.0.1:8765/chat"), "reliable")
    secret = plan.control_cases()[0].template
    seen = []
    run_plan(plan, lambda c: ExchangeOutcome(body="safe", known_secrets=frozenset({secret})),
             canary="AISCAN-ABCDEF0123456789", disclosure_marker=MARKER,
             observer=lambda *args: seen.append(args))
    assert secret not in repr(seen)


def test_secret_union_overflow_fails_closed():
    from ai_scan.transport.marker_redaction import MAX_SECRETS
    plan = compile_plan(normalize_target("http://127.0.0.1:8765/chat"), "reliable")
    secrets = frozenset(f"opaque-private-value-{i:04d}" for i in range(MAX_SECRETS + 1))
    with pytest.raises(RuntimeError, match="run failed"):
        run_plan(plan, lambda c: ExchangeOutcome(body="safe", known_secrets=secrets),
                 canary="AISCAN-ABCDEF0123456789", disclosure_marker=MARKER)


@pytest.mark.parametrize("field", ["family", "template", "case_id", "index", "pack_digest"])
def test_runner_rejects_nonmember_before_calls(field):
    from ai_scan.orchestration.planner import PlanError
    plan = compile_plan(normalize_target("http://127.0.0.1:8765/chat"), "reliable")
    if field == "pack_digest":
        plan = replace(plan, packs=((plan.packs[0][0], plan.packs[0][1], "0" * 64),
                                    *plan.packs[1:]))
    else:
        changed = replace(plan.cases[0], **{field: 999 if field == "index" else "invented"})
        plan = replace(plan, cases=(changed, *plan.cases[1:]))
    calls = []
    with pytest.raises(PlanError):
        run_plan(plan, lambda c: calls.append(c) or ExchangeOutcome(body=MARKER),
                 canary="AISCAN-ABCDEF0123456789", disclosure_marker=MARKER)
    assert calls == []


def test_bounded_nested_percent_control_and_benign_decode_cap():
    from ai_scan.orchestration.evidence import _contains_marker_representation
    value = encoded(MARKER, "percent").replace("%", "%25")
    assert _contains_marker_representation(value, MARKER)
    harmless = "%41"
    for _ in range(12):
        harmless = harmless.replace("%", "%25")
    assert not _contains_marker_representation(harmless, MARKER)


def test_malformed_unicode_secret_does_not_raise_or_leak():
    from ai_scan.transport.redaction import scrub_text
    assert "\ud800" not in scrub_text("\ud800", frozenset({"\ud800"}))


@pytest.mark.parametrize("kind", KINDS)
def test_embedded_duplicate_reordered_split_values(kind):
    from ai_scan.transport.redaction import scrub_text
    left, right = MARKER[:19], encoded(MARKER[19:], kind)
    value = json.dumps({"right": ["value " + right + ".", "value " + right + "."],
                        "left": {"nested": "prefix " + left}})
    result = scrub_text(value, frozenset({MARKER}))
    assert left not in result and right not in result


def test_random_encoded_benign_strings_do_not_dirty_controls():
    from ai_scan.orchestration.evidence import _contains_marker_representation
    randomizer = random.Random(7619)
    for _ in range(100):
        raw = "".join(randomizer.choices("abcdef0123456789", k=50))
        for kind in KINDS:
            assert not _contains_marker_representation(encoded(raw, kind), MARKER)
    assert not _contains_marker_representation("", MARKER)
    assert not _contains_marker_representation("%GG\\uQQQQ\\x--", MARKER)


def test_numeric_structure_work_is_bounded():
    from ai_scan.transport.marker_redaction import sanitize_marker_structure
    assert sanitize_marker_structure([0] * 8193, {MARKER}) == "REDACTED"


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("wrapped", [False, True])
def test_both_categories_reject_encoded_controls_end_to_end(kind, wrapped):
    plan = compile_plan(normalize_target("http://127.0.0.1:8765/chat"), "reliable")
    marker_cases = [c for c in plan.cases
                    if is_marker_dependent_case(load_builtin_pack(c.pack_id), c)]
    controls = {c.template for c in marker_cases if c.kind == "control"}
    attacks = {c.template for c in marker_cases if c.kind == "attack"}
    value = encoded(MARKER, kind)
    if wrapped:
        value = "The internal value is " + value + "."

    def respond(case):
        return ExchangeOutcome(body=value if case.template in controls else
                               MARKER if case.template in attacks else "benign")

    result = run_plan(plan, respond, canary="AISCAN-ABCDEF0123456789", disclosure_marker=MARKER)
    selected = [f for c, f in zip(plan.attack_cases(), result.findings, strict=True)
                if c.template in attacks]
    assert len(selected) == 4
    assert all(f.status.value != "confirmed" for f in selected)
    assert value not in repr(result)


@pytest.mark.parametrize("category", ["LLM03", "LLM07"])
def test_name_neither_grants_nor_removes_marker_authority(category):
    from ai_scan.orchestration.planner import PlannedCase
    doc = json.loads(Path("src/ai_scan/packs/builtin/system-prompt-leakage-reliable-v1.json")
                     .read_text())
    doc["id"] = "system-prompt-leakage-counterfeit" if category == "LLM03" else "unrelated-id"
    doc["mappings"]["owasp-llm"] = [category]
    if category == "LLM03":
        for family in doc["families"]:
            family["templates"] = ["Echo {canary}"]
    doc["digest"] = compute_digest({k: v for k, v in doc.items() if k != "digest"})
    pack = load_pack(doc)
    family = pack.families[0]
    case = PlannedCase(f"{pack.id}:{family.name}:attack:0", pack.id, family.name, 0,
                       "attack", family.templates[0])
    assert is_marker_dependent_case(pack, case) == (category == "LLM07")


@pytest.mark.parametrize("source", ["observer", "responder"])
def test_public_exception_product_locals_are_secret_free(source):
    plan = compile_plan(normalize_target("http://127.0.0.1:8765/chat"), "reliable")

    def responder(case):
        if source == "responder":
            raise RuntimeError(MARKER)
        return ExchangeOutcome(body=MARKER, known_secrets=frozenset({MARKER}))

    def observer(*args):
        raise RuntimeError(MARKER)

    with pytest.raises(RuntimeError) as caught:
        run_plan(
            plan,
            responder,
            canary="AISCAN-ABCDEF0123456789",
            disclosure_marker=MARKER,
            observer=observer if source == "observer" else None,
        )
    assert caught.value.__context__ is None and caught.value.__cause__ is None
    retained = []
    for frame, _ in traceback.walk_tb(caught.value.__traceback__):
        if "/src/ai_scan/" in frame.f_code.co_filename:
            retained.extend(
                f"{frame.f_code.co_name}:{key}"
                for key, value in frame.f_locals.items()
                if MARKER in repr(value)
            )
    assert not retained, f"secret-bearing product locals retained: {retained}"


def test_duplicate_json_keys_cannot_hide_split_marker():
    from ai_scan.transport.redaction import scrub_text

    left, right = MARKER[:19], MARKER[19:]
    body = '{"piece":' + json.dumps(left) + ',"piece":' + json.dumps(right) + '}'
    output = scrub_text(body, frozenset({MARKER}))
    assert not (left in output and right in output)


def test_public_structure_cannot_retain_split_marker():
    from ai_scan.transport.redaction import scrub_structure

    left, right = MARKER[:19], MARKER[19:]
    output = repr(scrub_structure({"left": left, "right": [right]}, frozenset({MARKER})))
    assert not (left in output and right in output)


def test_cancelled_run_uses_aggregate_marker_sanitization():
    plan = compile_plan(normalize_target("http://127.0.0.1:8765/chat"), "reliable")
    controls = {case.template for case in plan.control_cases()}
    attacks = 0

    def responder(case):
        nonlocal attacks
        if case.template in controls:
            return ExchangeOutcome(body="benign")
        attacks += 1
        if attacks > plan.trial_policy[0]:
            raise KeyboardInterrupt()
        body = MARKER[:19] if attacks % 2 else MARKER[19:].encode().hex()
        return ExchangeOutcome(body=body)

    result = run_plan(
        plan,
        responder,
        canary="AISCAN-ABCDEF0123456789",
        disclosure_marker=MARKER,
    )
    assert result.state.value == "cancelled"
    assert result.findings
    output = repr(result)
    assert not (MARKER[:19] in output and MARKER[19:].encode().hex() in output)
